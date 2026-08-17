namespace LiveClr.Runtime;

using System.Reflection.Metadata;
using LiveClr.Cdac;
using LiveClr.Memory;
using LiveClr.Metadata;

/// <summary>
/// How to read an instance field's offset out of a runtime <c>FieldDesc</c>, expressed as a
/// bitfield position rather than as a hardcoded struct layout.
/// </summary>
/// <param name="EntryMask">
/// Mask applied to a <c>FieldDefToDescMap</c> table entry before using it as a pointer. §5.4
/// notes those maps carry flag bits in the low bits of each entry; the mask that clears them
/// is derived, not assumed.
/// </param>
/// <param name="OffsetByteOffset">Byte offset of the 32-bit word holding the field offset.</param>
/// <param name="OffsetBitShift">Right shift applied to that word.</param>
/// <param name="OffsetBitWidth">Width of the bitfield after shifting.</param>
/// <param name="EnclosingSlot">
/// Byte offset of the slot pointing back at the declaring method table, or -1 if it could not
/// be derived. Used only to validate a lookup, never to produce a value.
/// </param>
/// <param name="EnclosingIsRelative">
/// True when the back-pointer is stored as a self-relative displacement rather than an
/// absolute address. CoreCLR uses both forms in different structures, so this is derived.
/// </param>
public readonly record struct FieldDescEncoding(
    ulong EntryMask,
    int OffsetByteOffset,
    int OffsetBitShift,
    int OffsetBitWidth,
    int EnclosingSlot,
    bool EnclosingIsRelative)
{
    /// <summary>Decode the field offset held in the <c>FieldDesc</c> at <paramref name="fieldDesc"/>.</summary>
    /// <remarks>
    /// The value is the runtime's own offset convention: relative to the first instance field,
    /// NOT to the start of the object. <see cref="RuntimeFieldLayoutSource"/> adds
    /// <see cref="ClrLayouts.FirstFieldOffset"/> before handing it out.
    /// </remarks>
    public bool TryDecodeOffset(IMemoryReader memory, ulong fieldDesc, out int offset)
    {
        offset = 0;
        if (fieldDesc == 0) return false;
        if (!memory.TryRead(fieldDesc + (ulong)OffsetByteOffset, out uint word)) return false;

        uint mask = OffsetBitWidth >= 32 ? uint.MaxValue : (1u << OffsetBitWidth) - 1;
        offset = (int)((word >> OffsetBitShift) & mask);
        return true;
    }

    /// <summary>Read the declaring method table a <c>FieldDesc</c> points back at.</summary>
    public bool TryReadEnclosingMethodTable(IMemoryReader memory, ulong fieldDesc, out ulong methodTable)
    {
        methodTable = 0;
        if (EnclosingSlot < 0 || fieldDesc == 0) return false;

        ulong slot = fieldDesc + (ulong)EnclosingSlot;
        if (EnclosingIsRelative)
        {
            if (!memory.TryRead(slot, out int displacement)) return false;
            methodTable = (ulong)((long)slot + displacement);
            return methodTable != 0;
        }

        return memory.TryReadPointer(slot, out methodTable) && methodTable != 0;
    }
}

/// <summary>
/// Derives <see cref="FieldDescEncoding"/> from ground truth the runtime publishes about
/// itself, instead of hardcoding CoreCLR's <c>FieldDesc</c> struct.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why this exists.</b> The .NET 9 contract descriptor (§5.2) publishes
/// <c>Module.FieldDefToDescMap</c> and <c>ModuleLookupMap.TableData</c>, so a metadata field
/// token can be turned into a <c>FieldDesc</c> address using only published data. What it
/// does NOT publish is the <c>FieldDesc</c> type itself — there is no <c>FieldDesc</c> entry
/// among the 29 types, no <c>EEClass.FieldDescList</c>, and no <c>MethodTable</c> field token.
/// The last hop, address → offset, therefore has no published layout. §5.5's "honest gap",
/// one level deeper.
/// </para>
/// <para>
/// <b>The technique is §12.5's, applied to the runtime instead of to Godot.</b> That section
/// derived Godot's offsets by scanning for slots consistent with independently-known values
/// and intersecting candidate sets across samples. The same move works here because the
/// descriptor hands us eight independently-known answers: the <c>Exception</c> entry publishes
/// the object-relative offsets of eight of <c>System.Exception</c>'s MANAGED instance fields
/// (<c>_message</c> 16, <c>_innerException</c> 32, <c>_stackTrace</c> 48, <c>_watsonBuckets</c>
/// 56, <c>_stackTraceString</c> 64, <c>_remoteStackTraceString</c> 72, <c>_xcode</c> 104,
/// <c>_HResult</c> 108), and <c>ExceptionMethodTable</c> is a published global. So:
/// resolve those eight fields' <c>FieldDesc</c>s through the published map, then search for
/// the one bitfield position that reproduces all eight known offsets.
/// </para>
/// <para>
/// <b>Why the failure mode is safe.</b> Convergence requires reproducing eight distinct known
/// values spanning 0..100 from real target bytes. A wrong guess about the map's flag bits, the
/// table stride, or the bitfield position does not "mostly work" — it fails to converge and
/// this class reports <see cref="IsCalibrated"/> false, at which point field resolution
/// degrades to whatever the caller supplied explicitly. There is no path here that produces a
/// plausible-but-wrong offset, which is the §12.4e/§7b.1 property that matters.
/// </para>
/// <para>
/// <b>Not live-verified.</b> Everything in §12 was measured against a running game; this was
/// not. It is exercised in tests against synthesised <c>FieldDesc</c>s using two DIFFERENT
/// encodings, which proves the search derives rather than recognises a layout, but that is an
/// argument, not a measurement — the same caveat §12.5 attaches to its own method.
/// </para>
/// <para>Lifetime: PROCESS tier (§8.8). Calibrate once at attach.</para>
/// </remarks>
public sealed class FieldDescCalibration
{
    /// <summary>How far into a <c>FieldDesc</c> the search looks. Generously past any plausible size.</summary>
    private const int SearchWindow = 64;

    /// <summary>Below this many agreeing samples the result is not trustworthy enough to use.</summary>
    private const int MinimumSamples = 3;

    /// <summary>
    /// Candidate masks for a lookup-map entry's flag bits (§5.4). Method tables and field
    /// descriptors are at least 8-byte aligned, so nothing above bit 2 can be a flag.
    /// </summary>
    /// <remarks>
    /// <b>Most restrictive first, deliberately.</b> On a target whose entries carry flag bits,
    /// the no-op mask leaves a misaligned pointer; convergence there would need a bitfield
    /// window in mid-structure bytes to reproduce all eight published offsets, which is
    /// astronomically unlikely but nothing in the search structurally forbids — and §12.5's
    /// worst outcome is exactly one confident wrong answer. Trying <c>~7</c> first inverts the
    /// risk instead of accepting it: on an 8-byte-aligned pointer <c>entry &amp; ~7 == entry</c>,
    /// so the most restrictive mask is a no-op on a target with no flags and the correct mask on
    /// a target with them — it is the only candidate that is right in both worlds. A mask that
    /// clears real address bits (a 4-byte-aligned <c>FieldDesc</c> on a 32-bit target) does not
    /// then produce a wrong encoding, it fails to converge and the next candidate is tried.
    /// </remarks>
    private static readonly ulong[] EntryMasks = [~7UL, ~3UL, ~1UL, ulong.MaxValue];

    private FieldDescCalibration(FieldDescEncoding? encoding, int sampleCount, int candidateCount, string detail)
    {
        Encoding = encoding;
        SampleCount = sampleCount;
        CandidateCount = candidateCount;
        Detail = detail;
    }

    /// <summary>The derived encoding, or null when calibration did not converge.</summary>
    public FieldDescEncoding? Encoding { get; }

    /// <summary>True when <see cref="Encoding"/> can be used.</summary>
    public bool IsCalibrated => Encoding is not null;

    /// <summary>Number of published offsets that were successfully turned into samples.</summary>
    public int SampleCount { get; }

    /// <summary>
    /// How many distinct bitfield positions satisfied every sample. One is the expected
    /// answer; more than one is reported rather than silently resolved, because picking
    /// arbitrarily is exactly the kind of plausible-but-wrong choice this class exists to
    /// avoid.
    /// </summary>
    public int CandidateCount { get; }

    /// <summary>Human-readable outcome, suitable for a startup diagnostic.</summary>
    public string Detail { get; }

    /// <summary>A calibration that was never attempted, or was deliberately disabled.</summary>
    public static FieldDescCalibration NotAttempted { get; } =
        new(null, 0, 0, "FieldDesc calibration was not attempted.");

    /// <summary>
    /// Attempt the derivation. Never throws; a runtime that cannot be calibrated is an
    /// ordinary outcome (§5.5).
    /// </summary>
    /// <param name="memory">Reader for the target.</param>
    /// <param name="target">The bootstrapped contract target (for globals and the published offsets).</param>
    /// <param name="layouts">Resolved CLR offsets.</param>
    /// <param name="metadata">Process-tier metadata cache; CoreLib's blob is loaded through it.</param>
    public static FieldDescCalibration Attempt(
        IMemoryReader memory,
        IRuntimeContractTarget target,
        ClrLayouts layouts,
        ModuleMetadataCache metadata)
    {
        ArgumentNullException.ThrowIfNull(memory);
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(layouts);
        ArgumentNullException.ThrowIfNull(metadata);

        if (!target.TryGetGlobalPointer("ExceptionMethodTable", out ulong globalAddress) ||
            !memory.TryReadPointer(globalAddress, out ulong exceptionMt) ||
            exceptionMt == 0)
        {
            return new FieldDescCalibration(
                null, 0, 0,
                "the descriptor does not publish ExceptionMethodTable, so there is no anchor with known field offsets.");
        }

        if (!memory.TryReadPointer(exceptionMt + (ulong)layouts.MethodTableModuleOffset, out ulong modulePointer) ||
            !memory.TryReadPointer(modulePointer + (ulong)layouts.ModuleBaseOffset, out ulong moduleBase))
        {
            return new FieldDescCalibration(null, 0, 0, "could not reach CoreLib's Module.Base from ExceptionMethodTable.");
        }

        ModuleMetadata? corelib = metadata.GetOrLoad(moduleBase);
        if (corelib is null)
        {
            return new FieldDescCalibration(null, 0, 0, $"no ECMA-335 metadata at CoreLib base 0x{moduleBase:X}.");
        }

        if (!corelib.Types.TryResolveType("System.Exception", out TypeDefinitionHandle exceptionType))
        {
            return new FieldDescCalibration(null, 0, 0, "the module behind ExceptionMethodTable does not define System.Exception.");
        }

        // Pair each metadata field with the object-relative offset the descriptor publishes
        // for it. Only fields present in BOTH are usable as ground truth.
        var samples = new List<(int Rid, int ExpectedFieldDescOffset)>();
        foreach (MetadataField field in corelib.Types.GetFields(exceptionType))
        {
            if (field.IsStatic || field.IsLiteral) continue;
            if (!target.TryGetFieldOffset("Exception", field.Name, out int objectRelative)) continue;

            int expected = objectRelative - layouts.FirstFieldOffset;
            if (expected < 0) continue;

            samples.Add((field.Token & 0x00FF_FFFF, expected));
        }

        if (samples.Count < MinimumSamples)
        {
            return new FieldDescCalibration(
                null, samples.Count, 0,
                $"only {samples.Count} of System.Exception's fields are published with offsets; " +
                $"{MinimumSamples} are needed to pin a bitfield position.");
        }

        return Solve(memory, layouts, modulePointer, exceptionMt, samples, corelib.Reader.FieldDefinitions.Count);
    }

    private static FieldDescCalibration Solve(
        IMemoryReader memory,
        ClrLayouts layouts,
        ulong modulePointer,
        ulong exceptionMt,
        List<(int Rid, int ExpectedFieldDescOffset)> samples,
        int fieldRowCount)
    {
        ulong mapAddress = modulePointer + (ulong)layouts.ModuleFieldDefMapOffset;
        FieldDescCalibration? ambiguous = null;

        // A mask under which the back-pointer could NOT be derived is held back rather than
        // returned: the eight offsets are then the ONLY constraint, because
        // RuntimeFieldLayoutSource cannot cross-check a lookup without that slot. Preferring any
        // later mask that does yield one costs three futile searches at attach and buys a second,
        // independent constraint on the mask itself. It is a preference and not a requirement
        // because a runtime that stores the declaring type somewhere this search cannot see is a
        // §5.5 gap, not a fault — refusing outright would trade a working degraded mode for none.
        FieldDescCalibration? unvalidated = null;

        foreach (ulong entryMask in EntryMasks)
        {
            var descriptors = new List<(ulong Address, byte[] Bytes, int Expected)>(samples.Count);

            foreach ((int rid, int expected) in samples)
            {
                if (!layouts.TryGetLookupMapSlot(memory, mapAddress, rid, fieldRowCount, out ulong slot)) continue;
                if (!memory.TryReadPointer(slot, out ulong raw)) continue;

                ulong fieldDesc = raw & entryMask;
                if (fieldDesc == 0) continue;

                var bytes = new byte[SearchWindow];
                if (!memory.TryRead(fieldDesc, bytes)) continue;

                descriptors.Add((fieldDesc, bytes, expected));
            }

            if (descriptors.Count < MinimumSamples) continue;

            List<(int ByteOffset, int Shift, int Width)> candidates = FindOffsetBitfields(descriptors);
            if (candidates.Count == 0) continue;

            (int byteOffset, int shift, int width) = candidates[0];
            (int enclosingSlot, bool enclosingRelative) = FindEnclosingSlot(descriptors, exceptionMt, layouts.PointerSize);

            var encoding = new FieldDescEncoding(
                entryMask, byteOffset, shift, width, enclosingSlot, enclosingRelative);

            if (candidates.Count > 1)
            {
                // Ambiguity under one mask does not condemn the others; record it and keep
                // going, but never resolve it by picking — that is the plausible-but-wrong
                // outcome this whole class exists to avoid.
                ambiguous ??= new FieldDescCalibration(
                    null, descriptors.Count, candidates.Count,
                    $"ambiguous under entry mask 0x{entryMask:X}: {candidates.Count} bitfield positions " +
                    $"reproduce all {descriptors.Count} known offsets, so none is trustworthy.");
                continue;
            }

            string enclosing = enclosingSlot < 0
                ? "no back-pointer slot derived (lookups are then bounded only by BaseSize)"
                : $"back-pointer at +{enclosingSlot} ({(enclosingRelative ? "self-relative" : "absolute")})";

            var converged = new FieldDescCalibration(
                encoding,
                descriptors.Count,
                1,
                $"derived from {descriptors.Count} System.Exception fields: offset at +{byteOffset} " +
                $"bits [{shift}, {shift + width}), entry mask 0x{entryMask:X}, {enclosing}.");

            if (enclosingSlot >= 0) return converged;

            unvalidated ??= converged;
        }

        // A unique convergence under some mask is stronger evidence than an ambiguity under
        // another, so the held-back result outranks it.
        return unvalidated ?? ambiguous ?? new FieldDescCalibration(
            null, samples.Count, 0,
            "no bitfield position in the first 64 bytes of a FieldDesc reproduces the published " +
            "System.Exception offsets; FieldDefToDescMap may be segmented past its first block, " +
            "or this runtime stores field offsets somewhere else entirely.");
    }

    /// <summary>
    /// Every (word, shift, width) that decodes ALL samples to their known offsets.
    /// </summary>
    /// <remarks>
    /// Width is grown to the widest that still satisfies every sample, which finds the real
    /// bitfield boundary: a neighbouring bitfield with any bit set in any sample stops the
    /// growth. Taking the minimum width instead would truncate offsets larger than the samples
    /// happened to cover.
    /// </remarks>
    private static List<(int ByteOffset, int Shift, int Width)> FindOffsetBitfields(
        List<(ulong Address, byte[] Bytes, int Expected)> descriptors)
    {
        var results = new List<(int, int, int)>();

        for (int byteOffset = 0; byteOffset + 4 <= SearchWindow; byteOffset += 4)
        {
            for (int shift = 0; shift < 32; shift++)
            {
                int width = 0;
                for (int candidateWidth = 1; candidateWidth <= 32 - shift; candidateWidth++)
                {
                    if (Matches(descriptors, byteOffset, shift, candidateWidth)) width = candidateWidth;
                    else if (width > 0) break;
                }

                if (width > 0) results.Add((byteOffset, shift, width));
            }
        }

        return results;
    }

    private static bool Matches(
        List<(ulong Address, byte[] Bytes, int Expected)> descriptors,
        int byteOffset,
        int shift,
        int width)
    {
        uint mask = width >= 32 ? uint.MaxValue : (1u << width) - 1;

        foreach ((_, byte[] bytes, int expected) in descriptors)
        {
            uint word = BitConverter.ToUInt32(bytes, byteOffset);
            if (((word >> shift) & mask) != (uint)expected) return false;
        }

        return true;
    }

    /// <summary>
    /// The slot every sampled <c>FieldDesc</c> uses to point back at its declaring method
    /// table, absolute or self-relative. Optional: it only strengthens validation.
    /// </summary>
    private static (int Slot, bool IsRelative) FindEnclosingSlot(
        List<(ulong Address, byte[] Bytes, int Expected)> descriptors,
        ulong methodTable,
        int pointerSize)
    {
        for (int slot = 0; slot + pointerSize <= SearchWindow; slot += pointerSize)
        {
            bool absolute = true;
            bool relative = true;

            foreach ((ulong address, byte[] bytes, _) in descriptors)
            {
                if (pointerSize == 8)
                {
                    if (BitConverter.ToUInt64(bytes, slot) != methodTable) absolute = false;
                }
                else if (BitConverter.ToUInt32(bytes, slot) != (uint)methodTable)
                {
                    absolute = false;
                }

                int displacement = BitConverter.ToInt32(bytes, slot);
                if ((ulong)((long)address + slot + displacement) != methodTable) relative = false;

                if (!absolute && !relative) break;
            }

            if (absolute) return (slot, false);
            if (relative) return (slot, true);
        }

        return (-1, false);
    }
}
