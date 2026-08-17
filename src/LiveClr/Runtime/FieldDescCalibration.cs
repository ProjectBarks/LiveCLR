namespace LiveClr.Runtime;

using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
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
/// <param name="OffsetBitWidth">
/// Width of the bitfield after shifting. Measured against real field descriptors, not inferred
/// from the anchors — see <see cref="FieldDescCalibration"/> for why the anchors cannot
/// determine it.
/// </param>
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

        offset = (int)Decode(word, OffsetBitShift, OffsetBitWidth);
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

    /// <summary>
    /// Extract a bitfield from a word. Public because "what would this word decode to at a
    /// different width?" is the question a diagnostic asks when an offset looks wrong, and it is
    /// the question that separates a correct width from one bit too many.
    /// </summary>
    public static uint Decode(uint word, int shift, int width) =>
        (word >> shift) & (width >= 32 ? uint.MaxValue : (1u << width) - 1);
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
/// <b>The technique is §12.5's, applied to the runtime instead of to Godot.</b> The descriptor
/// hands us eight independently-known answers: the <c>Exception</c> entry publishes the
/// object-relative offsets of eight of <c>System.Exception</c>'s MANAGED instance fields
/// (<c>_message</c> 16, <c>_innerException</c> 32, <c>_stackTrace</c> 48, <c>_watsonBuckets</c>
/// 56, <c>_stackTraceString</c> 64, <c>_remoteStackTraceString</c> 72, <c>_xcode</c> 104,
/// <c>_HResult</c> 108), and <c>ExceptionMethodTable</c> is a published global. Resolve those
/// eight fields' <c>FieldDesc</c>s through the published map, then search for the bitfield
/// POSITION — word and shift — that reproduces all eight.
/// </para>
/// <para>
/// <b>MEASURED: the anchors pin the position but CANNOT pin the width.</b> Live validation
/// against CoreCLR 9.0.725.31616 caught this class converging on a 28-bit field where the
/// runtime's is 27, swallowing the low bit of the neighbouring <c>m_type</c>. The reason is
/// structural, not incidental: all eight published anchors have an EVEN <c>m_type</c>
/// (<c>CLASS</c> = 18, <c>I4</c> = 8), so the bit above the offset field is zero in every
/// single sample. Widths 27 and 28 then reproduce the anchors identically, and there is no
/// ninth anchor to break the tie — <c>Exception</c> is the only managed type whose field
/// offsets the descriptor publishes. An earlier version resolved that tie by taking the widest
/// matching width, which is precisely the unsafe direction: a bit that is zero across every
/// sample is ABSENCE OF EVIDENCE that it belongs to the field, not evidence that it does.
/// The measured cost was 7,234 of sts2.dll's 23,235 instance fields — 31%, every non-enum
/// struct field, every <c>double</c>, every unsigned integer — decoding as
/// <c>realOffset + 0x8000000</c>.
/// </para>
/// <para>
/// <b>So the width is measured, not preferred.</b> Taking the narrowest instead would be just as
/// arbitrary and worse: the anchors span 0..100, so the narrowest matching width is 7 bits, and
/// every field past offset 127 would silently decode wrong — below <c>BaseSize</c>, so nothing
/// downstream would catch it. Neither direction is derivable from eight samples. Instead, once
/// the anchors have pinned the position, candidate widths are scored against a CORPUS of real
/// field descriptors walked out of CoreLib's own <c>TypeDefToMethodTableMap</c>: a decoded
/// offset must fit inside its declaring type's published <c>MethodTable.BaseSize</c> (§5.2).
/// A too-wide window fails that on every field whose <c>m_type</c> is odd; the chosen width is
/// the widest with ZERO violations, and it is accepted only if the next bit up is demonstrably
/// not ours — either the anchors exclude it, or the corpus does, or the word ends. The boundary
/// is therefore OBSERVED. Nothing here is a constant: the same walk finds 27 on this runtime and
/// would find whatever the next one uses.
/// </para>
/// <para>
/// <b>Why the failure mode is safe.</b> Every path that cannot establish both the position and
/// the boundary reports <see cref="IsCalibrated"/> false, and field resolution then degrades to
/// whatever the caller supplied explicitly. Live validation confirmed this held even while the
/// width was wrong: <see cref="RuntimeFieldLayoutSource"/>'s <c>BaseSize</c> guard caught 8 of 8
/// broken fields, because a swallowed <c>m_type</c> bit adds <c>0x8000000</c> and no object is
/// that large. Fields went missing; none came back wrong.
/// </para>
/// <para>Lifetime: PROCESS tier (§8.8). Calibrate once at attach.</para>
/// </remarks>
public sealed class FieldDescCalibration
{
    /// <summary>How far into a <c>FieldDesc</c> the search looks. Generously past any plausible size.</summary>
    private const int SearchWindow = 64;

    /// <summary>Below this many agreeing samples the result is not trustworthy enough to use.</summary>
    private const int MinimumSamples = 3;

    /// <summary>Types visited while gathering the width corpus. Bounds a cold-path cost.</summary>
    private const int MaxCorpusTypes = 512;

    /// <summary>Field descriptors gathered. §12.5's own bar: a few hundred is decisive.</summary>
    private const int MaxCorpusFields = 1024;

    /// <summary>Below this the corpus cannot separate widths, and the width stays underivable.</summary>
    private const int MinimumCorpusFields = 8;

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

    private FieldDescCalibration(
        FieldDescEncoding? encoding,
        int sampleCount,
        int candidateCount,
        string detail,
        int corpusFields = 0,
        int corpusViolations = 0)
    {
        Encoding = encoding;
        SampleCount = sampleCount;
        CandidateCount = candidateCount;
        Detail = detail;
        CorpusFields = corpusFields;
        CorpusViolations = corpusViolations;
    }

    /// <summary>The derived encoding, or null when calibration did not converge.</summary>
    public FieldDescEncoding? Encoding { get; }

    /// <summary>True when <see cref="Encoding"/> can be used.</summary>
    public bool IsCalibrated => Encoding is not null;

    /// <summary>Number of published offsets that were successfully turned into samples.</summary>
    public int SampleCount { get; }

    /// <summary>
    /// How many distinct bitfield POSITIONS (word and shift) satisfied every anchor. One is the
    /// expected answer; more than one is reported rather than silently resolved, because picking
    /// arbitrarily is exactly the kind of plausible-but-wrong choice this class exists to avoid.
    /// The width is not part of this count — the anchors cannot determine it, so it is measured
    /// separately against <see cref="CorpusFields"/>.
    /// </summary>
    public int CandidateCount { get; }

    /// <summary>Real field descriptors the width was measured against.</summary>
    public int CorpusFields { get; }

    /// <summary>
    /// Corpus fields whose decoded offset does not fit their declaring type's <c>BaseSize</c> at
    /// the CHOSEN width. Zero on a converged calibration by construction; carried so a caller can
    /// see the measurement rather than take it on trust.
    /// </summary>
    public int CorpusViolations { get; }

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

        return Solve(memory, layouts, modulePointer, exceptionMt, corelib, samples);
    }

    private static FieldDescCalibration Solve(
        IMemoryReader memory,
        ClrLayouts layouts,
        ulong modulePointer,
        ulong exceptionMt,
        ModuleMetadata corelib,
        List<(int Rid, int ExpectedFieldDescOffset)> samples)
    {
        ulong mapAddress = modulePointer + (ulong)layouts.ModuleFieldDefMapOffset;
        int fieldRowCount = corelib.Reader.FieldDefinitions.Count;

        FieldDescCalibration? ambiguous = null;

        // A mask under which the back-pointer could NOT be derived is held back rather than
        // returned: the eight offsets are then the ONLY constraint, because
        // RuntimeFieldLayoutSource cannot cross-check a lookup without that slot. Preferring any
        // later mask that does yield one costs three futile searches at attach and buys a second,
        // independent constraint on the mask itself. It is a preference and not a requirement
        // because a runtime that stores the declaring type somewhere this search cannot see is a
        // §5.5 gap, not a fault — refusing outright would trade a working degraded mode for none.
        FieldDescCalibration? unvalidated = null;
        FieldDescCalibration? unmeasured = null;

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

            List<OffsetPosition> positions = FindOffsetPositions(descriptors);
            if (positions.Count == 0) continue;

            if (positions.Count > 1)
            {
                // Ambiguity under one mask does not condemn the others; record it and keep
                // going, but never resolve it by picking — that is the plausible-but-wrong
                // outcome this whole class exists to avoid.
                ambiguous ??= new FieldDescCalibration(
                    null, descriptors.Count, positions.Count,
                    $"ambiguous under entry mask 0x{entryMask:X}: {positions.Count} bitfield positions " +
                    $"reproduce all {descriptors.Count} known offsets, so none is trustworthy.");
                continue;
            }

            OffsetPosition position = positions[0];
            (int enclosingSlot, bool enclosingRelative) = FindEnclosingSlot(descriptors, exceptionMt, layouts.PointerSize);

            List<CorpusField> corpus = CollectCorpus(
                memory, layouts, modulePointer, corelib, entryMask, position.ByteOffset, enclosingSlot, enclosingRelative);

            if (corpus.Count < MinimumCorpusFields)
            {
                unmeasured ??= new FieldDescCalibration(
                    null, descriptors.Count, 1,
                    $"the offset field sits at +{position.ByteOffset} shifted {position.ShiftBits}, but only " +
                    $"{corpus.Count} real field descriptors could be walked out of CoreLib — too few to measure " +
                    "the field's WIDTH. The eight published anchors all have an even m_type, so they cannot " +
                    "distinguish a width from a wider one (see the type remarks).",
                    corpus.Count);
                continue;
            }

            if (!TryMeasureWidth(corpus, position, layouts.FirstFieldOffset, out int width, out string boundary))
            {
                unmeasured ??= new FieldDescCalibration(
                    null, descriptors.Count, 1,
                    $"the offset field sits at +{position.ByteOffset} shifted {position.ShiftBits}, but no width " +
                    $"the anchors permit decodes all {corpus.Count} sampled field descriptors inside their own " +
                    "BaseSize, so the field's width could not be measured.",
                    corpus.Count);
                continue;
            }

            var encoding = new FieldDescEncoding(
                entryMask, position.ByteOffset, position.ShiftBits, width, enclosingSlot, enclosingRelative);

            string enclosing = enclosingSlot < 0
                ? "no back-pointer slot derived (lookups are then bounded only by BaseSize)"
                : $"back-pointer at +{enclosingSlot} ({(enclosingRelative ? "self-relative" : "absolute")})";

            var converged = new FieldDescCalibration(
                encoding,
                descriptors.Count,
                1,
                $"derived from {descriptors.Count} System.Exception anchors: offset at +{position.ByteOffset} " +
                $"bits [{position.ShiftBits}, {position.ShiftBits + width}), entry mask 0x{entryMask:X}, {enclosing}. " +
                $"Width measured against {corpus.Count} real field descriptors ({boundary}).",
                corpus.Count);

            if (enclosingSlot >= 0) return converged;

            unvalidated ??= converged;
        }

        // A unique convergence under some mask is stronger evidence than an ambiguity under
        // another, so the held-back result outranks it.
        return unvalidated ?? ambiguous ?? unmeasured ?? new FieldDescCalibration(
            null, samples.Count, 0,
            "no bitfield position in the first 64 bytes of a FieldDesc reproduces the published " +
            "System.Exception offsets; FieldDefToDescMap may be segmented past its first block, " +
            "or this runtime stores field offsets somewhere else entirely.");
    }

    /// <summary>A word and shift the anchors agree on, plus every width they leave possible.</summary>
    /// <param name="ByteOffset">Byte offset of the 32-bit word within the <c>FieldDesc</c>.</param>
    /// <param name="ShiftBits">Right shift applied to it.</param>
    /// <param name="Widths">Widths that reproduce every anchor, ascending. Never empty.</param>
    private readonly record struct OffsetPosition(int ByteOffset, int ShiftBits, IReadOnlyList<int> Widths);

    /// <summary>One real field descriptor, reduced to what scoring a width needs.</summary>
    /// <param name="Word">The 32-bit word at the position the anchors pinned.</param>
    /// <param name="BaseSize">Published <c>MethodTable.BaseSize</c> of the declaring type.</param>
    private readonly record struct CorpusField(uint Word, uint BaseSize);

    /// <summary>
    /// Every (word, shift) that decodes ALL anchors correctly at SOME width, with the widths
    /// listed rather than collapsed.
    /// </summary>
    /// <remarks>
    /// The previous version returned one entry per position carrying the widest matching width.
    /// That silently resolved the tie the anchors cannot resolve, and it is the defect live
    /// validation caught: 27 and 28 both reproduce all eight anchors, and 28 was returned. The
    /// widths are now carried out intact so the choice is made by something that can actually
    /// see the difference.
    /// </remarks>
    private static List<OffsetPosition> FindOffsetPositions(
        List<(ulong Address, byte[] Bytes, int Expected)> descriptors)
    {
        var results = new List<OffsetPosition>();

        for (int byteOffset = 0; byteOffset + 4 <= SearchWindow; byteOffset += 4)
        {
            for (int shift = 0; shift < 32; shift++)
            {
                var widths = new List<int>();
                for (int width = 1; width <= 32 - shift; width++)
                {
                    if (Matches(descriptors, byteOffset, shift, width)) widths.Add(width);
                }

                if (widths.Count > 0) results.Add(new OffsetPosition(byteOffset, shift, widths));
            }
        }

        return results;
    }

    /// <summary>
    /// Choose the width by measurement: the widest the anchors permit that decodes every sampled
    /// field descriptor inside its own type's <c>BaseSize</c>, accepted only if the next bit up
    /// is demonstrably NOT part of the field.
    /// </summary>
    /// <remarks>
    /// <para>
    /// "Widest with zero violations" and "boundary observed" pull in opposite directions on
    /// purpose. Widest guards the narrow end: the anchors span 0..100, so widths from 7 upward
    /// all satisfy them, and any of those below the true width would truncate real offsets into
    /// small plausible values that no downstream check could catch. The boundary requirement
    /// guards the wide end: the chosen width is only accepted when the next bit is excluded by
    /// the anchors, excluded by the corpus, or does not exist. Between them the width is pinned
    /// by evidence at both ends rather than by preference at either.
    /// </para>
    /// </remarks>
    private static bool TryMeasureWidth(
        List<CorpusField> corpus, OffsetPosition position, int firstFieldOffset, out int width, out string boundary)
    {
        width = 0;
        boundary = string.Empty;

        for (int i = position.Widths.Count - 1; i >= 0; i--)
        {
            int candidate = position.Widths[i];
            if (CountViolations(corpus, position.ShiftBits, candidate, firstFieldOffset) != 0) continue;

            int next = candidate + 1;
            if (next > 32 - position.ShiftBits)
            {
                width = candidate;
                boundary = "the field ends at the word boundary";
                return true;
            }

            // The anchors already exclude the next bit: they decoded correctly at `candidate`
            // and not at `next`, which only happens if some anchor has that bit set.
            if (!position.Widths.Contains(next))
            {
                width = candidate;
                boundary = $"bit {position.ShiftBits + candidate} is set in an anchor, so it is not part of the field";
                return true;
            }

            int violationsAbove = CountViolations(corpus, position.ShiftBits, next, firstFieldOffset);
            if (violationsAbove > 0)
            {
                width = candidate;
                boundary =
                    $"widening to {next} bits overflows BaseSize on {violationsAbove} of {corpus.Count} of them, " +
                    $"so bit {position.ShiftBits + candidate} belongs to the neighbouring field";
                return true;
            }

            // Neither the anchors nor real data can tell this bit apart from the field's own.
            // Claiming it is the unsafe direction, and that is the whole finding here.
            return false;
        }

        return false;
    }

    /// <summary>
    /// Field descriptors whose decoded offset does not fit inside their declaring type.
    /// </summary>
    /// <remarks>
    /// <c>MethodTable.BaseSize</c> (§5.2) is the size of an instance with no elements, so every
    /// instance field must lie inside it. A window one bit too wide picks up the low bit of the
    /// element type, which adds <c>2^(shift+width-1)</c> — vastly past any object — so a wrong
    /// width does not produce a subtly wrong number here, it produces an impossible one.
    /// </remarks>
    private static int CountViolations(List<CorpusField> corpus, int shift, int width, int firstFieldOffset)
    {
        int violations = 0;
        foreach (CorpusField field in corpus)
        {
            long objectRelative = FieldDescEncoding.Decode(field.Word, shift, width) + (long)firstFieldOffset;
            if (objectRelative >= field.BaseSize) violations++;
        }

        return violations;
    }

    /// <summary>
    /// Walks CoreLib's own loaded types for real field descriptors to measure a width against.
    /// </summary>
    /// <remarks>
    /// Self-validating target data, not a constant: every type is reached through
    /// <c>Module.TypeDefToMethodTableMap</c> and kept only if its <c>MethodTable.Module</c> points
    /// back at the module we came from, and every field descriptor is kept only if its
    /// back-pointer agrees too. Types are visited in rid order and the walk stops as soon as it
    /// has enough — this runs once, at attach, on the cold path.
    /// </remarks>
    private static List<CorpusField> CollectCorpus(
        IMemoryReader memory,
        ClrLayouts layouts,
        ulong modulePointer,
        ModuleMetadata corelib,
        ulong entryMask,
        int byteOffset,
        int enclosingSlot,
        bool enclosingRelative)
    {
        var corpus = new List<CorpusField>();

        ulong typeMap = modulePointer + (ulong)layouts.ModuleTypeDefMapOffset;
        ulong fieldMap = modulePointer + (ulong)layouts.ModuleFieldDefMapOffset;

        if (!memory.TryReadPointer(typeMap + (ulong)layouts.LookupMapTableDataOffset, out ulong table) || table == 0)
        {
            return corpus;
        }

        int stride = layouts.PointerSize;
        int typeCount = corelib.Reader.TypeDefinitions.Count;
        int fieldRowCount = corelib.Reader.FieldDefinitions.Count;
        var raw = new byte[Math.Max(4096 / stride, 1) * stride];
        int types = 0;

        for (int first = 1; first <= typeCount && corpus.Count < MaxCorpusFields && types < MaxCorpusTypes;)
        {
            ulong address = table + ((ulong)first * (ulong)stride);

            // Clipped to a page, so an unmapped one costs only the rids it holds.
            int count = ClrLayouts.EntriesWithinPage(address, stride, typeCount - first + 1);
            int scanned = count;

            if (!memory.TryRead(address, raw.AsSpan(0, count * stride)))
            {
                first += scanned;
                continue;
            }

            for (int i = 0; i < count && corpus.Count < MaxCorpusFields && types < MaxCorpusTypes; i++)
            {
                ulong methodTable = (stride == 8 ? BitConverter.ToUInt64(raw, i * 8) : BitConverter.ToUInt32(raw, i * 4)) & ~7UL;
                if (methodTable == 0) continue;

                // Only believe a method table that claims the module we walked it out of.
                if (!memory.TryReadPointer(methodTable + (ulong)layouts.MethodTableModuleOffset, out ulong owner)) continue;
                if (owner != modulePointer) continue;
                if (!memory.TryRead(methodTable + (ulong)layouts.MethodTableBaseSizeOffset, out uint baseSize)) continue;
                if (baseSize <= (uint)layouts.FirstFieldOffset) continue;

                types++;
                TypeDefinitionHandle handle = MetadataTokens.TypeDefinitionHandle(first + i);

                foreach (MetadataField field in corelib.Types.GetFields(handle))
                {
                    if (corpus.Count >= MaxCorpusFields) break;
                    if (field.IsStatic || field.IsLiteral) continue;

                    int rid = field.Token & 0x00FF_FFFF;
                    if (!layouts.TryGetLookupMapSlot(memory, fieldMap, rid, fieldRowCount, out ulong slot)) continue;
                    if (!memory.TryReadPointer(slot, out ulong entry)) continue;

                    ulong fieldDesc = entry & entryMask;
                    if (fieldDesc == 0) continue;
                    if (!IsDeclaredBy(memory, layouts, fieldDesc, enclosingSlot, enclosingRelative, modulePointer)) continue;
                    if (!memory.TryRead(fieldDesc + (ulong)byteOffset, out uint word)) continue;

                    corpus.Add(new CorpusField(word, baseSize));
                }
            }

            first += scanned;
        }

        return corpus;
    }

    /// <summary>
    /// Whether a candidate <c>FieldDesc</c> really belongs to the module being walked. Compared
    /// at module granularity because a generic instantiation's fields are described by the
    /// canonical type's descriptors, not the instantiation's.
    /// </summary>
    private static bool IsDeclaredBy(
        IMemoryReader memory,
        ClrLayouts layouts,
        ulong fieldDesc,
        int enclosingSlot,
        bool enclosingRelative,
        ulong modulePointer)
    {
        if (enclosingSlot < 0) return true;

        var probe = new FieldDescEncoding(0, 0, 0, 0, enclosingSlot, enclosingRelative);
        if (!probe.TryReadEnclosingMethodTable(memory, fieldDesc, out ulong enclosing)) return false;

        return memory.TryReadPointer(enclosing + (ulong)layouts.MethodTableModuleOffset, out ulong owner)
            && owner == modulePointer;
    }

    private static bool Matches(
        List<(ulong Address, byte[] Bytes, int Expected)> descriptors,
        int byteOffset,
        int shift,
        int width)
    {
        foreach ((_, byte[] bytes, int expected) in descriptors)
        {
            uint word = BitConverter.ToUInt32(bytes, byteOffset);
            if (FieldDescEncoding.Decode(word, shift, width) != (uint)expected) return false;
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
