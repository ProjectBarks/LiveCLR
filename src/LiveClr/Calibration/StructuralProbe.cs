namespace LiveClr.Calibration;

using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using LiveClr.Memory;

/// <summary>
/// Derives struct field offsets from ground truth instead of hardcoding them.
/// </summary>
/// <remarks>
/// <para><b>Why this exists.</b> Analysis doc §4.5 / §7b.2: a hardcoded offset table is
/// specific to one cell of a large matrix (engine version x build template x float precision x
/// fork), and §12 had validated exactly one cell. §12.5 tested the alternative — rediscover the
/// offsets at connect time from independently-known ground truth — and it worked with zero prior
/// knowledge of any offset:</para>
/// <list type="bullet">
/// <item>parent pointer, derived <c>0x128</c>, expected <c>0x128</c> — MATCH (one sample was enough:
/// a specific address is unique in the process)</item>
/// <item>child-list head, derived <c>0x148</c>, expected <c>0x148</c> — MATCH (indirect: the only
/// slot <c>p</c> where <c>*(p + 0x18)</c> is a known child)</item>
/// <item>size, derived <c>0x4c0</c> — uniquely, and only after intersecting two samples</item>
/// </list>
/// <para>The consequence §7b.2 draws: the offset table becomes a cache and a self-check, not
/// the source of truth. Calibrate, compare against the shipped table, warn on divergence — an
/// engine update becomes a startup diagnostic rather than silent breakage.</para>
///
/// <para><b>Deliberately engine-agnostic</b> (§8.8, "Two additions" item 2). This class knows
/// about addresses, pointers and bit patterns. It contains no Godot type, no notion of a node
/// or a control, and no semantics. The <i>semantic</i> half of calibration — knowing that a
/// full-screen control's size equals the design viewport, which is what supplies the expected
/// value — is engine-specific and belongs in the engine adapter. Keeping them together is what
/// §8.8 objects to: it buries a reusable trick inside an adapter nobody else can use.</para>
///
/// <para><b>Every method returns candidates, not an answer</b>, and every result carries whether
/// its window was fully readable. See <see cref="CalibrationResult"/>.</para>
/// </remarks>
public sealed class StructuralProbe
{
    /// <summary>
    /// Floor for the bisecting fallback read. A window that crosses unmapped memory is probed
    /// down to individual bytes so that captured bytes near the boundary are still scanned —
    /// coarse chunking would discard up to a chunk of perfectly readable memory, and a dropped
    /// candidate is how an intersection ends up confidently wrong.
    /// </summary>
    private const int MinProbeBytes = 1;

    /// <summary>
    /// Ceiling on refinement reads per window, so a wholly-unmapped 16 MiB window cannot turn
    /// into millions of syscalls. Exhausting it only ever loses coverage, and lost coverage is
    /// reported (<see cref="CalibrationResult.CompleteCoverage"/>), never hidden.
    /// </summary>
    private const int MaxRefinementReads = 8192;

    /// <summary>Refuses absurd windows: calibration scans a struct, not the heap.</summary>
    private const int MaxScanBytes = 16 * 1024 * 1024;

    private readonly IMemoryReader _reader;

    /// <summary>Creates a probe over a reader — live, page-cached, or a recorded fixture.</summary>
    /// <remarks>
    /// Works unchanged against <see cref="LiveClr.Fixtures.RecordedMemory"/>, which is how these
    /// techniques are regression-tested in CI without a running game (§8.8, §12.4e).
    /// </remarks>
    public StructuralProbe(IMemoryReader reader)
    {
        ArgumentNullException.ThrowIfNull(reader);
        _reader = reader;
    }

    /// <summary>Pointer width of the target, from <see cref="IMemoryReader.Is64Bit"/>.</summary>
    public int PointerSize => _reader.Is64Bit ? 8 : 4;

    // ---------------------------------------------------------------------
    // Technique 1 — a field holding a known pointer. STRUCTURAL.
    // ---------------------------------------------------------------------

    /// <summary>
    /// Offsets within <paramref name="containerAddress"/> whose stored pointer equals
    /// <paramref name="expectedTarget"/>.
    /// </summary>
    /// <remarks>
    /// This is the §12.5 parent-pointer derivation: given a known parent/child pair, the parent
    /// offset is the slot in the child equal to the parent's own address. It rediscovered
    /// <c>0x128</c> with no prior knowledge.
    ///
    /// <para>Structural, so one sample may determine the offset: a specific live address exists
    /// once in the process, unlike a semantic value such as "50". Coverage still has to be
    /// complete, and a second pair is still cheap insurance against a cached back-pointer.</para>
    ///
    /// <para>Passing <c>0</c> as the expected target matches every zeroed slot and is almost
    /// always a mistake.</para>
    /// </remarks>
    /// <param name="containerAddress">Base address of the object to scan.</param>
    /// <param name="expectedTarget">The pointer value to look for.</param>
    /// <param name="scanBytes">How far past the base to scan. Large enough to cover the subclass.</param>
    /// <param name="alignment">Candidate stride; defaults to pointer size, which is how a compiler lays pointers out.</param>
    public CalibrationResult FindPointerOffset(
        ulong containerAddress, ulong expectedTarget, int scanBytes, int alignment = 0)
    {
        int step = ResolveAlignment(alignment, PointerSize);
        var scan = ScanOne(containerAddress, scanBytes, step, PointerSize,
            (window, offset) => ReadPointerAt(window, offset) == expectedTarget);

        return Result(scan, CalibrationTechnique.Structural, containerAddress,
            $"pointer == 0x{expectedTarget:x}");
    }

    /// <summary>
    /// <see cref="FindPointerOffset(ulong,ulong,int,int)"/> over several samples of the SAME
    /// struct type, keeping only offsets valid for all of them.
    /// </summary>
    /// <remarks>
    /// Pointer scans are usually unambiguous on one sample, but "usually" is not a guarantee —
    /// a cached back-pointer, an intrusive list link and a parent field can all hold the same
    /// value. Samples must be distinct objects; sharing the same expected target is fine and
    /// expected here (two children of one parent).
    /// </remarks>
    /// <exception cref="ArgumentException">Fewer than two samples, or two samples at one address.</exception>
    public CalibrationResult FindPointerOffsetAcross(
        IReadOnlyList<PointerSample> samples, int scanBytes, int alignment = 0)
    {
        RequireDistinctSamples(samples, s => s.Address);
        return CalibrationResult.Intersect(samples.Select(
            s => FindPointerOffset(s.Address, s.ExpectedTarget, scanBytes, alignment)));
    }

    /// <summary>
    /// Offsets holding a pointer <c>p</c> such that <c>*(p + indirectionOffset)</c> equals
    /// <paramref name="expectedTarget"/>.
    /// </summary>
    /// <remarks>
    /// The §12.5 child-list head: the container does not point at the child directly, it points
    /// at a list node whose first element is the child. Derived <c>0x148</c> as "the only pointer
    /// <c>p</c> where <c>*(p + 0x18)</c> is a known child". Generalises to any one-hop
    /// indirection — a collection header, a vtable slot, an intrusive list link.
    ///
    /// <para>Each candidate costs one extra read, so this is the slowest probe here; it is a
    /// connect-time cost, not a polling-loop cost.</para>
    /// </remarks>
    /// <param name="containerAddress">Base address of the object to scan.</param>
    /// <param name="expectedTarget">Pointer expected at <c>p + indirectionOffset</c>.</param>
    /// <param name="indirectionOffset">Offset applied to the intermediate pointer before the second read.</param>
    /// <param name="scanBytes">How far past the base to scan.</param>
    /// <param name="alignment">Candidate stride; defaults to pointer size.</param>
    public CalibrationResult FindIndirectPointerOffset(
        ulong containerAddress, ulong expectedTarget, int indirectionOffset, int scanBytes, int alignment = 0)
    {
        int step = ResolveAlignment(alignment, PointerSize);

        var scan = ScanOne(containerAddress, scanBytes, step, PointerSize, (window, offset) =>
        {
            ulong intermediate = ReadPointerAt(window, offset);
            if (intermediate == 0) return false;

            // Fail closed on the second hop: an unreadable intermediate is not a match.
            ulong probeAddress = unchecked(intermediate + (ulong)(long)indirectionOffset);
            return _reader.TryReadPointer(probeAddress, out ulong reached) && reached == expectedTarget;
        });

        return Result(scan, CalibrationTechnique.Structural, containerAddress,
            $"*(p + 0x{indirectionOffset:x}) == 0x{expectedTarget:x}");
    }

    /// <summary>Intersecting form of <see cref="FindIndirectPointerOffset"/>.</summary>
    /// <exception cref="ArgumentException">Fewer than two samples, or two samples at one address.</exception>
    public CalibrationResult FindIndirectPointerOffsetAcross(
        IReadOnlyList<PointerSample> samples, int indirectionOffset, int scanBytes, int alignment = 0)
    {
        RequireDistinctSamples(samples, s => s.Address);
        return CalibrationResult.Intersect(samples.Select(
            s => FindIndirectPointerOffset(
                s.Address, s.ExpectedTarget, indirectionOffset, scanBytes, alignment)));
    }

    // ---------------------------------------------------------------------
    // Technique 2 — a field holding a known value. SEMANTIC: needs intersection.
    // ---------------------------------------------------------------------

    /// <summary>
    /// Candidate offsets within <paramref name="objectAddress"/> whose bytes equal
    /// <paramref name="expectedValue"/>.
    /// </summary>
    /// <remarks>
    /// <b>One sample is not an answer, and this method's result knows it</b> — the returned
    /// <see cref="CalibrationResult"/> is <see cref="CalibrationTechnique.Semantic"/> with a
    /// single sample, so <see cref="CalibrationResult.Offset"/> throws even if exactly one
    /// candidate matched. Read <see cref="CalibrationResult.Candidates"/> to inspect; use
    /// <see cref="FindValueOffsetAcross{T}"/> to actually derive an offset.
    ///
    /// <para>§12.5: a single 200x50 control produced four candidate size offsets (0x4c0, 0x4c8,
    /// 0x4d4, 0x4f4). Values that are small, round, or duplicated in cached/derived fields
    /// collide constantly, and a lone match is indistinguishable from a lucky one.</para>
    ///
    /// <para>Comparison is on the exact bit pattern, so <c>NaN</c> never matches and
    /// <c>-0.0f</c> does not match <c>0.0f</c>. For computed floats that will not be
    /// bit-identical, use <see cref="FindFloatOffset"/> with a tolerance.</para>
    /// </remarks>
    /// <typeparam name="T">Field type. Must have the same layout in this process as in the target.</typeparam>
    /// <param name="objectAddress">Base address of the object to scan.</param>
    /// <param name="expectedValue">Independently-known value the field must hold.</param>
    /// <param name="scanBytes">How far past the base to scan.</param>
    /// <param name="alignment">Candidate stride; defaults to <c>sizeof(T)</c>. Pass 1 for packed or unknown layouts.</param>
    public CalibrationResult FindValueOffset<T>(
        ulong objectAddress, T expectedValue, int scanBytes, int alignment = 0) where T : unmanaged
    {
        int size = Unsafe.SizeOf<T>();
        int step = ResolveAlignment(alignment, size);
        byte[] expected = ToBytes(expectedValue);

        var scan = ScanOne(objectAddress, scanBytes, step, size,
            (window, offset) => window.Slice(offset, size).SequenceEqual(expected));

        return Result(scan, CalibrationTechnique.Semantic, objectAddress,
            $"{typeof(T).Name} == {expectedValue}");
    }

    /// <summary>
    /// The disambiguation step, and the point of this whole class: scan several objects of the
    /// same struct type with DIFFERENT known values and keep only offsets valid for all of them.
    /// </summary>
    /// <remarks>
    /// §12.5, verbatim result: one full-screen control gave the size offset directly, a second
    /// control of 200x50 gave four candidates, and the intersection was exactly one — <c>0x4c0</c>,
    /// "uniquely derived with zero prior knowledge". A third sample hardens it further.
    ///
    /// <para>Requires at least two samples at distinct addresses carrying at least two distinct
    /// expected values, by design. One sample cannot distinguish the field from its
    /// coincidences, and two samples that share a value cannot separate the real field from a
    /// co-varying neighbour.</para>
    /// </remarks>
    /// <exception cref="ArgumentException">Fewer than two samples, duplicate addresses, or a single distinct value.</exception>
    public CalibrationResult FindValueOffsetAcross<T>(
        IReadOnlyList<ValueSample<T>> samples, int scanBytes, int alignment = 0) where T : unmanaged
    {
        RequireDistinctSamples(samples, s => s.Address, s => s.ExpectedValue);
        return CalibrationResult.Intersect(samples.Select(
            s => FindValueOffset(s.Address, s.ExpectedValue, scanBytes, alignment)));
    }

    // ---------------------------------------------------------------------
    // Technique 3 — adjacent pairs (a Vector2 and friends). SEMANTIC.
    // ---------------------------------------------------------------------

    /// <summary>
    /// Candidate offsets where <paramref name="first"/> is immediately followed by
    /// <paramref name="second"/> — i.e. the start of a two-component vector.
    /// </summary>
    /// <remarks>
    /// How §12.5 found the size and position offsets: scan for the design viewport
    /// <c>1920 x 1080</c> as an adjacent float pair. Adjacency is doing real work — <c>1920.0f</c>
    /// alone appears in many unrelated fields of a real UI object, while the ordered pair is rare.
    /// Returns the offset of the FIRST component, which is the vector's own offset.
    ///
    /// <para>Semantic: single-sample results are candidates only. Use
    /// <see cref="FindAdjacentPairOffsetAcross{T}"/> for an answer.</para>
    /// </remarks>
    /// <typeparam name="T">Component type, compared by exact bit pattern.</typeparam>
    /// <param name="objectAddress">Base address of the object to scan.</param>
    /// <param name="first">Expected first component.</param>
    /// <param name="second">Expected second component, stored immediately after the first.</param>
    /// <param name="scanBytes">How far past the base to scan.</param>
    /// <param name="alignment">Candidate stride; defaults to <c>sizeof(T)</c>.</param>
    public CalibrationResult FindAdjacentPairOffset<T>(
        ulong objectAddress, T first, T second, int scanBytes, int alignment = 0) where T : unmanaged
    {
        int size = Unsafe.SizeOf<T>();
        int step = ResolveAlignment(alignment, size);
        byte[] expected = ToBytes(first, second);

        var scan = ScanOne(objectAddress, scanBytes, step, size * 2,
            (window, offset) => window.Slice(offset, size * 2).SequenceEqual(expected));

        return Result(scan, CalibrationTechnique.Semantic, objectAddress,
            $"adjacent {typeof(T).Name} pair ({first}, {second})");
    }

    /// <summary>
    /// Intersecting form of <see cref="FindAdjacentPairOffset{T}"/> — the exact shape of the
    /// §12.5 size derivation (full-screen control, then a 200x50 control).
    /// </summary>
    /// <exception cref="ArgumentException">Fewer than two samples, duplicate addresses, or a single distinct value.</exception>
    public CalibrationResult FindAdjacentPairOffsetAcross<T>(
        IReadOnlyList<PairSample<T>> samples, int scanBytes, int alignment = 0) where T : unmanaged
    {
        RequireDistinctSamples(samples, s => s.Address, s => (s.First, s.Second));
        return CalibrationResult.Intersect(samples.Select(
            s => FindAdjacentPairOffset(s.Address, s.First, s.Second, scanBytes, alignment)));
    }

    // ---------------------------------------------------------------------
    // Tolerant float variants. SEMANTIC, and the most collision-prone of all.
    // ---------------------------------------------------------------------

    /// <summary>
    /// Like <see cref="FindValueOffset{T}"/> but compares floats within
    /// <paramref name="tolerance"/>.
    /// </summary>
    /// <remarks>
    /// Ground truth is only exactly representable when it is authored (a design viewport, a
    /// configured cell size). Anything the engine computed — a layout result, an anchor-derived
    /// size — will be close but not bit-identical, and an exact scan then finds nothing at all,
    /// which looks like "wrong layout" rather than "wrong comparison".
    /// <para>A wide tolerance buys ambiguity, so widen it and lean harder on intersection
    /// (<see cref="FindFloatOffsetAcross"/>). A non-positive tolerance falls back to IEEE
    /// equality, which — unlike the bitwise <see cref="FindValueOffset{T}"/> — treats
    /// <c>-0.0f</c> as <c>0.0f</c> and still never matches <c>NaN</c>.</para>
    /// </remarks>
    public CalibrationResult FindFloatOffset(
        ulong objectAddress, float expectedValue, float tolerance, int scanBytes, int alignment = 0)
    {
        int step = ResolveAlignment(alignment, sizeof(float));

        var scan = ScanOne(objectAddress, scanBytes, step, sizeof(float),
            (window, offset) => Near(MemoryMarshal.Read<float>(window.Slice(offset, 4)), expectedValue, tolerance));

        return Result(scan, CalibrationTechnique.Semantic, objectAddress,
            $"float ≈ {expectedValue} (±{tolerance})");
    }

    /// <summary>Intersecting form of <see cref="FindFloatOffset"/>.</summary>
    /// <remarks>
    /// A tolerant scalar scan is the most ambiguity-prone probe here — one component, one
    /// object, and a window of slack — so it needs intersection more than anything else does.
    /// </remarks>
    /// <exception cref="ArgumentException">Fewer than two samples, duplicate addresses, or a single distinct value.</exception>
    public CalibrationResult FindFloatOffsetAcross(
        IReadOnlyList<ValueSample<float>> samples, float tolerance, int scanBytes, int alignment = 0)
    {
        RequireDistinctSamples(samples, s => s.Address, s => s.ExpectedValue);
        return CalibrationResult.Intersect(samples.Select(
            s => FindFloatOffset(s.Address, s.ExpectedValue, tolerance, scanBytes, alignment)));
    }

    /// <summary>Tolerant form of <see cref="FindAdjacentPairOffset{T}"/> for float pairs.</summary>
    public CalibrationResult FindFloatPairOffset(
        ulong objectAddress, float first, float second, float tolerance, int scanBytes, int alignment = 0)
    {
        int step = ResolveAlignment(alignment, sizeof(float));

        var scan = ScanOne(objectAddress, scanBytes, step, sizeof(float) * 2, (window, offset) =>
            Near(MemoryMarshal.Read<float>(window.Slice(offset, 4)), first, tolerance) &&
            Near(MemoryMarshal.Read<float>(window.Slice(offset + 4, 4)), second, tolerance));

        return Result(scan, CalibrationTechnique.Semantic, objectAddress,
            $"adjacent float pair ≈ ({first}, {second}) (±{tolerance})");
    }

    /// <summary>Intersecting form of <see cref="FindFloatPairOffset"/>.</summary>
    /// <exception cref="ArgumentException">Fewer than two samples, duplicate addresses, or a single distinct value.</exception>
    public CalibrationResult FindFloatPairOffsetAcross(
        IReadOnlyList<PairSample<float>> samples, float tolerance, int scanBytes, int alignment = 0)
    {
        RequireDistinctSamples(samples, s => s.Address, s => (s.First, s.Second));
        return CalibrationResult.Intersect(samples.Select(
            s => FindFloatPairOffset(s.Address, s.First, s.Second, tolerance, scanBytes, alignment)));
    }

    // ---------------------------------------------------------------------
    // Machinery.
    // ---------------------------------------------------------------------

    private delegate bool OffsetMatcher(ReadOnlySpan<byte> window, int offset);

    /// <summary>Candidates from one object, plus whether the window backing them was whole.</summary>
    private readonly record struct Scan(List<int> Hits, bool CompleteCoverage);

    private Scan ScanOne(ulong address, int scanBytes, int step, int itemSize, OffsetMatcher match)
    {
        ValidateWindow(address, scanBytes);

        var window = ReadWindow(address, scanBytes);
        var hits = new List<int>();

        for (int offset = 0; offset + itemSize <= scanBytes; offset += step)
        {
            if (!window.IsReadable(offset, itemSize)) continue;
            if (match(window.Bytes, offset)) hits.Add(offset);
        }

        return new Scan(hits, window.FullyReadable);
    }

    private static CalibrationResult Result(
        Scan scan, CalibrationTechnique technique, ulong address, string description) =>
        CalibrationResult.From(
            scan.Hits,
            technique,
            new CalibrationResult.SampleKey(address, description),
            scan.CompleteCoverage,
            description);

    private Window ReadWindow(ulong address, int scanBytes)
    {
        var bytes = new byte[scanBytes];
        if (_reader.TryRead(address, bytes))
            return new Window(bytes, null);

        // The window crosses something unreadable. Bisect rather than give up, and rather than
        // writing off a whole fixed-size chunk: an object near the end of a mapped region is
        // ordinary, and every byte discarded here is a candidate that silently disappears from
        // an intersection. What cannot be read is recorded as such, never guessed.
        var valid = new List<ByteRange>();
        int budget = MaxRefinementReads;
        Refine(address, bytes, 0, scanBytes, valid, ref budget);

        return new Window(bytes, valid);
    }

    private void Refine(ulong baseAddress, byte[] buffer, int offset, int length, List<ByteRange> valid, ref int budget)
    {
        if (length <= 0 || budget <= 0) return;

        budget--;
        if (_reader.TryRead(baseAddress + (ulong)offset, buffer.AsSpan(offset, length)))
        {
            // Ranges are produced in ascending order, so merging with the tail keeps them sorted.
            if (valid.Count > 0 && valid[^1].End == offset) valid[^1] = valid[^1] with { End = offset + length };
            else valid.Add(new ByteRange(offset, offset + length));
            return;
        }

        if (length <= MinProbeBytes) return;

        int half = length / 2;
        Refine(baseAddress, buffer, offset, half, valid, ref budget);
        Refine(baseAddress, buffer, offset + half, length - half, valid, ref budget);
    }

    private record struct ByteRange(int Start, int End);

    /// <summary>A scan window plus which parts of it were actually readable.</summary>
    private readonly struct Window
    {
        public readonly byte[] Bytes;
        private readonly List<ByteRange>? _valid;

        public Window(byte[] bytes, List<ByteRange>? valid)
        {
            Bytes = bytes;
            // A bisected window that turned out to cover everything is as good as a whole read.
            _valid = valid is { Count: 1 } one && one[0].Start == 0 && one[0].End == bytes.Length ? null : valid;
        }

        /// <summary>False if any byte of the window was unreadable.</summary>
        public bool FullyReadable => _valid is null;

        /// <summary>True only if the whole span was read. Bytes never read stay zero and are never compared.</summary>
        public bool IsReadable(int offset, int length)
        {
            if (_valid is null) return true;

            // Ranges are sorted and disjoint: find the last one starting at or before offset.
            int lo = 0, hi = _valid.Count - 1, found = -1;
            while (lo <= hi)
            {
                int mid = (int)(((uint)lo + (uint)hi) >> 1);
                if (_valid[mid].Start <= offset) { found = mid; lo = mid + 1; }
                else hi = mid - 1;
            }

            return found >= 0 && offset + length <= _valid[found].End;
        }
    }

    private ulong ReadPointerAt(ReadOnlySpan<byte> window, int offset) =>
        _reader.Is64Bit
            ? MemoryMarshal.Read<ulong>(window.Slice(offset, 8))
            : MemoryMarshal.Read<uint>(window.Slice(offset, 4));

    /// <remarks>NaN matches nothing, with or without a tolerance — including another NaN.</remarks>
    private static bool Near(float actual, float expected, float tolerance) =>
        tolerance <= 0f
            ? actual == expected
            : Math.Abs(actual - expected) <= tolerance;

    private static byte[] ToBytes<T>(T value) where T : unmanaged
    {
        var bytes = new byte[Unsafe.SizeOf<T>()];
        MemoryMarshal.Write(bytes, in value);
        return bytes;
    }

    private static byte[] ToBytes<T>(T first, T second) where T : unmanaged
    {
        int size = Unsafe.SizeOf<T>();
        var bytes = new byte[size * 2];
        MemoryMarshal.Write(bytes.AsSpan(0, size), in first);
        MemoryMarshal.Write(bytes.AsSpan(size, size), in second);
        return bytes;
    }

    private static int ResolveAlignment(int requested, int natural)
    {
        if (requested == 0) return natural;
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(requested, "alignment");
        return requested;
    }

    private static void ValidateWindow(ulong address, int scanBytes)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(scanBytes, nameof(scanBytes));
        ArgumentOutOfRangeException.ThrowIfGreaterThan(scanBytes, MaxScanBytes, nameof(scanBytes));

        if ((ulong)scanBytes > ulong.MaxValue - address)
            throw new ArgumentException("Scan window wraps the end of the address space.", nameof(scanBytes));
    }

    /// <summary>Two or more samples, each a different object.</summary>
    private static void RequireDistinctSamples<TSample>(
        IReadOnlyList<TSample> samples, Func<TSample, ulong> address)
    {
        ArgumentNullException.ThrowIfNull(samples);

        if (samples.Count < 2)
        {
            throw new ArgumentException(
                "Calibration by intersection needs at least two samples with different expected " +
                "values. One sample yields candidates, not an offset — analysis doc §12.5 records " +
                "a single control producing four candidate size offsets, of which one was correct. " +
                "Use the single-sample overload only when you intend to inspect candidates yourself.",
                nameof(samples));
        }

        if (samples.Select(address).Distinct().Count() != samples.Count)
        {
            throw new ArgumentException(
                "Samples must be distinct objects, but two share an address. Re-scanning one object " +
                "cannot narrow anything: the second scan returns the same candidates as the first.",
                nameof(samples));
        }
    }

    /// <summary>As above, and the expected values must not all be identical.</summary>
    private static void RequireDistinctSamples<TSample, TValue>(
        IReadOnlyList<TSample> samples, Func<TSample, ulong> address, Func<TSample, TValue> value)
    {
        RequireDistinctSamples(samples, address);

        if (samples.Select(value).Distinct().Count() < 2)
        {
            throw new ArgumentException(
                "Samples must carry at least two DIFFERENT expected values. Objects sharing a value " +
                "cannot separate the real field from a co-varying neighbour — analysis doc §12.5 " +
                "collapsed four candidates only because the second control had a different size.",
                nameof(samples));
        }
    }
}
