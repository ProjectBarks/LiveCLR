namespace LiveClr.Fixtures;

using LiveClr.Memory;

/// <summary>
/// An <see cref="IMemoryReader"/> backed by bytes captured earlier from a real process.
/// </summary>
/// <remarks>
/// <para>This is the recorded-fixture provider of analysis doc §8.8 ("Two additions", item 1).
/// The motivation is blunt: every result in §12 — the type walk, the 30/30 offset table,
/// the in-run gameplay read, the §12.4e tearing measurement — required an attached, running
/// game. Without a replayable capture, <c>LiveClr.Tests</c> cannot run in CI at all, and the
/// whole library is only testable on one developer's machine with one build of one game open.</para>
///
/// <para><b>A fixture is a snapshot, not a history.</b> Captures are coalesced and overlaps are
/// last-write-wins, so a recording taken from a live, mutating process is a composite image
/// that may never have existed at any single instant — bytes at 0x1000 can be from t=0 while
/// bytes at 0x2000 are from t=5. For a page-cached snapshot (§4.7) that is exactly right,
/// because each page is read once. For a long recording across a mutating heap it is not:
/// such a fixture cannot reproduce the §12.4e torn walk, since tearing IS two reads of the
/// same address disagreeing over time and coalescing destroys precisely that. Record one
/// snapshot per fixture.</para>
///
/// <para>Replay is deliberately dumb and fails closed: a read is served only when the entire
/// span lies inside one captured region. Extrapolating (zero-filling a gap, stitching across a
/// hole) would reproduce exactly the failure mode §4.8/§6.4 call the most expensive one —
/// a read that "succeeds" with garbage. A fixture that says false is debuggable; a fixture
/// that says true with invented bytes is not.</para>
/// </remarks>
public sealed class RecordedMemory : IMemoryReader
{
    private readonly RegionMap _map;
    private RecordedRegion[]? _regions;

    internal RecordedMemory(RegionMap map, bool is64Bit, string description)
    {
        _map = map;
        Is64Bit = is64Bit;
        Description = description;
    }

    /// <inheritdoc />
    public bool Is64Bit { get; }

    /// <summary>Free-text provenance carried in the file header (process, build, capture date).</summary>
    /// <remarks>
    /// A fixture with no provenance is unmaintainable: when it starts disagreeing with a live
    /// process, the first question is always "which build was this taken from?".
    /// </remarks>
    public string Description { get; }

    /// <summary>Number of coalesced regions. Diagnostic only.</summary>
    public int RegionCount => _map.Count;

    /// <summary>Total captured bytes across all regions.</summary>
    public long RecordedByteCount => _map.TotalBytes;

    /// <summary>The captured regions, ascending by address, non-overlapping and non-adjacent.</summary>
    /// <remarks>Computed once — a recording is immutable after construction.</remarks>
    public IReadOnlyList<RecordedRegion> Regions =>
        _regions ??= _map.Entries.Select(e => new RecordedRegion(e.Start, e.Data)).ToArray();

    /// <inheritdoc />
    /// <remarks>
    /// Returns false for any span not fully covered by the recording. A zero-length read
    /// succeeds at any address: nothing was requested, so nothing is invented.
    /// </remarks>
    public bool TryRead(ulong address, Span<byte> buffer) => _map.TryRead(address, buffer);

    /// <summary>True if every byte of the span was captured. Does not copy.</summary>
    public bool Covers(ulong address, int length) => _map.Covers(address, length);

    /// <summary>Write this recording to a stream in the container format described on <see cref="RecordedMemoryFormat"/>.</summary>
    public void Save(Stream stream) => RecordedMemoryFormat.Write(stream, _map, Is64Bit, Description);

    /// <summary>Write this recording to a file.</summary>
    public void Save(string path)
    {
        using var fs = File.Create(path);
        Save(fs);
    }

    /// <summary>Read a recording written by <see cref="Save(Stream)"/>.</summary>
    /// <exception cref="InvalidDataException">
    /// The stream is not a fixture, is a version this build does not understand, is truncated,
    /// or is not canonical (regions must be ascending, disjoint and non-adjacent). Malformed
    /// input never escapes as some other exception type — see <see cref="RecordedMemoryFormat"/>.
    /// </exception>
    public static RecordedMemory Load(Stream stream) => RecordedMemoryFormat.Read(stream);

    /// <summary>Read a recording from a file.</summary>
    /// <exception cref="InvalidDataException">As <see cref="Load(Stream)"/>.</exception>
    public static RecordedMemory Load(string path)
    {
        using var fs = File.OpenRead(path);
        return Load(fs);
    }

    /// <summary>No-op. A recording owns nothing but managed arrays; present only to satisfy <see cref="IMemoryReader"/>.</summary>
    public void Dispose()
    {
        // Intentionally empty — see summary.
    }

    /// <inheritdoc />
    public override string ToString() =>
        $"RecordedMemory({(Is64Bit ? "x64" : "x86")}, {RegionCount} regions, {RecordedByteCount} bytes)";
}

/// <summary>One captured range of target memory.</summary>
public readonly record struct RecordedRegion(ulong Address, ReadOnlyMemory<byte> Bytes)
{
    /// <summary>Exclusive end address.</summary>
    public ulong EndAddress => Address + (ulong)Bytes.Length;
}
