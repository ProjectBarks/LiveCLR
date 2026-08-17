namespace LiveClr.Fixtures;

using System.Text;

/// <summary>
/// The on-disk container for a <see cref="RecordedMemory"/> fixture.
/// </summary>
/// <remarks>
/// <para>Binary, not JSON, on purpose. A snapshot page cache (§4.7) is multi-megabyte —
/// §7b.3 alone bulk-copies a ~5 MB metadata blob per module — and base64-in-JSON would
/// inflate that by a third while making a round-trip test a text-diff problem instead of a
/// byte-equality problem. Fixtures are committed artefacts; size and exactness both matter.</para>
///
/// <para>Self-describing header so a stale fixture fails loudly rather than deserializing
/// into plausible nonsense:</para>
/// <code>
/// offset  size  field
/// 0       8     magic       'L','C','L','R','F','I','X', 0x1A
/// 8       4     version     u32, currently 1
/// 12      4     flags       u32, bit0 = target is 64-bit; unknown bits rejected
/// 16      var   description length-prefixed UTF-8 (BinaryWriter 7-bit encoding)
/// ..      4     regionCount i32
/// ..      8     totalBytes  i64, sum of region lengths
/// ..      var   regions     regionCount x { u64 address, i32 length, byte[length] }
/// </code>
///
/// <para><b>The region table is canonical:</b> strictly ascending, disjoint, and non-adjacent.
/// That is not a formality. Coalescing on load means an overlapping or unsorted file would
/// load fine and then re-serialise to different bytes, quietly breaking round-trip stability
/// and any fixture-hash-based CI check. Rejecting non-canonical input makes the byte encoding
/// a function of the content.</para>
///
/// <para>All integers little-endian: <see cref="BinaryWriter"/> is LE on every platform, and
/// the targets we inspect are x64/x86, so no byte-swap path is needed or pretended.</para>
///
/// <para>Every malformed input surfaces as <see cref="InvalidDataException"/>. Parsing hostile
/// bytes reaches end-of-stream, overflow and argument failures deep inside; leaking those
/// would force callers to catch <see cref="Exception"/>, which is how a real bug gets swallowed
/// by a fixture-loading try/catch.</para>
/// </remarks>
internal static class RecordedMemoryFormat
{
    /// <summary>"LCLRFIX" + 0x1A. The trailing EOF byte stops an accidental `type` of the file early.</summary>
    internal static ReadOnlySpan<byte> Magic =>
        new byte[] { (byte)'L', (byte)'C', (byte)'L', (byte)'R', (byte)'F', (byte)'I', (byte)'X', 0x1A };

    internal const uint CurrentVersion = 1;

    private const uint Flag64Bit = 1u << 0;
    private const uint KnownFlags = Flag64Bit;

    /// <summary>Sanity ceiling on a single region so a corrupt length cannot request a gigabyte allocation.</summary>
    private const int MaxRegionLength = 256 * 1024 * 1024;

    internal static void Write(Stream stream, RegionMap map, bool is64Bit, string description)
    {
        ArgumentNullException.ThrowIfNull(stream);

        using var w = new BinaryWriter(stream, Encoding.UTF8, leaveOpen: true);
        w.Write(Magic);
        w.Write(CurrentVersion);
        w.Write(is64Bit ? Flag64Bit : 0u);
        w.Write(description);
        w.Write(map.Count);
        w.Write(map.TotalBytes);

        // RegionMap keeps its entries canonical, so this loop emits a canonical table.
        foreach (var entry in map.Entries)
        {
            w.Write(entry.Start);
            w.Write(entry.Data.Length);
            w.Write(entry.Data.Span);
        }
    }

    internal static RecordedMemory Read(Stream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);

        try
        {
            return ReadCore(stream);
        }
        catch (InvalidDataException)
        {
            throw;
        }
        catch (Exception ex) when (ex is EndOfStreamException or IOException or ArgumentException
                                      or OverflowException or OutOfMemoryException or FormatException)
        {
            throw new InvalidDataException($"Malformed LiveClr memory fixture: {ex.Message}", ex);
        }
    }

    private static RecordedMemory ReadCore(Stream stream)
    {
        using var r = new BinaryReader(stream, Encoding.UTF8, leaveOpen: true);

        Span<byte> magic = stackalloc byte[Magic.Length];
        if (r.Read(magic) != Magic.Length || !magic.SequenceEqual(Magic))
            throw new InvalidDataException("Not a LiveClr memory fixture (bad magic).");

        uint version = r.ReadUInt32();
        if (version == 0 || version > CurrentVersion)
            throw new InvalidDataException(
                $"Fixture format version {version} is not supported by this build (max {CurrentVersion}).");

        uint flags = r.ReadUInt32();
        if ((flags & ~KnownFlags) != 0)
            throw new InvalidDataException(
                $"Fixture sets unknown header flags (0x{flags & ~KnownFlags:x}); it was written by a newer build.");

        string description = r.ReadString();
        int regionCount = r.ReadInt32();
        long totalBytes = r.ReadInt64();

        if (regionCount < 0) throw new InvalidDataException($"Negative region count ({regionCount}).");
        if (totalBytes < 0) throw new InvalidDataException($"Negative byte count ({totalBytes}).");

        var map = new RegionMap();
        long seen = 0;
        ulong previousEnd = 0;
        bool havePrevious = false;

        for (int i = 0; i < regionCount; i++)
        {
            ulong address = r.ReadUInt64();
            int length = r.ReadInt32();

            if (length <= 0 || length > MaxRegionLength)
                throw new InvalidDataException($"Region {i} has an implausible length ({length}).");
            if ((ulong)length > ulong.MaxValue - address)
                throw new InvalidDataException($"Region {i} at {address:X} wraps the end of the address space.");

            // Canonical order: strictly after the previous region, with a gap (adjacent regions
            // would have been merged by the writer).
            if (havePrevious && address <= previousEnd)
                throw new InvalidDataException(
                    $"Region {i} at {address:X} is not canonical: regions must be ascending, " +
                    $"disjoint and non-adjacent (previous ended at {previousEnd:X}).");

            var data = r.ReadBytes(length);
            if (data.Length != length)
                throw new InvalidDataException($"Fixture truncated inside region {i} at {address:X}.");

            map.Add(address, data);
            seen += length;
            previousEnd = address + (ulong)length;
            havePrevious = true;
        }

        // With a canonical table nothing can coalesce, so these three agree or the header lied.
        if (seen != totalBytes || map.TotalBytes != totalBytes || map.Count != regionCount)
            throw new InvalidDataException(
                $"Fixture header disagrees with its contents: header says {regionCount} region(s)/" +
                $"{totalBytes} byte(s), contents give {map.Count}/{map.TotalBytes}.");

        return new RecordedMemory(map, (flags & Flag64Bit) != 0, description);
    }
}
