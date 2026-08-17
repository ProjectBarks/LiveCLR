namespace LiveClr.Metadata;

using System.Buffers.Binary;
using System.Text;

/// <summary>One entry of the metadata root's stream header list (ECMA-335 II.24.2.2).</summary>
/// <param name="Name">Stream name, e.g. <c>#~</c>, <c>#Strings</c>, <c>#US</c>, <c>#GUID</c>, <c>#Blob</c>.</param>
/// <param name="Offset">Byte offset of the stream from the start of the metadata root.</param>
/// <param name="Size">Stream length in bytes.</param>
public readonly record struct MetadataStreamHeader(string Name, int Offset, int Size);

/// <summary>
/// The validated shape of a metadata root, retained for diagnostics.
/// §12.4d recorded these live for <c>sts2.dll</c>: version <c>"v4.0.30319"</c>, 5 streams,
/// <c>#~</c> 3,031,628 / <c>#Strings</c> 577,064 / <c>#US</c> 621,000 / <c>#GUID</c> 16 /
/// <c>#Blob</c> 738,108 — so a failure here is comparable against a known-good reading.
/// </summary>
public sealed class MetadataRootInfo
{
    internal MetadataRootInfo(
        ushort majorVersion,
        ushort minorVersion,
        string versionString,
        ushort flags,
        IReadOnlyList<MetadataStreamHeader> streams)
    {
        MajorVersion = majorVersion;
        MinorVersion = minorVersion;
        VersionString = versionString;
        Flags = flags;
        Streams = streams;
    }

    public ushort MajorVersion { get; }
    public ushort MinorVersion { get; }

    /// <summary>The runtime version string, e.g. <c>"v4.0.30319"</c>.</summary>
    public string VersionString { get; }

    public ushort Flags { get; }
    public IReadOnlyList<MetadataStreamHeader> Streams { get; }

    public bool HasStream(string name)
    {
        foreach (var s in Streams)
        {
            if (string.Equals(s.Name, name, StringComparison.Ordinal)) return true;
        }

        return false;
    }
}

/// <summary>
/// Bounds-checks a metadata blob BEFORE it reaches <c>MetadataReader</c>.
/// </summary>
/// <remarks>
/// <para>
/// This exists because of an explicit warning in the <c>System.Reflection.Metadata</c>
/// documentation: the reader is <em>not</em> hardened against untrusted input. Our input is
/// bytes copied out of another process at an address derived from a chain of pointer
/// dereferences (§12.4d). Any link in that chain can be stale or garbage — §7b.1 and §12.4e
/// both document failure modes where every read succeeds and the data is still wrong — so the
/// blob must be treated as hostile until its self-describing offsets are proven in range.
/// </para>
/// <para>
/// Validation is deliberately structural only: signature, version block, and the invariant
/// that every stream lies wholly inside the blob. Table-level parsing stays the library's job
/// (§8.1: never hand-roll ECMA-335).
/// </para>
/// <para>
/// <b>What this deliberately does NOT check</b>, so it is not re-litigated: overlapping streams
/// and duplicate stream names both pass. Neither can read outside the buffer — the only
/// property this gate exists to guarantee — and rejecting them would refuse images that
/// obfuscators and some legitimate producers emit. Nor does it inspect table CONTENTS: row
/// indices, heap handles, and the <c>NestedClass</c> graph all reach
/// <see cref="TypeResolver"/> unvalidated, which is why that class treats them as hostile.
/// </para>
/// </remarks>
public static class MetadataBlobValidator
{
    /// <summary>'BSJB' as a little-endian uint (ECMA-335 II.24.2.1).</summary>
    private const uint BsjbSignature = 0x424A_5342;

    /// <summary>ECMA-335 caps the version string at 255 bytes; the field is padded to 4.</summary>
    private const int MaxVersionStringLength = 256;

    /// <summary>No real image has anywhere near this many streams; a garbage blob might claim to.</summary>
    private const int MaxStreams = 64;

    /// <summary>Stream names are short ASCII; cap the scan so a missing NUL cannot run away.</summary>
    private const int MaxStreamNameLength = 32;

    /// <summary>
    /// Returns true only if <paramref name="blob"/> is a self-consistent metadata root whose
    /// streams all lie within it. On false, <paramref name="error"/> names the specific
    /// violation — worth surfacing, since "wrong module base" and "torn read" look identical
    /// from the caller's side without it.
    /// </summary>
    public static bool TryValidate(
        ReadOnlySpan<byte> blob,
        out MetadataRootInfo? info,
        out string? error)
    {
        info = null;

        if (blob.Length < 20)
        {
            error = $"blob is {blob.Length} bytes; a metadata root header needs at least 20";
            return false;
        }

        if (BinaryPrimitives.ReadUInt32LittleEndian(blob) != BsjbSignature)
        {
            error = "missing 'BSJB' metadata root signature";
            return false;
        }

        ushort majorVersion = BinaryPrimitives.ReadUInt16LittleEndian(blob[4..]);
        ushort minorVersion = BinaryPrimitives.ReadUInt16LittleEndian(blob[6..]);
        // blob[8..12] is Reserved and must be ignored, not validated — some producers vary.

        int versionLength = BinaryPrimitives.ReadInt32LittleEndian(blob[12..]);
        if (versionLength <= 0 || versionLength > MaxVersionStringLength || (versionLength % 4) != 0)
        {
            error = $"version string length {versionLength} is not a positive multiple of 4 within range";
            return false;
        }

        // 16 bytes of fixed header + version + Flags(2) + Streams(2).
        if (blob.Length < 16 + versionLength + 4)
        {
            error = $"blob is truncated before the stream count (needs {16 + versionLength + 4} bytes)";
            return false;
        }

        ReadOnlySpan<byte> versionBytes = blob.Slice(16, versionLength);
        int nul = versionBytes.IndexOf((byte)0);
        string versionString = Encoding.UTF8.GetString(nul < 0 ? versionBytes : versionBytes[..nul]);

        int cursor = 16 + versionLength;
        ushort flags = BinaryPrimitives.ReadUInt16LittleEndian(blob[cursor..]);
        int streamCount = BinaryPrimitives.ReadUInt16LittleEndian(blob[(cursor + 2)..]);
        cursor += 4;

        if (streamCount is <= 0 or > MaxStreams)
        {
            error = $"implausible stream count {streamCount}";
            return false;
        }

        var streams = new MetadataStreamHeader[streamCount];
        for (int i = 0; i < streamCount; i++)
        {
            if (cursor + 8 > blob.Length)
            {
                error = $"stream header {i} runs past the end of the blob";
                return false;
            }

            uint offset = BinaryPrimitives.ReadUInt32LittleEndian(blob[cursor..]);
            uint size = BinaryPrimitives.ReadUInt32LittleEndian(blob[(cursor + 4)..]);
            cursor += 8;

            // The whole point of this class: offset+size must lie inside the buffer we own.
            // Widened to ulong so a hostile pair cannot wrap into a "valid" range.
            if ((ulong)offset + size > (ulong)blob.Length)
            {
                error =
                    $"stream {i} spans [{offset}, {(ulong)offset + size}) which is outside the " +
                    $"{blob.Length}-byte blob";
                return false;
            }

            int nameStart = cursor;
            int nameEnd = -1;
            int limit = Math.Min(blob.Length, nameStart + MaxStreamNameLength);
            for (int p = nameStart; p < limit; p++)
            {
                if (blob[p] == 0) { nameEnd = p; break; }
            }

            if (nameEnd < 0)
            {
                error = $"stream header {i} has an unterminated name";
                return false;
            }

            string name = Encoding.ASCII.GetString(blob[nameStart..nameEnd]);
            if (name.Length == 0)
            {
                error = $"stream header {i} has an empty name";
                return false;
            }

            // II.24.2.2: the name is padded to the next 4-byte boundary relative to the
            // start of the metadata root, which is index 0 of this blob.
            // Rounding up must not overflow into a negative cursor, which would slip both
            // bounds checks below and throw out of a Try* method. Unreachable while the
            // 256 MB size cap holds, but this is a public entry point on a security gate and
            // must not depend on a caller-side invariant.
            int paddedEnd = nameEnd + 1;
            if (paddedEnd > int.MaxValue - 3)
            {
                error = $"stream header {i} name length overflows";
                return false;
            }

            cursor = (paddedEnd + 3) & ~3;
            if (cursor > blob.Length)
            {
                error = $"stream header {i} padding runs past the end of the blob";
                return false;
            }

            streams[i] = new MetadataStreamHeader(name, (int)offset, (int)size);
        }

        // Without a table stream there is nothing for MetadataReader to read; treat its
        // absence as corruption rather than letting the library raise BadImageFormatException.
        bool hasTables = false;
        foreach (var s in streams)
        {
            if (s.Name is "#~" or "#-") { hasTables = true; break; }
        }

        if (!hasTables)
        {
            error = "no '#~' or '#-' metadata table stream";
            return false;
        }

        info = new MetadataRootInfo(majorVersion, minorVersion, versionString, flags, streams);
        error = null;
        return true;
    }
}
