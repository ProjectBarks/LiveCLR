namespace LiveClr.Tests.Metadata;

using System.Buffers.Binary;
using LiveClr.Memory;

/// <summary>
/// An on-disk assembly laid out the way the Windows loader would map it, so that
/// <c>RVA == offset from base</c> — the assumption the production PE walk makes about
/// <c>Module.Base</c> (analysis doc §5.2 / §12.4d).
/// </summary>
/// <remarks>
/// Mapping is the whole point of this helper. Reading the raw file would silently exercise a
/// DIFFERENT address model (file offsets), so a test built on the raw bytes could pass while
/// the live walk was broken.
/// </remarks>
internal sealed class MappedPeImage
{
    private MappedPeImage(byte[] image, int cliDirectoryOffset)
    {
        Image = image;
        CliDirectoryOffset = cliDirectoryOffset;
    }

    /// <summary>The image bytes, indexed by RVA.</summary>
    public byte[] Image { get; }

    /// <summary>Offset of data directory 14 within <see cref="Image"/>, for corruption tests.</summary>
    public int CliDirectoryOffset { get; }

    /// <summary>An arbitrary, ASLR-looking base so tests never accidentally depend on base 0.</summary>
    public const ulong BaseAddress = 0x0000_01A9_0220_0000;

    public IMemoryReader CreateReader() => new FakeImageMemoryReader(Image, BaseAddress);

    public static MappedPeImage FromFile(string path) => FromBytes(File.ReadAllBytes(path));

    public static MappedPeImage FromBytes(byte[] file)
    {
        int lfanew = BinaryPrimitives.ReadInt32LittleEndian(file.AsSpan(0x3C));
        int coff = lfanew + 4;
        int sectionCount = BinaryPrimitives.ReadUInt16LittleEndian(file.AsSpan(coff + 2));
        int sizeOfOptionalHeader = BinaryPrimitives.ReadUInt16LittleEndian(file.AsSpan(coff + 16));
        int optional = coff + 20;

        ushort magic = BinaryPrimitives.ReadUInt16LittleEndian(file.AsSpan(optional));
        // SizeOfImage(56) and SizeOfHeaders(60) sit at the same optional-header offsets in
        // PE32 and PE32+: the widened ImageBase exactly replaces BaseOfData.
        int sizeOfImage = BinaryPrimitives.ReadInt32LittleEndian(file.AsSpan(optional + 56));
        int sizeOfHeaders = BinaryPrimitives.ReadInt32LittleEndian(file.AsSpan(optional + 60));
        int dataDirectories = magic == 0x20B ? 112 : 96;

        var image = new byte[sizeOfImage];
        file.AsSpan(0, Math.Min(sizeOfHeaders, file.Length)).CopyTo(image);

        int sectionTable = optional + sizeOfOptionalHeader;
        for (int i = 0; i < sectionCount; i++)
        {
            int header = sectionTable + (i * 40);
            int virtualAddress = BinaryPrimitives.ReadInt32LittleEndian(file.AsSpan(header + 12));
            int sizeOfRawData = BinaryPrimitives.ReadInt32LittleEndian(file.AsSpan(header + 16));
            int pointerToRawData = BinaryPrimitives.ReadInt32LittleEndian(file.AsSpan(header + 20));

            if (sizeOfRawData == 0 || pointerToRawData == 0) continue;

            int copy = Math.Min(sizeOfRawData, file.Length - pointerToRawData);
            copy = Math.Min(copy, image.Length - virtualAddress);
            if (copy <= 0) continue;

            file.AsSpan(pointerToRawData, copy).CopyTo(image.AsSpan(virtualAddress));
        }

        return new MappedPeImage(image, optional + dataDirectories + (14 * 8));
    }
}

/// <summary>
/// <see cref="IMemoryReader"/> over a byte array pretending to be a target address space.
/// Fails any read that is not wholly in range, matching the interface contract that a partial
/// read is reported as failure (§4.8).
/// </summary>
internal sealed class FakeImageMemoryReader : IMemoryReader
{
    private readonly byte[] _image;
    private readonly ulong _base;

    /// <summary>Reads larger than this fail, forcing the chunked fallback path. 0 = no limit.</summary>
    public int MaxSingleRead { get; set; }

    /// <summary>Number of successful <see cref="TryRead"/> calls, to assert bulk-copy behaviour.</summary>
    public int ReadCount { get; private set; }

    public FakeImageMemoryReader(byte[] image, ulong baseAddress)
    {
        _image = image;
        _base = baseAddress;
    }

    public bool Is64Bit => true;

    public bool TryRead(ulong address, Span<byte> buffer)
    {
        if (MaxSingleRead > 0 && buffer.Length > MaxSingleRead) return false;
        if (address < _base) return false;

        ulong offset = address - _base;
        if (offset + (ulong)buffer.Length > (ulong)_image.Length) return false;

        _image.AsSpan((int)offset, buffer.Length).CopyTo(buffer);
        ReadCount++;
        return true;
    }

    public void Dispose() { }
}
