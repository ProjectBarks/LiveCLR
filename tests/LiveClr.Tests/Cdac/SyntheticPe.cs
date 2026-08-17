namespace LiveClr.Tests.Cdac;

using System.Buffers.Binary;
using System.Text;
using LiveClr.Cdac;

/// <summary>
/// Builds a minimal but structurally honest PE image, laid out as it would be
/// <em>mapped</em> (RVA == offset from the base), so the export walk can be tested
/// without a live process.
/// </summary>
/// <remarks>
/// Two deliberate cruelties, both modelling real images:
/// <list type="bullet">
/// <item>The name-ordinal table is a <em>fixed-point-free</em> permutation, so an
/// implementation that assumes "the i-th name is the i-th function" fails for every
/// name — including when a test resolves only one. An earlier version used a stride of
/// 7 over 12 entries, which fixes every even index and left the descriptor at index 2
/// mapping to itself; a suite that only looked up the descriptor would have passed
/// against a reader that ignored the ordinal table entirely.</item>
/// <item>The ordinal base is 1, so an implementation that adds it to the name-ordinal
/// index — the classic off-by-Base bug — reads the wrong export.</item>
/// </list>
/// The buffer also ends exactly at the last export name, so resolving that name forces
/// the chunked string reader to fall back at the end of the mapped region.
/// </remarks>
internal static class SyntheticPe
{
    /// <summary>Where §12.1 found coreclr.dll mapped in the live game. Not the preferred base.</summary>
    public const ulong DefaultImageBase = 0x0000_7FFE_30DF_0000UL;

    /// <summary>§5.1 / §12.1: the descriptor export's RVA in the shipped runtime.</summary>
    public const uint DescriptorExportRva = 0x461D30;

    public const uint ExportDirectoryRva = 0x200;

    private const int NtHeaderOffset = 0x80;

    /// <summary>
    /// A twelve-name export table shaped like the shipped runtime's. Only the three
    /// names §5 documents matter; the rest are representative filler whose only job is
    /// to make the sought name not be the first entry.
    /// </summary>
    public static (string Name, uint Rva)[] CoreClrExports =>
    [
        ("DllGetActivationFactory", 0x0011_0000),
        ("DllGetClassObject", 0x0011_1000),
        ("DotNetRuntimeContractDescriptor", DescriptorExportRva),
        ("GetCLRRuntimeHost", 0x0012_0000),
        ("MetaDataGetDispenser", 0x0013_0000),
        ("coreclr_create_delegate", 0x0014_0000),
        ("coreclr_execute_assembly", 0x0014_1000),
        ("coreclr_initialize", 0x0014_2000),
        ("coreclr_shutdown", 0x0014_3000),
        ("coreclr_shutdown_2", 0x0014_4000),
        ("g_CLREngineMetrics", 0x0045_F000),
        ("g_dacTable", 0x0046_0000),
    ];

    public static byte[] BuildCoreClrLike() => Build(CoreClrExports);

    public static byte[] Build(
        IReadOnlyList<(string Name, uint Rva)> exports,
        bool pe32Plus = true,
        ushort machine = PeImage.MachineAmd64,
        uint ordinalBase = 1)
    {
        int count = exports.Count;

        uint functionsRva = ExportDirectoryRva + 40;
        uint namesRva = functionsRva + (uint)(count * 4);
        uint ordinalsRva = namesRva + (uint)(count * 4);
        uint stringsRva = ordinalsRva + (uint)(count * 2);

        var nameBytes = exports.Select(e => Encoding.ASCII.GetBytes(e.Name)).ToArray();
        int stringsLength = nameBytes.Sum(b => b.Length + 1);

        var image = new byte[stringsRva + stringsLength];
        Span<byte> span = image;

        // --- DOS header -------------------------------------------------------
        BinaryPrimitives.WriteUInt16LittleEndian(span, 0x5A4D);
        BinaryPrimitives.WriteInt32LittleEndian(span[0x3C..], NtHeaderOffset);

        // --- NT headers -------------------------------------------------------
        BinaryPrimitives.WriteUInt32LittleEndian(span[NtHeaderOffset..], 0x0000_4550);
        BinaryPrimitives.WriteUInt16LittleEndian(span[(NtHeaderOffset + 4)..], machine);
        BinaryPrimitives.WriteUInt16LittleEndian(span[(NtHeaderOffset + 20)..], (ushort)(pe32Plus ? 240 : 224));
        BinaryPrimitives.WriteUInt16LittleEndian(span[(NtHeaderOffset + 22)..], 0x2022);
        BinaryPrimitives.WriteUInt16LittleEndian(span[(NtHeaderOffset + 24)..], (ushort)(pe32Plus ? 0x20B : 0x10B));

        // SizeOfImage sits at the same optional-header offset in both formats.
        BinaryPrimitives.WriteUInt32LittleEndian(span[(NtHeaderOffset + 24 + 56)..], (uint)image.Length);

        // Export data directory: §4.3 step 4, preceded by the NumberOfRvaAndSizes that
        // says the entry exists at all.
        int exportDirEntry = NtHeaderOffset + (pe32Plus ? 0x88 : 0x78);
        BinaryPrimitives.WriteUInt32LittleEndian(span[(exportDirEntry - 4)..], 16);
        BinaryPrimitives.WriteUInt32LittleEndian(span[exportDirEntry..], ExportDirectoryRva);
        BinaryPrimitives.WriteUInt32LittleEndian(span[(exportDirEntry + 4)..], (uint)image.Length - ExportDirectoryRva);

        // --- IMAGE_EXPORT_DIRECTORY ------------------------------------------
        int dir = (int)ExportDirectoryRva;
        BinaryPrimitives.WriteUInt32LittleEndian(span[(dir + 16)..], ordinalBase);
        BinaryPrimitives.WriteUInt32LittleEndian(span[(dir + 20)..], (uint)count);
        BinaryPrimitives.WriteUInt32LittleEndian(span[(dir + 24)..], (uint)count);
        BinaryPrimitives.WriteUInt32LittleEndian(span[(dir + 28)..], functionsRva);
        BinaryPrimitives.WriteUInt32LittleEndian(span[(dir + 32)..], namesRva);
        BinaryPrimitives.WriteUInt32LittleEndian(span[(dir + 36)..], ordinalsRva);

        // --- tables -----------------------------------------------------------
        int stringCursor = (int)stringsRva;
        for (int i = 0; i < count; i++)
        {
            int functionIndex = FunctionIndexOf(i, count);

            BinaryPrimitives.WriteUInt32LittleEndian(span[((int)functionsRva + functionIndex * 4)..], exports[i].Rva);
            BinaryPrimitives.WriteUInt32LittleEndian(span[((int)namesRva + i * 4)..], (uint)stringCursor);
            BinaryPrimitives.WriteUInt16LittleEndian(span[((int)ordinalsRva + i * 2)..], (ushort)functionIndex);

            nameBytes[i].CopyTo(span[stringCursor..]);
            stringCursor += nameBytes[i].Length + 1; // the array is zero-filled, so the NUL is already there
        }

        return image;
    }

    /// <summary>
    /// A cyclic shift: still a bijection, but with no fixed point for any count above one,
    /// so no name resolves correctly by accident.
    /// </summary>
    private static int FunctionIndexOf(int nameIndex, int count) => (nameIndex + 1) % count;
}
