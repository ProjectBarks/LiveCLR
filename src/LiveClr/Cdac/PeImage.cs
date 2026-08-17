namespace LiveClr.Cdac;

using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using LiveClr.Memory;
using LiveClr.Pe;

/// <summary>
/// Parses a PE image's export table <em>out of a remote address space</em>, through
/// <see cref="IMemoryReader"/> only.
/// </summary>
/// <remarks>
/// <para>
/// This is the analysis doc §4.3 algorithm. Steps 1-4 — <c>MZ</c>, <c>e_lfanew</c>,
/// <c>PE\0\0</c>, the machine field, the optional-header magic and the export data
/// directory — are <see cref="PeHeaders"/>, shared with the §12.4d metadata route so the
/// two cannot drift apart again. What remains here is step 5, the export name/ordinal/
/// address walk, which nothing else needs.
/// </para>
/// <para>
/// Because the image is <em>mapped</em>, every RVA is simply <c>ImageBase + rva</c>; see
/// <see cref="PeHeaders"/> for why there is no section-table walk and why ASLR needs no
/// handling.
/// </para>
/// <para>Little-endian targets only (x86/x64), which is all §6.1 scopes us to.</para>
/// </remarks>
public sealed class PeImage
{
    /// <summary>x64. §4.3 step 3.</summary>
    public const ushort MachineAmd64 = PeHeaders.MachineAmd64;

    /// <summary>x86. §4.3 step 3.</summary>
    public const ushort MachineI386 = PeHeaders.MachineI386;

    /// <summary>Data directory 0. §4.3 step 4.</summary>
    private const int ExportDirectoryIndex = 0;

    /// <summary><c>IMAGE_EXPORT_DIRECTORY</c> is 40 bytes; a smaller declared size is malformed.</summary>
    private const uint MinExportDirectorySize = 40;

    // Guards against allocating from a corrupt/mismatched export directory. coreclr.dll
    // exports 12 names (§5); kernel32 is under 2000.
    private const int MaxExportNames = 1 << 16;

    private const int MaxExportNameLength = 512;
    private const int NameReadChunk = 64;

    private readonly IMemoryReader _reader;
    private readonly PeHeaders _headers;

    private PeImage(
        IMemoryReader reader,
        PeHeaders headers,
        uint exportDirectoryRva,
        uint exportDirectorySize)
    {
        _reader = reader;
        _headers = headers;
        ExportDirectoryRva = exportDirectoryRva;
        ExportDirectorySize = exportDirectorySize;
    }

    /// <summary>Address the module is mapped at in the target. Not the preferred base.</summary>
    public ulong ImageBase => _headers.ImageBase;

    /// <summary>COFF machine field: <see cref="MachineAmd64"/> or <see cref="MachineI386"/>.</summary>
    public ushort Machine => _headers.Machine;

    /// <summary>True for PE32+ (optional header magic <c>0x20B</c>).</summary>
    public bool IsPe32Plus => _headers.IsPe32Plus;

    /// <summary>
    /// Total mapped size of the module. Every RVA is bounds-checked against it: in a live
    /// process the pages next to a module are frequently mapped by something else, so an
    /// unchecked RVA reads plausible bytes from a neighbouring allocation rather than
    /// failing (§4.3).
    /// </summary>
    public uint SizeOfImage => _headers.SizeOfImage;

    /// <summary>RVA of <c>IMAGE_EXPORT_DIRECTORY</c>; zero when the module exports nothing.</summary>
    public uint ExportDirectoryRva { get; }

    /// <summary>Size of the export data directory. Only used to detect forwarders.</summary>
    public uint ExportDirectorySize { get; }

    /// <summary>True if the machine field says 64-bit.</summary>
    public bool Is64Bit => _headers.Is64Bit;

    /// <summary>
    /// Validate and parse the headers of the module mapped at <paramref name="imageBase"/>.
    /// Returns false rather than throwing for anything unrecognisable — the caller is
    /// typically probing module bases and a wrong guess must be cheap.
    /// </summary>
    public static bool TryLoad(IMemoryReader reader, ulong imageBase, [NotNullWhen(true)] out PeImage? image)
    {
        ArgumentNullException.ThrowIfNull(reader);
        image = null;

        // §4.3 steps 1-2 and 4's prerequisites.
        if (!PeHeaders.TryParse(reader, imageBase, out PeHeaders? headers, out _, out _)) return false;

        // §4.3 step 3. Unlike the metadata route, this one dereferences pointers read out
        // of the image, so an architecture whose pointer width we have not reasoned about
        // is not a target we can walk.
        if (!PeHeaders.IsSupportedMachine(headers.Machine)) return false;

        uint exportRva = 0;
        uint exportSize = 0;

        // §4.3 step 4. Zero directories is legal and means exactly what it says: there is
        // no export entry to read. Same for an optional header that stops before entry 0.
        switch (headers.TryReadDataDirectory(ExportDirectoryIndex, out uint rva, out uint size))
        {
            case PeDirectoryResult.Present:
                // A live RVA with a zero or out-of-range size is malformed. Demoting it to
                // "no exports" matters because IsForwarderRva is derived from that size:
                // left as-is it would silently answer false for every RVA, disabling the
                // forwarder guard on precisely the images where it is needed.
                if (size >= MinExportDirectorySize && headers.IsRvaRangeInImage(rva, size))
                {
                    exportRva = rva;
                    exportSize = size;
                }

                break;

            case PeDirectoryResult.Unreadable:
                return false;
        }

        image = new PeImage(reader, headers, exportRva, exportSize);
        return true;
    }

    /// <summary>
    /// §4.3 step 5: resolve an export by name to its RVA, walking the target's own name,
    /// ordinal and address tables. Add <see cref="ImageBase"/> for a usable address.
    /// </summary>
    /// <remarks>
    /// The name table is sorted, so a binary search is possible; it is not worth it here.
    /// The one call site that matters resolves a single symbol from a 12-entry table
    /// once per attach, and a linear walk over two bulk-read arrays has no failure mode
    /// that depends on the table actually being sorted.
    /// </remarks>
    public bool TryFindExport(string name, out ulong rva)
    {
        ArgumentNullException.ThrowIfNull(name);
        rva = 0;

        if (!TryReadExportTable(out ExportTable table)) return false;
        if (!TryReadNameTables(table, out byte[]? nameRvas, out byte[]? nameOrdinals)) return false;

        for (int i = 0; i < table.NameCount; i++)
        {
            uint nameRva = BinaryPrimitives.ReadUInt32LittleEndian(nameRvas.AsSpan(i * 4));
            if (!IsRvaRangeInImage(nameRva, 1)) continue;
            if (!TryReadUtf8String(ImageBase + nameRva, out string? candidate)) continue;
            if (!string.Equals(candidate, name, StringComparison.Ordinal)) continue;

            // AddressOfNameOrdinals holds unbiased indices into AddressOfFunctions.
            // OrdinalBase applies to *ordinal* lookups only; adding it here is a
            // well-known off-by-Base bug.
            ushort index = BinaryPrimitives.ReadUInt16LittleEndian(nameOrdinals.AsSpan(i * 2));
            if (index >= table.FunctionCount) return false;

            if (!_reader.TryRead(ImageBase + table.FunctionsRva + (uint)index * 4u, out uint functionRva)) return false;
            if (functionRva == 0) return false;

            rva = functionRva;
            return true;
        }

        return false;
    }

    /// <summary>
    /// Every export name this image could be read for, in table order.
    /// </summary>
    /// <remarks>
    /// <b>The list can be SHORTER than the table declares</b>, because an entry whose name RVA
    /// leaves the image, or whose string cannot be read, is skipped rather than invented. Use
    /// <see cref="GetExportNames(out int)"/> when the count matters: §12.1's "12 names" line is
    /// only confirmation that the walk landed on a real table if the two agree, and this
    /// overload cannot tell you whether they do. That is exactly how it went wrong — the doc
    /// here sold <c>Count</c> as that confirmation while the loop shrank it without counting,
    /// so a module that dropped one name looked like a module that exports one thing fewer
    /// (§13.11).
    /// </remarks>
    public IReadOnlyList<string> GetExportNames() => GetExportNames(out _);

    /// <summary>
    /// Every export name that could be read, together with the number the export directory
    /// DECLARED. They differ when an entry was unreadable; equality is the confirmation.
    /// </summary>
    /// <param name="declaredCount">
    /// <c>NumberOfNames</c> from <c>IMAGE_EXPORT_DIRECTORY</c>, or 0 when no export table could
    /// be read at all — in which case the returned list is empty too, and the two still agree.
    /// </param>
    public IReadOnlyList<string> GetExportNames(out int declaredCount)
    {
        declaredCount = 0;
        if (!TryReadExportTable(out ExportTable table)) return [];
        if (!TryReadNameTables(table, out byte[]? nameRvas, out _)) return [];

        declaredCount = (int)table.NameCount;

        var names = new List<string>(declaredCount);
        for (int i = 0; i < table.NameCount; i++)
        {
            uint nameRva = BinaryPrimitives.ReadUInt32LittleEndian(nameRvas.AsSpan(i * 4));
            if (!IsRvaRangeInImage(nameRva, 1)) continue;
            if (TryReadUtf8String(ImageBase + nameRva, out string? candidate)) names.Add(candidate);
        }

        return names;
    }

    /// <summary>
    /// True if an export RVA points back inside the export directory, which by PE
    /// convention means it is a forwarder string (<c>"OTHERDLL.Symbol"</c>) rather than
    /// code or data. <c>DotNetRuntimeContractDescriptor</c> is real data, so this only
    /// exists so a caller can tell "found something useless" from "found the descriptor".
    /// <para>
    /// The zero-size test is not a silent opt-out: <see cref="TryLoad"/> demotes a
    /// malformed directory to "no exports", so a zero size here implies no export could
    /// have been resolved in the first place.
    /// </para>
    /// </summary>
    public bool IsForwarderRva(ulong rva) =>
        ExportDirectorySize != 0 &&
        rva >= ExportDirectoryRva &&
        rva < (ulong)ExportDirectoryRva + ExportDirectorySize;

    private bool TryReadExportTable(out ExportTable table)
    {
        table = default;
        if (ExportDirectoryRva == 0) return false;

        ulong dir = ImageBase + ExportDirectoryRva;

        // IMAGE_EXPORT_DIRECTORY: Base +16, NumberOfFunctions +20, NumberOfNames +24,
        // AddressOfFunctions +28, AddressOfNames +32, AddressOfNameOrdinals +36.
        Span<byte> raw = stackalloc byte[40];
        if (!_reader.TryRead(dir, raw)) return false;

        uint nameCount = BinaryPrimitives.ReadUInt32LittleEndian(raw[24..]);
        if (nameCount == 0 || nameCount > MaxExportNames) return false;

        table = new ExportTable(
            OrdinalBase: BinaryPrimitives.ReadUInt32LittleEndian(raw[16..]),
            FunctionCount: BinaryPrimitives.ReadUInt32LittleEndian(raw[20..]),
            NameCount: nameCount,
            FunctionsRva: BinaryPrimitives.ReadUInt32LittleEndian(raw[28..]),
            NamesRva: BinaryPrimitives.ReadUInt32LittleEndian(raw[32..]),
            NameOrdinalsRva: BinaryPrimitives.ReadUInt32LittleEndian(raw[36..]));

        // Every table must lie inside the module. Without this, a corrupt directory reads
        // a neighbouring allocation and returns names that look entirely real.
        return IsRvaRangeInImage(table.FunctionsRva, (ulong)table.FunctionCount * 4) &&
               IsRvaRangeInImage(table.NamesRva, (ulong)table.NameCount * 4) &&
               IsRvaRangeInImage(table.NameOrdinalsRva, (ulong)table.NameCount * 2);
    }

    /// <summary>True if <c>[rva, rva + size)</c> lies inside the mapped module.</summary>
    private bool IsRvaRangeInImage(uint rva, ulong size) => _headers.IsRvaRangeInImage(rva, size);

    // Both tables come back in one read each rather than four bytes at a time: the
    // §4.1 bulk-read argument applies to any array we walk, not just strings.
    private bool TryReadNameTables(
        ExportTable table,
        [NotNullWhen(true)] out byte[]? nameRvas,
        [NotNullWhen(true)] out byte[]? nameOrdinals)
    {
        nameRvas = null;
        nameOrdinals = null;

        int count = (int)table.NameCount;
        var rvas = new byte[count * 4];
        if (!_reader.TryRead(ImageBase + table.NamesRva, rvas)) return false;

        var ordinals = new byte[count * 2];
        if (!_reader.TryRead(ImageBase + table.NameOrdinalsRva, ordinals)) return false;

        nameRvas = rvas;
        nameOrdinals = ordinals;
        return true;
    }

    private bool TryReadUtf8String(ulong address, [NotNullWhen(true)] out string? value)
    {
        value = null;
        Span<byte> buffer = stackalloc byte[MaxExportNameLength];
        int filled = 0;

        while (filled < MaxExportNameLength)
        {
            int want = Math.Min(NameReadChunk, MaxExportNameLength - filled);
            Span<byte> slice = buffer.Slice(filled, want);

            if (!_reader.TryRead(address + (ulong)filled, slice))
            {
                // A chunked read can run off the end of a mapped section even though the
                // string itself is fine. Narrow to one byte before concluding failure.
                if (want == 1) return false;
                want = 1;
                slice = buffer.Slice(filled, 1);
                if (!_reader.TryRead(address + (ulong)filled, slice)) return false;
            }

            int terminator = slice.IndexOf((byte)0);
            if (terminator >= 0)
            {
                value = Encoding.UTF8.GetString(buffer[..(filled + terminator)]);
                return true;
            }

            filled += want;
        }

        return false;
    }

    /// <summary>Decoded <c>IMAGE_EXPORT_DIRECTORY</c> fields we actually use.</summary>
    private readonly record struct ExportTable(
        uint OrdinalBase,
        uint FunctionCount,
        uint NameCount,
        uint FunctionsRva,
        uint NamesRva,
        uint NameOrdinalsRva);
}
