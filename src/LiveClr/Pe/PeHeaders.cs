namespace LiveClr.Pe;

using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using LiveClr.Memory;

/// <summary>Why <see cref="PeHeaders.TryParse"/> refused an image.</summary>
/// <remarks>
/// Callers need the distinction because they report failure differently: the §4.3 export
/// walk collapses everything to <see langword="false"/> (it is probing module bases and a
/// wrong guess must be cheap), while the §12.4d metadata route has to tell "not a PE" from
/// "a perfectly ordinary native DLL" — see <c>ModuleMetadataStatus</c>.
/// </remarks>
internal enum PeHeaderError
{
    /// <summary>Headers parsed.</summary>
    None,

    /// <summary>A header read failed outright: unmapped, paged out, or a stale base.</summary>
    Unreadable,

    /// <summary>No <c>MZ</c>, no <c>PE\0\0</c>, an absurd <c>e_lfanew</c>, or an unknown optional-header magic.</summary>
    NotAPeImage,

    /// <summary>
    /// <c>SizeOfOptionalHeader</c> stops before the data directory table even begins, so
    /// no directory entry exists at any index. Kept separate from
    /// <see cref="MalformedHeader"/> because it is indistinguishable, from the caller's
    /// point of view, from an image that simply declares no directories.
    /// </summary>
    OptionalHeaderTooSmall,

    /// <summary>The header is self-inconsistent: zero <c>SizeOfImage</c>, or more directories than the format allows.</summary>
    MalformedHeader,
}

/// <summary>Outcome of a <see cref="PeHeaders.TryReadDataDirectory"/> lookup.</summary>
/// <remarks>
/// Three states, not two. "The image declares no entry at this index" is legal and ordinary
/// (a native DLL has no CLI directory; a resource-only DLL has no exports), whereas "the
/// entry should be there and could not be read" means the base is wrong. Collapsing them
/// would make a stale <c>Module.Base</c> look like a native module — the silent failure
/// §12.4e warns about.
/// </remarks>
internal enum PeDirectoryResult
{
    /// <summary>The entry exists and was read.</summary>
    Present,

    /// <summary>The image declares no directory at this index. Not an error.</summary>
    Absent,

    /// <summary>The entry should exist but the read failed.</summary>
    Unreadable,
}

/// <summary>
/// The PE header walk shared by every consumer in this library, performed <em>out of a
/// remote address space</em> through <see cref="IMemoryReader"/> alone.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why this type exists.</b> Analysis doc §4.3 (remote export resolution) and §12.4d
/// (the ECMA-335 metadata route) both begin with the identical walk — <c>MZ</c> →
/// <c>e_lfanew</c> → <c>PE\0\0</c> → optional-header magic → a data directory entry. It was
/// written twice, and the two copies drifted: one grew <c>SizeOfImage</c>,
/// <c>NumberOfRvaAndSizes</c> and <c>SizeOfOptionalHeader</c> validation that the other
/// never received. A header parser fed hostile input from a live process is exactly the
/// wrong thing to maintain in duplicate, so it lives here once and both routes are built on
/// it. Only the walk is shared: the export table stays in <c>LiveClr.Cdac</c> and the CLI
/// header stays in <c>LiveClr.Metadata</c>.
/// </para>
/// <para>
/// <b>Why not <c>System.Reflection.PortableExecutable</c>.</b> §8.1: the BCL reader wants a
/// <see cref="System.IO.Stream"/> over a file, and we have a module already mapped into
/// another process. Opening a local copy of the DLL would resolve RVAs but is a lie twice
/// over — it can disagree with what the target actually mapped (hotpatched or side-loaded
/// images), and it makes a read-only inspection tool open and map the target's binaries.
/// </para>
/// <para>
/// <b>KEY ASSUMPTION: the image is loader-mapped</b> (<c>SEC_IMAGE</c>), so an RVA is just
/// <c>ImageBase + rva</c>. There is no section-table walk here and there must not be:
/// RVA→file-offset translation applies to on-disk images only, and applying it to a mapped
/// image is the classic way to read plausible garbage. ASLR is handled for free — nothing
/// assumes the preferred image base (§12.1: static base <c>0x180000000</c>, live base
/// <c>0x7FFE30DF0000</c>, every recovered RVA still matched).
/// </para>
/// <para>
/// <b>Everything read here is attacker-influenced.</b> Every field below is a number the
/// target's own memory supplied, and in a live process the pages next to a module are
/// frequently mapped by something else — so an unchecked RVA reads plausible bytes from a
/// neighbouring allocation rather than failing (§4.8, §6.4). Hence
/// <see cref="IsRvaRangeInImage"/> and the bounds checks in <see cref="TryParse"/>.
/// </para>
/// <para>Little-endian targets only (x86/x64), which is all §6.1 scopes us to.</para>
/// </remarks>
internal sealed class PeHeaders
{
    private const ushort DosSignature = 0x5A4D;      // "MZ"
    private const uint NtSignature = 0x0000_4550;    // "PE\0\0"
    private const ushort OptionalMagicPe32 = 0x010B;
    private const ushort OptionalMagicPe32Plus = 0x020B;

    /// <summary>x64. §4.3 step 3.</summary>
    internal const ushort MachineAmd64 = 0x8664;

    /// <summary>x86. §4.3 step 3.</summary>
    internal const ushort MachineI386 = 0x014C;

    /// <summary>The COFF header follows the 4-byte PE signature; the optional header follows that.</summary>
    private const uint OptionalHeaderOffset = 24;

    /// <summary><c>SizeOfOptionalHeader</c>, measured from the PE signature.</summary>
    private const int SizeOfOptionalHeaderOffset = 20;

    /// <summary><c>SizeOfImage</c> sits at the same optional-header offset in both formats.</summary>
    private const uint SizeOfImageOffset = 56;

    /// <summary>
    /// Data directory 0 measured from the start of the optional header. Adding
    /// <see cref="OptionalHeaderOffset"/> gives §4.3 step 4's <c>+0x78</c> / <c>+0x88</c>
    /// from the PE signature; the two differ by the 8 bytes PE32+ spends widening
    /// <c>ImageBase</c> in place of PE32's separate <c>BaseOfData</c>.
    /// </summary>
    private const uint DirectoryTableOffsetPe32 = 96;

    private const uint DirectoryTableOffsetPe32Plus = 112;

    /// <summary>The PE specification caps the data directory at 16 entries.</summary>
    private const uint MaxDataDirectories = 16;

    /// <summary>Each <c>IMAGE_DATA_DIRECTORY</c> is a VirtualAddress/Size pair.</summary>
    private const uint DataDirectoryEntrySize = 8;

    /// <summary>
    /// The NT headers live in the first page of every sane image. A bogus base address
    /// usually surfaces as an absurd <c>e_lfanew</c>, so bounding it turns "read a random
    /// address and interpret it" into a clean rejection.
    /// </summary>
    private const int MaxNtHeaderOffset = 0x1000;

    private readonly IMemoryReader _reader;

    private PeHeaders(
        IMemoryReader reader,
        ulong imageBase,
        ulong optionalHeader,
        ushort machine,
        bool isPe32Plus,
        ushort sizeOfOptionalHeader,
        uint sizeOfImage,
        uint numberOfRvaAndSizes)
    {
        _reader = reader;
        ImageBase = imageBase;
        OptionalHeaderAddress = optionalHeader;
        Machine = machine;
        IsPe32Plus = isPe32Plus;
        SizeOfOptionalHeader = sizeOfOptionalHeader;
        SizeOfImage = sizeOfImage;
        NumberOfRvaAndSizes = numberOfRvaAndSizes;
    }

    /// <summary>Address the module is mapped at in the target. Not the preferred base.</summary>
    internal ulong ImageBase { get; }

    /// <summary>Absolute address of <c>IMAGE_OPTIONAL_HEADER</c> in the target.</summary>
    internal ulong OptionalHeaderAddress { get; }

    /// <summary>
    /// COFF machine field, as read. Deliberately <em>not</em> validated here — see
    /// <see cref="IsSupportedMachine"/> for who applies the §4.3 step 3 restriction and why
    /// it is a caller's decision rather than a statement about header validity.
    /// </summary>
    internal ushort Machine { get; }

    /// <summary>True for PE32+ (optional header magic <c>0x20B</c>).</summary>
    internal bool IsPe32Plus { get; }

    /// <summary>
    /// The header's own statement of how far it extends. Checked against every directory
    /// entry before that entry is read: <see cref="NumberOfRvaAndSizes"/> alone is not
    /// enough, because it is just a field and a stale or garbage image can claim 16 entries
    /// in a header far too small to hold them.
    /// </summary>
    internal ushort SizeOfOptionalHeader { get; }

    /// <summary>
    /// Total mapped size of the module, and the only bound any RVA can be checked against.
    /// Guaranteed non-zero: without it <see cref="IsRvaRangeInImage"/> would accept
    /// everything.
    /// </summary>
    internal uint SizeOfImage { get; }

    /// <summary>Number of data directory entries the image declares. At most 16.</summary>
    internal uint NumberOfRvaAndSizes { get; }

    /// <summary>Offset of data directory 0 from <see cref="OptionalHeaderAddress"/>: 96 (PE32) or 112 (PE32+).</summary>
    internal uint DirectoryTableOffset => IsPe32Plus ? DirectoryTableOffsetPe32Plus : DirectoryTableOffsetPe32;

    /// <summary>True if the machine field says 64-bit.</summary>
    internal bool Is64Bit => Machine == MachineAmd64;

    /// <summary>
    /// §4.3 step 3: x64 or x86. This is a restriction on what a caller may safely
    /// <em>dereference out of</em> the image, not on whether the headers parsed — pointer
    /// width and the little-endian field reads follow from it (§6.1). A route that only
    /// reads RVAs and byte blobs, such as the §12.4d metadata walk, has no such dependency
    /// and must not reject an image over it.
    /// </summary>
    internal static bool IsSupportedMachine(ushort machine) =>
        machine is MachineAmd64 or MachineI386;

    /// <summary>
    /// Validate and parse the headers of the module mapped at <paramref name="imageBase"/>.
    /// Never throws: the caller is typically probing addresses, and a wrong guess must be
    /// cheap rather than exceptional.
    /// </summary>
    /// <param name="reader">Reader for the target address space.</param>
    /// <param name="imageBase">Base address the module is mapped at.</param>
    /// <param name="headers">Parsed headers on success.</param>
    /// <param name="error">Why the parse failed; <see cref="PeHeaderError.None"/> on success.</param>
    /// <param name="detail">Human-readable explanation on failure, <see langword="null"/> on success.</param>
    internal static bool TryParse(
        IMemoryReader reader,
        ulong imageBase,
        [NotNullWhen(true)] out PeHeaders? headers,
        out PeHeaderError error,
        out string? detail)
    {
        ArgumentNullException.ThrowIfNull(reader);

        headers = null;

        // §4.3 steps 1-2. The DOS header is read whole so that the MZ check and e_lfanew
        // cost one round trip: a failed probe must give up after a single read, not after
        // speculatively chasing header fields.
        Span<byte> dos = stackalloc byte[0x40];
        if (!reader.TryRead(imageBase, dos))
        {
            return Fail(PeHeaderError.Unreadable, $"could not read DOS header at 0x{imageBase:X}", out error, out detail);
        }

        // Not in §4.3, but a two-byte check that rejects a wrong module base before we
        // start dereferencing values read out of it.
        if (BinaryPrimitives.ReadUInt16LittleEndian(dos) != DosSignature)
        {
            return Fail(PeHeaderError.NotAPeImage, "missing 'MZ' signature", out error, out detail);
        }

        int lfanew = BinaryPrimitives.ReadInt32LittleEndian(dos[0x3C..]);
        if (lfanew < 0x40 || lfanew > MaxNtHeaderOffset)
        {
            return Fail(PeHeaderError.NotAPeImage, $"implausible e_lfanew 0x{lfanew:X}", out error, out detail);
        }

        ulong ntHeaders = imageBase + (uint)lfanew;

        // PE signature (4) + COFF file header (20): the signature, the machine field and
        // SizeOfOptionalHeader all come out of this one read.
        Span<byte> coff = stackalloc byte[24];
        if (!reader.TryRead(ntHeaders, coff))
        {
            return Fail(PeHeaderError.Unreadable, $"could not read PE/COFF header at 0x{ntHeaders:X}", out error, out detail);
        }

        if (BinaryPrimitives.ReadUInt32LittleEndian(coff) != NtSignature)
        {
            return Fail(PeHeaderError.NotAPeImage, "missing 'PE\\0\\0' signature", out error, out detail);
        }

        // §4.3 step 3.
        ushort machine = BinaryPrimitives.ReadUInt16LittleEndian(coff[4..]);
        ushort sizeOfOptionalHeader = BinaryPrimitives.ReadUInt16LittleEndian(coff[SizeOfOptionalHeaderOffset..]);

        ulong optionalHeader = ntHeaders + OptionalHeaderOffset;

        // The optional header magic — not the machine field — decides the data directory
        // offset, because it is what determines the optional header's own size.
        if (!reader.TryRead(optionalHeader, out ushort magic))
        {
            return Fail(PeHeaderError.Unreadable, "could not read optional header magic", out error, out detail);
        }

        bool isPe32Plus = magic == OptionalMagicPe32Plus;
        if (!isPe32Plus && magic != OptionalMagicPe32)
        {
            return Fail(PeHeaderError.NotAPeImage, $"unknown optional header magic 0x{magic:X4}", out error, out detail);
        }

        uint directoryTableOffset = isPe32Plus ? DirectoryTableOffsetPe32Plus : DirectoryTableOffsetPe32;

        // §4.3 step 4 gives a fixed offset for the directory table, which is sound only once
        // the header says it extends that far. Without this, a stale or garbage base means
        // whatever bytes happen to sit at +0x78 / +0x88 get parsed as a data directory.
        if (sizeOfOptionalHeader < directoryTableOffset)
        {
            return Fail(
                PeHeaderError.OptionalHeaderTooSmall,
                $"SizeOfOptionalHeader {sizeOfOptionalHeader} stops before the data directory table at +{directoryTableOffset}",
                out error,
                out detail);
        }

        // SizeOfImage (+56) through NumberOfRvaAndSizes (the last windows-specific field,
        // immediately before the directories) in one read. The window is 40 bytes for PE32
        // and 56 for PE32+, and the check above has already established the header covers it.
        Span<byte> window = stackalloc byte[(int)(DirectoryTableOffsetPe32Plus - SizeOfImageOffset)];
        window = window[..(int)(directoryTableOffset - SizeOfImageOffset)];
        if (!reader.TryRead(optionalHeader + SizeOfImageOffset, window))
        {
            return Fail(PeHeaderError.Unreadable, "could not read SizeOfImage/NumberOfRvaAndSizes", out error, out detail);
        }

        uint sizeOfImage = BinaryPrimitives.ReadUInt32LittleEndian(window);
        if (sizeOfImage == 0)
        {
            // Without it no RVA can be bounds-checked, and an unchecked RVA in a live
            // process reads a neighbouring allocation rather than failing.
            return Fail(PeHeaderError.MalformedHeader, "SizeOfImage is zero", out error, out detail);
        }

        uint numberOfRvaAndSizes = BinaryPrimitives.ReadUInt32LittleEndian(window[^4..]);
        if (numberOfRvaAndSizes > MaxDataDirectories)
        {
            return Fail(
                PeHeaderError.MalformedHeader,
                $"NumberOfRvaAndSizes {numberOfRvaAndSizes} exceeds the {MaxDataDirectories}-entry maximum",
                out error,
                out detail);
        }

        headers = new PeHeaders(
            reader,
            imageBase,
            optionalHeader,
            machine,
            isPe32Plus,
            sizeOfOptionalHeader,
            sizeOfImage,
            numberOfRvaAndSizes);

        error = PeHeaderError.None;
        detail = null;
        return true;
    }

    /// <summary>
    /// Read data directory <paramref name="index"/> — entry 0 is the export table (§4.3
    /// step 4), entry 14 the CLI header (ECMA-335 II.25.4.3).
    /// </summary>
    /// <remarks>
    /// Both bounds are applied before the read: <see cref="NumberOfRvaAndSizes"/> says how
    /// many entries the image claims, and <see cref="SizeOfOptionalHeader"/> says whether
    /// the header is physically long enough to hold them. Either falling short yields
    /// <see cref="PeDirectoryResult.Absent"/>, which is a legitimate answer, not a failure.
    /// </remarks>
    internal PeDirectoryResult TryReadDataDirectory(int index, out uint rva, out uint size)
    {
        rva = 0;
        size = 0;

        if ((uint)index >= NumberOfRvaAndSizes) return PeDirectoryResult.Absent;

        uint end = DirectoryTableOffset + (((uint)index + 1) * DataDirectoryEntrySize);
        if (SizeOfOptionalHeader < end) return PeDirectoryResult.Absent;

        ulong entry = OptionalHeaderAddress + DirectoryTableOffset + ((uint)index * DataDirectoryEntrySize);

        Span<byte> raw = stackalloc byte[(int)DataDirectoryEntrySize];
        if (!_reader.TryRead(entry, raw)) return PeDirectoryResult.Unreadable;

        rva = BinaryPrimitives.ReadUInt32LittleEndian(raw);
        size = BinaryPrimitives.ReadUInt32LittleEndian(raw[4..]);
        return PeDirectoryResult.Present;
    }

    /// <summary>Sets both failure outputs and returns false, so every reject site is one line.</summary>
    private static bool Fail(PeHeaderError reason, string message, out PeHeaderError error, out string? detail)
    {
        error = reason;
        detail = message;
        return false;
    }

    /// <summary>
    /// True if <c>[rva, rva + size)</c> lies wholly inside the mapped module.
    /// </summary>
    /// <remarks>
    /// A zero RVA or a zero size is rejected rather than treated as an empty range: both
    /// mean "absent" everywhere this is used, and letting them through would hand callers a
    /// "valid" range at the image base. Arithmetic is widened to <see cref="ulong"/> so a
    /// hostile <c>rva + size</c> cannot wrap past the check.
    /// </remarks>
    internal bool IsRvaRangeInImage(uint rva, ulong size) =>
        rva != 0 && size != 0 && rva + size <= SizeOfImage;
}
