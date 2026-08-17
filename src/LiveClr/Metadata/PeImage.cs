namespace LiveClr.Metadata;

using System.Buffers.Binary;
using LiveClr.Memory;
using LiveClr.Pe;

/// <summary>
/// The CLI-header half of the §12.4d route: data directory 14 → COR20 header → the
/// ECMA-335 metadata RVA and size, over a <em>loaded</em> image in the target address space.
/// </summary>
/// <remarks>
/// <para>
/// The PE header walk that gets us to data directory 14 is <see cref="PeHeaders"/>, shared
/// with the §4.3 export walk. It used to be a second, independently written copy here, and
/// the two drifted: this side never received the <c>SizeOfImage</c> and
/// <c>NumberOfRvaAndSizes</c> validation the other side grew. It now does, which is why
/// <see cref="ModuleMetadataStatus.NotAPeImage"/> can be reported for a self-inconsistent
/// header that previously parsed.
/// </para>
/// <para>
/// Analysis doc §8.1 rejects <c>System.Reflection.PortableExecutable</c> here: the BCL types
/// want a <see cref="System.IO.Stream"/>, which is awkward against a remote process, and the
/// hand-rolled walk is short and already proven in probes 01/13.
/// </para>
/// <para>
/// KEY ASSUMPTION: the image is mapped by the loader (<c>SEC_IMAGE</c>), so an RVA is
/// simply an offset from <c>Module.Base</c>. That is what §12.4d walked live; it would
/// NOT hold for a raw on-disk file, where RVAs must be translated through the section
/// table.
/// </para>
/// </remarks>
internal static class PeImage
{
    /// <summary>Data directory index 14 is the CLI header (ECMA-335 II.25.4.3).</summary>
    private const int CliHeaderDirectoryIndex = 14;

    /// <summary>ECMA-335 II.25.3.3: the CLI header is 72 bytes.</summary>
    private const uint CliHeaderSize = 72;

    /// <summary>
    /// Guards against an absurd allocation if a garbage pointer parses far enough to
    /// yield a "size". Real metadata is single-digit MB (sts2.dll: 4,967,924 bytes).
    /// </summary>
    private const uint MaxPlausibleMetadataSize = 256u * 1024 * 1024;

    /// <summary>
    /// Follow <c>Module.Base</c> → PE headers → CLI header → metadata RVA/size.
    /// Never throws: a native DLL is an expected, ordinary outcome, not an error.
    /// </summary>
    internal static bool TryLocateMetadata(
        IMemoryReader memory,
        ulong moduleBase,
        out uint metadataRva,
        out uint metadataSize,
        out ModuleMetadataStatus status,
        out string? detail)
    {
        metadataRva = 0;
        metadataSize = 0;

        if (!PeHeaders.TryParse(memory, moduleBase, out PeHeaders? headers, out PeHeaderError error, out detail))
        {
            // An optional header that stops before the data directory table cannot hold
            // entry 14, which is indistinguishable — to this caller — from an image that
            // simply declares no CLI directory. Everything else is a broken image.
            //
            // The machine field is deliberately NOT filtered: this route reads RVAs and
            // copies a byte blob, so it has none of §4.3's pointer-width dependency and an
            // ARM64 managed module is a perfectly good input.
            status = error == PeHeaderError.OptionalHeaderTooSmall
                ? ModuleMetadataStatus.NoCliHeader
                : ModuleMetadataStatus.NotAPeImage;
            return false;
        }

        switch (headers.TryReadDataDirectory(CliHeaderDirectoryIndex, out uint cliRva, out uint cliSize))
        {
            case PeDirectoryResult.Absent:
                // A perfectly normal native DLL. §12.4d step "data directory 14".
                status = ModuleMetadataStatus.NoCliHeader;
                detail = headers.SizeOfOptionalHeader <
                         headers.DirectoryTableOffset + ((CliHeaderDirectoryIndex + 1) * 8)
                    ? "optional header too small to contain data directory 14"
                    : "image has no CLI data directory";
                return false;

            case PeDirectoryResult.Unreadable:
                status = ModuleMetadataStatus.NotAPeImage;
                detail = "could not read CLI data directory entry";
                return false;
        }

        if (cliRva == 0 || cliSize == 0)
        {
            status = ModuleMetadataStatus.NoCliHeader;
            detail = "CLI data directory is empty (native image)";
            return false;
        }

        // From here on the image has ASSERTED that it is managed. Anything that fails now is
        // corruption, not a native DLL — and must not be reported as NoCliHeader, which
        // callers are explicitly told to swallow. A stale Module.Base is the likely cause.
        if (cliSize < CliHeaderSize)
        {
            status = ModuleMetadataStatus.MalformedMetadata;
            detail = $"CLI header size {cliSize} is below the ECMA-335 minimum of {CliHeaderSize}";
            return false;
        }

        // SizeOfImage is the only bound an RVA can be checked against, and in a live process
        // the pages past a module are frequently mapped by something else — so an unchecked
        // RVA reads a neighbouring allocation and yields a plausible-looking COR20 header
        // rather than failing (§4.3, §6.4).
        if (!headers.IsRvaRangeInImage(cliRva, cliSize))
        {
            status = ModuleMetadataStatus.MalformedMetadata;
            detail = $"CLI header rva=0x{cliRva:X} size={cliSize} runs outside the {headers.SizeOfImage}-byte image";
            return false;
        }

        // CLI header: cb(0) MajorRuntimeVersion(4) MinorRuntimeVersion(6)
        //             MetaData.VirtualAddress(8) MetaData.Size(12)   — §12.4d
        Span<byte> cli = stackalloc byte[16];
        if (!memory.TryRead(moduleBase + cliRva, cli))
        {
            status = ModuleMetadataStatus.MetadataUnreadable;
            detail = $"could not read CLI header at rva 0x{cliRva:X}";
            return false;
        }

        uint cb = BinaryPrimitives.ReadUInt32LittleEndian(cli);
        if (cb < CliHeaderSize)
        {
            status = ModuleMetadataStatus.MalformedMetadata;
            detail = $"CLI header cb={cb} is not a valid COR20 header";
            return false;
        }

        uint rva = BinaryPrimitives.ReadUInt32LittleEndian(cli[8..]);
        uint size = BinaryPrimitives.ReadUInt32LittleEndian(cli[12..]);
        if (rva == 0 || size < 16 || size > MaxPlausibleMetadataSize)
        {
            status = ModuleMetadataStatus.MalformedMetadata;
            detail = $"implausible metadata directory rva=0x{rva:X} size={size}";
            return false;
        }

        // Same argument as the CLI header above: without this, a blob that runs off the end
        // of the module is copied out of whatever is mapped next and handed to the validator.
        if (!headers.IsRvaRangeInImage(rva, size))
        {
            status = ModuleMetadataStatus.MalformedMetadata;
            detail = $"metadata rva=0x{rva:X} size={size} runs outside the {headers.SizeOfImage}-byte image";
            return false;
        }

        metadataRva = rva;
        metadataSize = size;
        status = ModuleMetadataStatus.Loaded;
        detail = null;
        return true;
    }
}
