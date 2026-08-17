namespace LiveClr.Tests.Metadata;

using System.Buffers.Binary;
using LiveClr.Metadata;

/// <summary>
/// The §12.4d metadata route's half of the shared <c>LiveClr.Pe.PeHeaders</c> walk.
/// </summary>
/// <remarks>
/// <para>
/// These headers used to be parsed twice — once for the §4.3 export walk, once here — and
/// the copies drifted. The export copy grew <c>SizeOfImage</c>, <c>NumberOfRvaAndSizes</c>
/// and <c>e_lfanew</c> hardening; this route never received any of it, so every case below
/// either loaded successfully or failed for an accidental reason before the two were merged.
/// The corresponding assertions on the export side live in
/// <c>LiveClr.Tests.Cdac.PeImageTests</c>; if one of these files ever needs a check the
/// other lacks, the merge has come undone.
/// </para>
/// <para>
/// Everything here mutates a real assembly's headers after mapping, so the surrounding
/// image stays structurally honest and only the field under test is hostile.
/// </para>
/// </remarks>
public sealed class SharedPeHeaderTests
{
    private static MappedPeImage LiveClrImage() =>
        MappedPeImage.FromFile(typeof(ModuleMetadata).Assembly.Location);

    private static int OptionalHeaderOffset(byte[] image) =>
        BinaryPrimitives.ReadInt32LittleEndian(image.AsSpan(0x3C)) + 24;

    /// <summary>PE32 puts it at +92, PE32+ at +108: the 16-byte shift from the widened <c>ImageBase</c>.</summary>
    private static int NumberOfRvaAndSizesOffset(byte[] image)
    {
        int optional = OptionalHeaderOffset(image);
        ushort magic = BinaryPrimitives.ReadUInt16LittleEndian(image.AsSpan(optional));
        return optional + (magic == 0x20B ? 108 : 92);
    }

    private static ModuleMetadataStatus StatusOf(MappedPeImage mapped, out string? detail)
    {
        using var reader = mapped.CreateReader();
        using ModuleMetadata? metadata = ModuleMetadata.TryLoad(
            reader, MappedPeImage.BaseAddress, out ModuleMetadataStatus status, out detail);
        Assert.Null(metadata);
        return status;
    }

    [Fact]
    public void AZeroSizeOfImageIsRejected()
    {
        // Previously this route never read SizeOfImage at all and loaded the module happily.
        // It is the ONLY bound an RVA can be checked against, so without it every later
        // bounds check silently degrades to "anything the target will let us read".
        MappedPeImage mapped = LiveClrImage();
        BinaryPrimitives.WriteUInt32LittleEndian(mapped.Image.AsSpan(OptionalHeaderOffset(mapped.Image) + 56), 0);

        Assert.Equal(ModuleMetadataStatus.NotAPeImage, StatusOf(mapped, out string? detail));
        Assert.Contains("SizeOfImage", detail ?? string.Empty, StringComparison.Ordinal);
    }

    [Fact]
    public void AnAbsurdNumberOfRvaAndSizesIsRejected()
    {
        // The PE format caps the directory table at 16 entries. This route used to test only
        // "is the count greater than 14", so a garbage count of 0x1000 satisfied it and the
        // module loaded — the exact case the export walk had rejected since it was written.
        MappedPeImage mapped = LiveClrImage();
        BinaryPrimitives.WriteUInt32LittleEndian(mapped.Image.AsSpan(NumberOfRvaAndSizesOffset(mapped.Image)), 0x1000);

        Assert.Equal(ModuleMetadataStatus.NotAPeImage, StatusOf(mapped, out string? detail));
        Assert.Contains("NumberOfRvaAndSizes", detail ?? string.Empty, StringComparison.Ordinal);
    }

    [Fact]
    public void ADirectoryCountThatSimplyStopsBeforeEntry14StaysANativeModule()
    {
        // The counterpart to the test above, and the reason the 16-entry cap could not just
        // be folded into it: a count of 14 is a legal, ordinary image with no CLI directory.
        // Reporting that as NotAPeImage would make every native DLL look broken.
        MappedPeImage mapped = LiveClrImage();
        BinaryPrimitives.WriteUInt32LittleEndian(mapped.Image.AsSpan(NumberOfRvaAndSizesOffset(mapped.Image)), 14);

        Assert.Equal(ModuleMetadataStatus.NoCliHeader, StatusOf(mapped, out string? detail));
        Assert.NotNull(detail);
    }

    [Fact]
    public void AnELfanewOutsideTheFirstPageIsRejected()
    {
        // Both copies bounded e_lfanew, but disagreed: 0x1000 here versus 0x10000000 there.
        // The NT headers are in the first page of every image the loader will map, and the
        // looser bound let a wrong base chase a pointer 256 MB into someone else's memory
        // before noticing. The strict bound won.
        MappedPeImage mapped = LiveClrImage();
        BinaryPrimitives.WriteInt32LittleEndian(mapped.Image.AsSpan(0x3C), 0x2000);

        Assert.Equal(ModuleMetadataStatus.NotAPeImage, StatusOf(mapped, out string? detail));
        Assert.Contains("e_lfanew", detail ?? string.Empty, StringComparison.Ordinal);
    }

    [Fact]
    public void ACliDirectoryPointingOutsideTheImageIsMalformedRatherThanUnreadable()
    {
        // The payoff of having SizeOfImage on this route. Against the fake reader the read
        // simply fails, but in a live process the pages past a module are routinely mapped
        // by something else — so this would have read a neighbouring allocation and parsed
        // whatever it found as a COR20 header (§4.3, §6.4).
        MappedPeImage mapped = LiveClrImage();
        BinaryPrimitives.WriteUInt32LittleEndian(
            mapped.Image.AsSpan(mapped.CliDirectoryOffset), (uint)mapped.Image.Length);

        // "CLI header rva=", not just "outside": the blob validator has an "outside" message
        // of its own, and a test that matched it would pass without this bound existing.
        Assert.Equal(ModuleMetadataStatus.MalformedMetadata, StatusOf(mapped, out string? detail));
        Assert.Contains("CLI header rva=", detail ?? string.Empty, StringComparison.Ordinal);
    }

    [Fact]
    public void AMetadataBlobRunningPastTheEndOfTheImageIsRejectedBeforeTheCopy()
    {
        // Same bound one level down, and the size is deliberately plausible (under the
        // 256 MB cap) so only SizeOfImage can catch it.
        MappedPeImage mapped = LiveClrImage();
        int cliRva = (int)BinaryPrimitives.ReadUInt32LittleEndian(mapped.Image.AsSpan(mapped.CliDirectoryOffset));
        BinaryPrimitives.WriteUInt32LittleEndian(mapped.Image.AsSpan(cliRva + 12), (uint)mapped.Image.Length);

        Assert.Equal(ModuleMetadataStatus.MalformedMetadata, StatusOf(mapped, out string? detail));
        Assert.Contains("metadata rva=", detail ?? string.Empty, StringComparison.Ordinal);
    }

    [Fact]
    public void AnOptionalHeaderTooSmallForTheDirectoryTableStaysANativeModule()
    {
        // The one place the two copies disagreed about SEVERITY rather than strictness: the
        // export walk failed outright, this route called it NoCliHeader. Both are preserved
        // — the shared parser reports the cause and each caller keeps its own verdict, so a
        // truncated optional header is still swallowed here as an unremarkable module.
        MappedPeImage mapped = LiveClrImage();
        int coff = BinaryPrimitives.ReadInt32LittleEndian(mapped.Image.AsSpan(0x3C)) + 4;
        BinaryPrimitives.WriteUInt16LittleEndian(mapped.Image.AsSpan(coff + 16), 64);

        Assert.Equal(ModuleMetadataStatus.NoCliHeader, StatusOf(mapped, out string? detail));
        Assert.NotNull(detail);
    }
}
