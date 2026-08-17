namespace LiveClr.Tests.Cdac;

using System.Buffers.Binary;
using LiveClr.Cdac;

/// <summary>
/// Covers the §4.3 remote export walk against a synthetic in-memory PE. The image is
/// mapped at an ASLR'd base, so anything that assumed the preferred image base or a
/// file-offset layout fails here rather than in front of a live game.
/// </summary>
public class PeImageTests
{
    private static FakeMemory MapImage(byte[] image, ulong imageBase = SyntheticPe.DefaultImageBase) =>
        new FakeMemory().Map(imageBase, image);

    [Fact]
    public void TryLoad_ParsesPe32PlusHeaders()
    {
        using FakeMemory memory = MapImage(SyntheticPe.BuildCoreClrLike());

        Assert.True(PeImage.TryLoad(memory, SyntheticPe.DefaultImageBase, out PeImage? image));
        Assert.Equal(PeImage.MachineAmd64, image.Machine);
        Assert.True(image.IsPe32Plus);
        Assert.True(image.Is64Bit);
        Assert.Equal(SyntheticPe.ExportDirectoryRva, image.ExportDirectoryRva);
        Assert.Equal(SyntheticPe.DefaultImageBase, image.ImageBase);
    }

    [Fact]
    public void TryLoad_ParsesPe32_UsingTheOtherDataDirectoryOffset()
    {
        // §4.3 step 4: the export directory sits at +0x78 for PE32 and +0x88 for PE32+.
        // A reader that hardcodes one of them finds garbage in the other.
        byte[] image = SyntheticPe.Build(SyntheticPe.CoreClrExports, pe32Plus: false, machine: PeImage.MachineI386);
        using FakeMemory memory = MapImage(image);

        Assert.True(PeImage.TryLoad(memory, SyntheticPe.DefaultImageBase, out PeImage? pe));
        Assert.False(pe.IsPe32Plus);
        Assert.Equal(PeImage.MachineI386, pe.Machine);
        Assert.True(pe.TryFindExport(DescriptorLocator.ExportName, out ulong rva));
        Assert.Equal(SyntheticPe.DescriptorExportRva, rva);
    }

    [Fact]
    public void TryFindExport_ResolvesTheDescriptorRva()
    {
        using FakeMemory memory = MapImage(SyntheticPe.BuildCoreClrLike());
        Assert.True(PeImage.TryLoad(memory, SyntheticPe.DefaultImageBase, out PeImage? image));

        Assert.True(image.TryFindExport(DescriptorLocator.ExportName, out ulong rva));
        Assert.Equal(SyntheticPe.DescriptorExportRva, rva);
    }

    [Fact]
    public void TryFindExport_ResolvesEveryName()
    {
        using FakeMemory memory = MapImage(SyntheticPe.BuildCoreClrLike());
        Assert.True(PeImage.TryLoad(memory, SyntheticPe.DefaultImageBase, out PeImage? image));

        foreach ((string name, uint expected) in SyntheticPe.CoreClrExports)
        {
            Assert.True(image.TryFindExport(name, out ulong rva), name);
            Assert.Equal(expected, rva);
        }
    }

    [Fact]
    public void TryFindExport_IsCaseSensitive()
    {
        // PE export names are case-sensitive; a case-insensitive match would be a
        // silent behaviour change relative to the loader.
        using FakeMemory memory = MapImage(SyntheticPe.BuildCoreClrLike());
        Assert.True(PeImage.TryLoad(memory, SyntheticPe.DefaultImageBase, out PeImage? image));

        Assert.False(image.TryFindExport("dotnetruntimecontractdescriptor", out _));
    }

    [Fact]
    public void TryFindExport_ReturnsFalseForUnknownName()
    {
        using FakeMemory memory = MapImage(SyntheticPe.BuildCoreClrLike());
        Assert.True(PeImage.TryLoad(memory, SyntheticPe.DefaultImageBase, out PeImage? image));

        Assert.False(image.TryFindExport("g_notAThing", out ulong rva));
        Assert.Equal(0UL, rva);
    }

    [Fact]
    public void TryFindExport_HandlesANameFlushWithTheEndOfMappedMemory()
    {
        // The synthetic image ends exactly at the last name, so the chunked string read
        // runs off the end of the region and must narrow instead of failing. Real images
        // put the string table at the end of a section, so this is not a contrived case.
        using FakeMemory memory = MapImage(SyntheticPe.BuildCoreClrLike());
        Assert.True(PeImage.TryLoad(memory, SyntheticPe.DefaultImageBase, out PeImage? image));

        (string lastName, uint lastRva) = SyntheticPe.CoreClrExports[^1];
        Assert.True(image.TryFindExport(lastName, out ulong rva));
        Assert.Equal(lastRva, rva);
    }

    [Fact]
    public void Fixture_NameOrdinalTableHasNoFixedPoints()
    {
        // Guards the guard. If the permutation ever regains a fixed point at the
        // descriptor's index, every test that resolves only that one name silently stops
        // covering the ordinal indirection and would pass against a reader that ignored
        // the ordinal table outright.
        byte[] image = SyntheticPe.BuildCoreClrLike();
        int count = SyntheticPe.CoreClrExports.Length;
        int ordinalsOffset = (int)SyntheticPe.ExportDirectoryRva + 40 + (count * 4) + (count * 4);

        for (int i = 0; i < count; i++)
        {
            int functionIndex = BinaryPrimitives.ReadUInt16LittleEndian(image.AsSpan(ordinalsOffset + (i * 2)));
            Assert.NotEqual(i, functionIndex);
        }
    }

    [Fact]
    public void GetExportNames_ReturnsTheWholeTable()
    {
        using FakeMemory memory = MapImage(SyntheticPe.BuildCoreClrLike());
        Assert.True(PeImage.TryLoad(memory, SyntheticPe.DefaultImageBase, out PeImage? image));

        IReadOnlyList<string> names = image.GetExportNames(out int declared);

        Assert.Equal(12, names.Count);
        Assert.Equal(12, declared);
        Assert.Contains(DescriptorLocator.ExportName, names);
        Assert.Contains("g_dacTable", names);
    }

    /// <summary>
    /// One name whose RVA leaves the image: eleven names come back, and the table still says
    /// twelve.
    /// </summary>
    /// <remarks>
    /// The list shrinks — there is no honest name to put in the gap — but it must not shrink
    /// SILENTLY. <c>GetExportNames</c>'s own doc used to sell its length as confirmation that
    /// the walk had landed on a real table, while the loop dropped entries without counting: a
    /// module missing one name was then indistinguishable from a module exporting one thing
    /// fewer. That is §13.11's species 6 — a denominator that shrinks with its numerator —
    /// living in production code rather than in a test.
    /// </remarks>
    [Fact]
    public void GetExportNames_ReportsTheDeclaredCountWhenOneNameIsUnreadable()
    {
        byte[] image = SyntheticPe.BuildCoreClrLike();
        int namesRva = (int)SyntheticPe.ExportDirectoryRva + 40 + (SyntheticPe.CoreClrExports.Length * 4);

        // Entry 0's name now points outside the module.
        BinaryPrimitives.WriteUInt32LittleEndian(image.AsSpan(namesRva), 0x00FF_0000);
        using FakeMemory memory = MapImage(image);

        Assert.True(PeImage.TryLoad(memory, SyntheticPe.DefaultImageBase, out PeImage? pe));

        IReadOnlyList<string> names = pe.GetExportNames(out int declared);

        Assert.Equal(11, names.Count);
        Assert.Equal(12, declared);
        Assert.DoesNotContain("DllGetActivationFactory", names);
        Assert.Contains("g_dacTable", names);
    }

    [Fact]
    public void IsForwarderRva_DetectsRvasInsideTheExportDirectory()
    {
        using FakeMemory memory = MapImage(SyntheticPe.BuildCoreClrLike());
        Assert.True(PeImage.TryLoad(memory, SyntheticPe.DefaultImageBase, out PeImage? image));

        Assert.True(image.IsForwarderRva(SyntheticPe.ExportDirectoryRva + 0x10));
        Assert.False(image.IsForwarderRva(SyntheticPe.DescriptorExportRva));
    }

    [Fact]
    public void TryLoad_ReturnsFalseWhenNothingIsMappedAtTheBase()
    {
        using var memory = new FakeMemory();
        Assert.False(PeImage.TryLoad(memory, SyntheticPe.DefaultImageBase, out PeImage? image));
        Assert.Null(image);

        // Probing module bases is a loop, so giving up on the first failed read — not
        // after speculatively chasing header fields — is part of the contract.
        Assert.Equal(1, memory.FailedReads);
    }

    [Fact]
    public void TryLoad_ReturnsFalseWhenTheOptionalHeaderIsTooShortToHoldTheDirectories()
    {
        // SizeOfOptionalHeader is the header's own statement of how far it extends. Below
        // the data directory table there is nothing legitimate to read at +0x88.
        byte[] image = SyntheticPe.BuildCoreClrLike();
        BinaryPrimitives.WriteUInt16LittleEndian(image.AsSpan(0x80 + 20), 64);
        using FakeMemory memory = MapImage(image);

        Assert.False(PeImage.TryLoad(memory, SyntheticPe.DefaultImageBase, out _));
    }

    [Fact]
    public void TryLoad_ReportsNoExportsWhenThereAreNoDataDirectories()
    {
        // NumberOfRvaAndSizes = 0 means the directories do not exist. The image is still
        // a valid PE, so it loads — but whatever bytes sit at +0x88 must not be read as
        // an export directory.
        byte[] image = SyntheticPe.BuildCoreClrLike();
        BinaryPrimitives.WriteUInt32LittleEndian(image.AsSpan(0x80 + 0x88 - 4), 0);
        using FakeMemory memory = MapImage(image);

        Assert.True(PeImage.TryLoad(memory, SyntheticPe.DefaultImageBase, out PeImage? pe));
        Assert.Equal(0u, pe.ExportDirectoryRva);
        Assert.False(pe.TryFindExport(DescriptorLocator.ExportName, out _));
    }

    [Fact]
    public void TryLoad_ReturnsFalseForAnAbsurdDirectoryCount()
    {
        byte[] image = SyntheticPe.BuildCoreClrLike();
        BinaryPrimitives.WriteUInt32LittleEndian(image.AsSpan(0x80 + 0x88 - 4), 0x1000);
        using FakeMemory memory = MapImage(image);

        Assert.False(PeImage.TryLoad(memory, SyntheticPe.DefaultImageBase, out _));
    }

    [Fact]
    public void TryLoad_ReturnsFalseWhenSizeOfImageIsMissing()
    {
        // Without it no RVA can be bounds-checked, and an unchecked RVA in a live process
        // reads a neighbouring allocation rather than failing.
        byte[] image = SyntheticPe.BuildCoreClrLike();
        BinaryPrimitives.WriteUInt32LittleEndian(image.AsSpan(0x80 + 24 + 56), 0);
        using FakeMemory memory = MapImage(image);

        Assert.False(PeImage.TryLoad(memory, SyntheticPe.DefaultImageBase, out _));
    }

    [Theory]
    [InlineData(0u)]            // live RVA, zero size — would disable the forwarder guard
    [InlineData(8u)]            // smaller than IMAGE_EXPORT_DIRECTORY itself
    [InlineData(0x1000_0000u)]  // runs past the end of the module
    public void TryLoad_DemotesAMalformedExportDirectoryToNoExports(uint exportSize)
    {
        byte[] image = SyntheticPe.BuildCoreClrLike();
        BinaryPrimitives.WriteUInt32LittleEndian(image.AsSpan(0x80 + 0x88 + 4), exportSize);
        using FakeMemory memory = MapImage(image);

        Assert.True(PeImage.TryLoad(memory, SyntheticPe.DefaultImageBase, out PeImage? pe));
        Assert.Equal(0u, pe.ExportDirectoryRva);
        Assert.Equal(0u, pe.ExportDirectorySize);
        Assert.False(pe.TryFindExport(DescriptorLocator.ExportName, out _));
        Assert.Empty(pe.GetExportNames());
    }

    /// <summary>
    /// A corrupt <c>AddressOfNames</c> pointing past the module, with a perfectly valid name
    /// table waiting at the address it points to.
    /// </summary>
    /// <remarks>
    /// The decoy is the test. Left unmapped — as this used to be — the walk fails at the read
    /// instead of at the bounds check, so deleting the bounds check kept the suite green while
    /// modelling the opposite of the hazard the code's own comment names: in a live process
    /// the pages next door are usually mapped by something else, and an unchecked RVA then
    /// returns names that look entirely real (§4.3, §13.11).
    /// </remarks>
    [Fact]
    public void TryFindExport_ReturnsFalseWhenATableRunsOutsideTheImage()
    {
        const uint decoyRva = 0x0F00_0000;

        byte[] image = SyntheticPe.BuildCoreClrLike();
        BinaryPrimitives.WriteUInt32LittleEndian(image.AsSpan((int)SyntheticPe.ExportDirectoryRva + 32), decoyRva);

        // The neighbouring allocation: a byte-for-byte copy of the image's real name table,
        // whose entries point back at the real string table. Nothing else about the walk is
        // damaged, so if the RVA is not bounds-checked the lookup SUCCEEDS.
        int namesOffset = (int)SyntheticPe.ExportDirectoryRva + 40 + (SyntheticPe.CoreClrExports.Length * 4);
        byte[] decoy = image[namesOffset..(namesOffset + (SyntheticPe.CoreClrExports.Length * 4))];

        using FakeMemory memory = MapImage(image).Map(SyntheticPe.DefaultImageBase + decoyRva, decoy);

        Assert.True(PeImage.TryLoad(memory, SyntheticPe.DefaultImageBase, out PeImage? pe));
        Assert.False(pe.TryFindExport(DescriptorLocator.ExportName, out _));
        Assert.Empty(pe.GetExportNames());

        // The decoy really is readable and really does spell the export name, so the refusal
        // above is the bounds check and nothing else.
        Assert.True(memory.TryRead(SyntheticPe.DefaultImageBase + decoyRva, new byte[decoy.Length]));
        Assert.Equal(SyntheticPe.CoreClrExports.Length * 4, decoy.Length);
    }

    [Theory]
    [InlineData(0x00)]      // DOS signature clobbered
    [InlineData(0x80)]      // PE signature clobbered
    public void TryLoad_ReturnsFalseWhenASignatureIsWrong(int offset)
    {
        byte[] image = SyntheticPe.BuildCoreClrLike();
        BinaryPrimitives.WriteUInt16LittleEndian(image.AsSpan(offset), 0);
        using FakeMemory memory = MapImage(image);

        Assert.False(PeImage.TryLoad(memory, SyntheticPe.DefaultImageBase, out _));
    }

    [Fact]
    public void TryLoad_ReturnsFalseForAnUnsupportedMachine()
    {
        // §4.3 step 3 admits x64 and x86 only. ARM64 would need a separate look at the
        // pointer-width assumptions before it could be waved through.
        byte[] image = SyntheticPe.BuildCoreClrLike();
        BinaryPrimitives.WriteUInt16LittleEndian(image.AsSpan(0x84), 0xAA64);
        using FakeMemory memory = MapImage(image);

        Assert.False(PeImage.TryLoad(memory, SyntheticPe.DefaultImageBase, out _));
    }

    /// <summary>
    /// An <c>e_lfanew</c> far outside the first page is refused by the bound, not by luck.
    /// </summary>
    /// <remarks>
    /// A perfectly good copy of the NT headers is mapped AT the bogus offset, so the walk that
    /// follows it would succeed. That is the realistic shape: §4.3 probes module bases, and a
    /// wrong base lands in memory that is mapped by something else — reading a random address
    /// and interpreting it is the failure the bound exists to prevent. Left unmapped, as this
    /// test used to be, the read failed first and the bound was untested (§13.11).
    /// </remarks>
    [Fact]
    public void TryLoad_ReturnsFalseForAnAbsurdLfanew()
    {
        const int bogus = 0x0010_0000;

        byte[] image = SyntheticPe.BuildCoreClrLike();
        BinaryPrimitives.WriteInt32LittleEndian(image.AsSpan(0x3C), bogus);

        byte[] ntHeaders = image[0x80..0x200];
        using FakeMemory memory = MapImage(image).Map(SyntheticPe.DefaultImageBase + bogus, ntHeaders);

        // The decoy is genuinely a PE signature, so nothing but the offset bound refuses it.
        Assert.Equal(0x0000_4550u, BinaryPrimitives.ReadUInt32LittleEndian(ntHeaders));
        Assert.False(PeImage.TryLoad(memory, SyntheticPe.DefaultImageBase, out _));

        // ...and the largest offset the bound permits still parses, so the rejection above is
        // the cap rather than a blanket refusal of anything past the DOS stub.
        byte[] atTheCap = SyntheticPe.BuildCoreClrLike();
        BinaryPrimitives.WriteInt32LittleEndian(atTheCap.AsSpan(0x3C), 0x1000);
        using FakeMemory capped = MapImage(atTheCap).Map(SyntheticPe.DefaultImageBase + 0x1000, atTheCap[0x80..0x200]);
        Assert.True(PeImage.TryLoad(capped, SyntheticPe.DefaultImageBase, out _));
    }

    [Fact]
    public void TryLoad_ReturnsFalseForAnUnrecognisedOptionalHeaderMagic()
    {
        byte[] image = SyntheticPe.BuildCoreClrLike();
        BinaryPrimitives.WriteUInt16LittleEndian(image.AsSpan(0x80 + 24), 0x0107); // ROM image
        using FakeMemory memory = MapImage(image);

        Assert.False(PeImage.TryLoad(memory, SyntheticPe.DefaultImageBase, out _));
    }

    [Fact]
    public void TryFindExport_ReturnsFalseWhenTheModuleExportsNothing()
    {
        byte[] image = SyntheticPe.BuildCoreClrLike();
        int exportDirEntry = 0x80 + 0x88;
        BinaryPrimitives.WriteUInt32LittleEndian(image.AsSpan(exportDirEntry), 0);
        using FakeMemory memory = MapImage(image);

        Assert.True(PeImage.TryLoad(memory, SyntheticPe.DefaultImageBase, out PeImage? pe));
        Assert.False(pe.TryFindExport(DescriptorLocator.ExportName, out _));
        Assert.Empty(pe.GetExportNames());
    }

    [Fact]
    public void TryFindExport_ReturnsFalseWhenTheStringTableIsUnreadable()
    {
        // Models a module whose export strings live in a paged-out or unreadable region:
        // the walk must fail, not return whatever the previous entry held.
        byte[] image = SyntheticPe.BuildCoreClrLike();
        int namesRva = (int)SyntheticPe.ExportDirectoryRva + 40 + 12 * 4;
        BinaryPrimitives.WriteUInt32LittleEndian(image.AsSpan(namesRva), 0x00FF_0000);
        using FakeMemory memory = MapImage(image);

        Assert.True(PeImage.TryLoad(memory, SyntheticPe.DefaultImageBase, out PeImage? pe));
        Assert.True(pe.TryFindExport("g_dacTable", out _));           // later entries still resolve
        Assert.False(pe.TryFindExport("DllGetActivationFactory", out _));
    }
}
