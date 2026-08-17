namespace LiveClr.Tests.Cdac;

using LiveClr.Cdac;

/// <summary>
/// §5: finding <c>DotNetRuntimeContractDescriptor</c> in the target's own export table.
/// </summary>
public class DescriptorLocatorTests
{
    [Fact]
    public void TryLocate_ReturnsTheRelocatedDescriptorAddress()
    {
        // The RVA is build-constant; the address is not. §12.1 confirmed exactly this
        // arithmetic against a live process whose base had moved by ASLR.
        using var memory = new FakeMemory().Map(SyntheticPe.DefaultImageBase, SyntheticPe.BuildCoreClrLike());

        Assert.True(DescriptorLocator.TryLocate(memory, SyntheticPe.DefaultImageBase, out ulong address));
        Assert.Equal(SyntheticPe.DefaultImageBase + SyntheticPe.DescriptorExportRva, address);
    }

    [Fact]
    public void TryLocate_ReturnsFalseWhenTheSymbolIsAbsent()
    {
        (string Name, uint Rva)[] exports = [.. SyntheticPe.CoreClrExports.Where(e => e.Name != DescriptorLocator.ExportName)];
        using var memory = new FakeMemory().Map(SyntheticPe.DefaultImageBase, SyntheticPe.Build(exports));

        Assert.False(DescriptorLocator.TryLocate(memory, SyntheticPe.DefaultImageBase, out ulong address));
        Assert.Equal(0UL, address);
    }

    [Fact]
    public void TryLocate_ReturnsFalseWhenNothingIsMappedThere()
    {
        using var memory = new FakeMemory();

        Assert.False(DescriptorLocator.TryLocate(memory, 0x1000, out _));
    }

    [Fact]
    public void TryLocate_RejectsAForwarderExport()
    {
        // A forwarder's RVA points at a string inside the export directory. Treating it
        // as a descriptor address would mean parsing 40 bytes of ASCII as a header.
        (string Name, uint Rva)[] exports =
        [
            .. SyntheticPe.CoreClrExports.Select(e =>
                e.Name == DescriptorLocator.ExportName ? (e.Name, SyntheticPe.ExportDirectoryRva + 8) : e),
        ];
        using var memory = new FakeMemory().Map(SyntheticPe.DefaultImageBase, SyntheticPe.Build(exports));

        Assert.False(DescriptorLocator.TryLocate(memory, SyntheticPe.DefaultImageBase, out _));
    }

    [Fact]
    public void TryLocate_ProbesSeveralModuleBases()
    {
        // Modelling a module list where only one entry is the runtime: the others are
        // valid PEs that simply do not export the symbol.
        const ulong otherBase = 0x0000_7FFE_2000_0000;
        (string Name, uint Rva)[] otherExports = [("SomethingElse", 0x1000)];

        using var memory = new FakeMemory()
            .Map(otherBase, SyntheticPe.Build(otherExports))
            .Map(SyntheticPe.DefaultImageBase, SyntheticPe.BuildCoreClrLike());

        Assert.True(DescriptorLocator.TryLocate(memory, [0x1000, otherBase, SyntheticPe.DefaultImageBase], out ulong address));
        Assert.Equal(SyntheticPe.DefaultImageBase + SyntheticPe.DescriptorExportRva, address);
    }
}
