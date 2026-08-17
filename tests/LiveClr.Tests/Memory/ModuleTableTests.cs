namespace LiveClr.Tests.Memory;

using LiveClr.Memory;

public class ModuleTableTests
{
    private static ModuleTable Sample() => new(
    [
        new ModuleInfo("sts2.exe", 0x140000000, 0x0100_0000, 0x140001000),
        new ModuleInfo("coreclr.dll", 0x7FFE_0000_0000, 0x0080_0000),
        new ModuleInfo("System.Private.CoreLib.dll", 0x7FFE_1000_0000, 0x0090_0000),
        new ModuleInfo("api-ms-win-core-processsnapshot-l1-1-0.dll", 0x7FFE_2000_0000, 0x1000),
    ]);

    [Theory]
    [InlineData("coreclr")]
    [InlineData("CoreCLR")]
    [InlineData("CORECLR")]
    [InlineData("coreclr.dll")]
    [InlineData("CoreCLR.DLL")]
    public void Runtime_module_resolves_by_any_spelling(string query)
    {
        Assert.True(Sample().TryGet(query, out var module));
        Assert.Equal("coreclr.dll", module.FileName);
        Assert.Equal(0x7FFE_0000_0000UL, module.BaseAddress);
        Assert.Equal(0x0080_0000U, module.Size);
    }

    /// <summary>
    /// §4.4 compares the game assembly against bare <c>"sts2"</c> while §4.2
    /// compares the runtime against <c>"coreclr.dll"</c>; both spellings have to
    /// reach the right image without the caller knowing the extension.
    /// </summary>
    [Theory]
    [InlineData("sts2")]
    [InlineData("STS2")]
    [InlineData("sts2.exe")]
    public void Game_module_resolves_without_knowing_its_extension(string query)
    {
        var module = Sample()[query];
        Assert.Equal("sts2.exe", module.FileName);
        Assert.Equal(0x140000000UL, module.BaseAddress);
    }

    [Fact]
    public void Only_image_extensions_are_stripped()
    {
        var table = Sample();
        Assert.Equal("System.Private.CoreLib", table["System.Private.CoreLib"].Name);
        Assert.Equal("System.Private.CoreLib", table["System.Private.CoreLib.dll"].Name);
        Assert.Equal("api-ms-win-core-processsnapshot-l1-1-0", table["api-ms-win-core-processsnapshot-l1-1-0.dll"].Name);
    }

    /// <summary>
    /// Stripping any final dot-segment would fold a dotted assembly name onto a
    /// different module that happens to be loaded. Answering with the wrong
    /// module is the worst possible outcome: every offset read from it is
    /// plausible and wrong.
    /// </summary>
    [Fact]
    public void A_dotted_name_does_not_collapse_onto_a_shorter_module()
    {
        var table = new ModuleTable(
        [
            new ModuleInfo("MegaCrit.dll", 0x1000, 0x100),
            new ModuleInfo("coreclr.dll", 0x2000, 0x100),
        ]);

        Assert.Null(table.Find("MegaCrit.Sts2"));
        Assert.Equal(0x1000UL, table["MegaCrit"].BaseAddress);
    }

    /// <summary>An explicit extension in the query is a requirement, not a hint.</summary>
    [Fact]
    public void An_explicit_extension_selects_that_exact_image()
    {
        var both = new ModuleTable(
        [
            new ModuleInfo("sts2.exe", 0x1000, 0x100),
            new ModuleInfo("sts2.dll", 0x2000, 0x100),
        ]);

        Assert.Equal(0x2000UL, both["sts2.dll"].BaseAddress);
        Assert.Equal(0x1000UL, both["sts2.exe"].BaseAddress);
        Assert.Equal(0x1000UL, both["sts2"].BaseAddress); // first loaded wins

        // Only the EXE is present: a .dll query must not settle for it.
        var exeOnly = new ModuleTable([new ModuleInfo("sts2.exe", 0x1000, 0x100)]);
        Assert.Null(exeOnly.Find("sts2.dll"));
        Assert.Equal(0x1000UL, exeOnly["sts2"].BaseAddress);
    }

    [Fact]
    public void A_debug_file_is_not_the_image()
    {
        var table = Sample();
        Assert.Null(table.Find("coreclr.pdb"));
        Assert.Null(table.Find("sts2.pdb"));
        Assert.NotNull(table.Find("coreclr"));
    }

    [Fact]
    public void Missing_modules_report_absence_rather_than_a_wrong_match()
    {
        var table = Sample();
        Assert.False(table.TryGet("mono", out var module));
        Assert.Null(module);
        Assert.Null(table.Find("clrjit"));
        Assert.Throws<KeyNotFoundException>(() => table["clrjit"]);

        // A prefix is not a match: "core" must not resolve to "coreclr".
        Assert.Null(table.Find("core"));
        Assert.Null(table.Find("clr"));
    }

    [Fact]
    public void Duplicate_simple_names_resolve_to_the_first_loaded()
    {
        var table = new ModuleTable(
        [
            new ModuleInfo("coreclr.dll", 0x1000, 0x100),
            new ModuleInfo("coreclr.dll", 0x9000, 0x100),
        ]);

        Assert.Equal(0x1000UL, table["coreclr"].BaseAddress);
        Assert.Equal(2, table.Count);
        Assert.Single(table.Names);
    }

    [Fact]
    public void Address_containment_is_half_open()
    {
        var m = new ModuleInfo("coreclr.dll", 0x1000, 0x100);

        Assert.False(m.Contains(0x0FFF));
        Assert.True(m.Contains(0x1000));
        Assert.True(m.Contains(0x10FF));
        Assert.False(m.Contains(0x1100)); // EndAddress is exclusive
        Assert.Equal(0x1100UL, m.EndAddress);
    }

    [Fact]
    public void FindContaining_locates_the_owning_image()
    {
        var table = Sample();

        Assert.Equal("coreclr.dll", table.FindContaining(0x7FFE_0000_1234)!.FileName);
        Assert.Equal("sts2.exe", table.FindContaining(0x140000000)!.FileName);
        Assert.Null(table.FindContaining(0x1234));
    }

    [Fact]
    public void Names_are_the_simple_forms_and_enumeration_order_is_preserved()
    {
        var table = Sample();

        Assert.Contains("coreclr", table.Names);
        Assert.Contains("sts2", table.Names);
        Assert.DoesNotContain("coreclr.dll", table.Names);

        Assert.Equal("sts2.exe", table.Modules[0].FileName);
        Assert.Equal(4, table.Modules.Count);
    }

    [Fact]
    public void An_empty_table_is_valid()
    {
        var table = new ModuleTable([]);
        Assert.Equal(0, table.Count);
        Assert.Empty(table.Names);
        Assert.Null(table.Find("coreclr"));
    }
}
