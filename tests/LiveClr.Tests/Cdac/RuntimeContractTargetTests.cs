namespace LiveClr.Tests.Cdac;

using System.Buffers.Binary;
using LiveClr.Cdac;

/// <summary>
/// Asserts the offsets a real .NET 9 runtime publishes about itself (§5.2), and the
/// §5.5 gap: what it does <em>not</em> publish must degrade, never throw.
/// </summary>
public class RuntimeContractTargetTests
{
    private static RuntimeContractTarget Target(FakeMemory memory)
    {
        Assert.True(RuntimeContractTarget.TryCreate(memory, SyntheticPe.DefaultImageBase, out RuntimeContractTarget? target));
        Assert.NotNull(target);
        return target;
    }

    private static RuntimeContractTarget FixtureTarget() => Target(SyntheticDescriptor.BuildTarget());

    // ---- §5.2: the published layouts -------------------------------------------------

    [Theory]
    [InlineData("Object", "m_pMethTab", 0)]
    [InlineData("MethodTable", "Module", 24)]
    [InlineData("MethodTable", "EEClassOrCanonMT", 40)]
    [InlineData("MethodTable", "BaseSize", 4)]
    [InlineData("MethodTable", "ParentMethodTable", 16)]
    [InlineData("Module", "Assembly", 216)]
    [InlineData("Module", "Base", 192)]
    [InlineData("Module", "TypeDefToMethodTableMap", 336)]
    [InlineData("Module", "Path", 176)]
    [InlineData("String", "m_FirstChar", 12)]
    [InlineData("String", "m_StringLength", 8)]
    [InlineData("Array", "m_NumComponents", 8)]
    [InlineData("EEClass", "MethodTable", 16)]
    [InlineData("ArrayClass", "Rank", 88)]
    [InlineData("ModuleLookupMap", "TableData", 8)]
    [InlineData("MethodDesc", "Flags3AndTokenRemainder", 0)]
    public void TryGetFieldOffset_ReturnsThePublishedOffset(string typeName, string fieldName, int expected)
    {
        RuntimeContractTarget target = FixtureTarget();

        Assert.True(target.HasType(typeName));
        Assert.True(target.HasField(typeName, fieldName));
        Assert.True(target.TryGetFieldOffset(typeName, fieldName, out int offset));
        Assert.Equal(expected, offset);
    }

    [Fact]
    public void TryGetGlobalValue_ReturnsPublishedScalars()
    {
        RuntimeContractTarget target = FixtureTarget();

        // §5.2's relevant scalars. ObjectToMethodTableUnmask is the one that matters
        // most: every object → MethodTable hop masks with it.
        Assert.True(target.TryGetGlobalValue("ObjectToMethodTableUnmask", out ulong unmask));
        Assert.Equal(0x7UL, unmask);

        Assert.True(target.TryGetGlobalValue("ObjectHeaderSize", out ulong headerSize));
        Assert.Equal(0x8UL, headerSize);

        Assert.True(target.TryGetGlobalValue("MethodDescAlignment", out ulong alignment));
        Assert.Equal(0x8UL, alignment);

        Assert.True(target.TryGetGlobalValue("MethodDescTokenRemainderBitCount", out ulong bits));
        Assert.Equal(0xCUL, bits);

        Assert.True(target.TryGetGlobalValue("SOSBreakingChangeVersion", out ulong sos));
        Assert.Equal(0x5UL, sos);
    }

    [Fact]
    public void TryGetTypeSize_ReturnsTheBangEntryWhenPublished()
    {
        RuntimeContractTarget target = FixtureTarget();

        Assert.True(target.TryGetTypeSize("Array", out int arraySize));
        Assert.Equal(16, arraySize);

        Assert.True(target.TryGetTypeSize("GCHandle", out int handleSize));
        Assert.Equal(8, handleSize);

        // Most types omit "!", and "not published" must not read as "size zero".
        Assert.False(target.TryGetTypeSize("MethodTable", out int missing));
        Assert.Equal(0, missing);
    }

    [Fact]
    public void TryGetContractVersion_ReturnsTheAdvertisedVersions()
    {
        RuntimeContractTarget target = FixtureTarget();

        foreach (string contract in new[] { "DacStreams", "EcmaMetadata", "Exception", "Loader", "Object", "RuntimeTypeSystem", "Thread" })
        {
            Assert.True(target.TryGetContractVersion(contract, out int version), contract);
            Assert.Equal(1, version);
        }

        Assert.False(target.TryGetContractVersion("StackWalk", out int absent));
        Assert.Equal(0, absent);
    }

    [Fact]
    public void DescriptorSurface_ExposesVersionJsonAndNames()
    {
        RuntimeContractTarget target = FixtureTarget();

        Assert.Equal(0, target.DescriptorVersion);
        Assert.Equal(DescriptorFixture.Json, target.DescriptorJson);
        Assert.Equal(29, target.TypeNames.Count);
        Assert.Equal(22, target.GlobalNames.Count);
        Assert.Equal(7, target.ContractNames.Count);
        Assert.Contains("MethodTable", target.TypeNames);
        Assert.Contains("ObjectToMethodTableUnmask", target.GlobalNames);
    }

    // ---- §5.5: the honest gap --------------------------------------------------------

    [Theory]
    [InlineData("AppDomain")]
    [InlineData("Assembly")]
    [InlineData("ArrayListBase")]
    [InlineData("ArrayListBlock")]
    public void UnpublishedTypes_DegradeInsteadOfThrowing(string typeName)
    {
        // These three are the §5.5 finding, not hypotheticals: baseline is "empty", so
        // nothing fills them in, and a reader that assumed coverage would crash on a
        // shipping runtime. Note AppDomain exists as a *global* while its *type* layout
        // does not — precisely the trap this test pins down.
        RuntimeContractTarget target = FixtureTarget();

        Assert.False(target.HasType(typeName));
        Assert.Null(target.GetTypeLayout(typeName));
        Assert.False(target.HasField(typeName, "Anything"));
        Assert.False(target.TryGetFieldOffset(typeName, "Anything", out int offset));
        Assert.Equal(0, offset);
        Assert.False(target.TryGetTypeSize(typeName, out _));
        Assert.False(target.TryGetFieldType(typeName, "Anything", out string? fieldType));
        Assert.Null(fieldType);
        Assert.False(target.TryGetFieldAddress(0x1000, typeName, "Anything", out ulong address));
        Assert.Equal(0UL, address);
        Assert.False(target.TryReadField(0x1000, typeName, "Anything", out int value));
        Assert.Equal(0, value);
    }

    [Fact]
    public void UnpublishedFieldsOfPublishedTypes_DegradeInsteadOfThrowing()
    {
        // §4.6b: several offsets scry uses (0xb8 between Path and Base, 0xa8, 0x308) are
        // real Module fields the descriptor simply does not name. Asking for one must be
        // a false, not an exception.
        RuntimeContractTarget target = FixtureTarget();

        Assert.True(target.HasType("Module"));
        Assert.False(target.HasField("Module", "SimpleName"));
        Assert.False(target.TryGetFieldOffset("Module", "SimpleName", out int offset));
        Assert.Equal(0, offset);
    }

    [Fact]
    public void UnpublishedGlobals_DegradeInsteadOfThrowing()
    {
        RuntimeContractTarget target = FixtureTarget();

        Assert.False(target.HasGlobal("NotAGlobal"));
        Assert.Null(target.GetGlobal("NotAGlobal"));
        Assert.False(target.TryGetGlobalValue("NotAGlobal", out ulong value));
        Assert.Equal(0UL, value);
        Assert.False(target.TryGetGlobalPointer("NotAGlobal", out ulong pointer));
        Assert.Equal(0UL, pointer);
        Assert.False(target.TryReadGlobalPointer("NotAGlobal", out ulong dereferenced));
        Assert.Equal(0UL, dereferenced);
    }

    [Fact]
    public void EmptyAndOddNamesDoNotThrow()
    {
        RuntimeContractTarget target = FixtureTarget();

        Assert.False(target.HasType(string.Empty));
        Assert.False(target.HasField("Module", string.Empty));
        Assert.False(target.TryGetFieldOffset(string.Empty, string.Empty, out _));
        Assert.False(target.TryGetGlobalValue(string.Empty, out _));
        Assert.False(target.TryGetContractVersion(string.Empty, out _));

        // Descriptor names are ordinal and case-sensitive; a near miss is a miss.
        Assert.False(target.HasType("methodtable"));
        Assert.False(target.HasField("MethodTable", "module"));
    }

    // ---- §5.3: globals through pointer_data ------------------------------------------

    [Fact]
    public void TryGetGlobalPointer_ResolvesThroughPointerData()
    {
        RuntimeContractTarget target = FixtureTarget();

        // The entry holds the ADDRESS OF the global, not the global.
        Assert.True(target.TryGetGlobalPointer("AppDomain", out ulong addressOfAppDomain));
        Assert.Equal(SyntheticDescriptor.PointerData[1], addressOfAppDomain);

        Assert.True(target.TryGetGlobalPointer("ObjectMethodTable", out ulong addressOfObjectMt));
        Assert.Equal(SyntheticDescriptor.PointerData[8], addressOfObjectMt);
    }

    [Fact]
    public void TryReadGlobalPointer_PerformsTheFinalDereference()
    {
        // §12.1 end to end: pointer_data[1] → &AppDomain → AppDomain.
        const ulong appDomain = 0x0000_01A9_6EC7_1B30;
        var value = new byte[8];
        BinaryPrimitives.WriteUInt64LittleEndian(value, appDomain);

        FakeMemory memory = SyntheticDescriptor.BuildTarget().Map(SyntheticDescriptor.PointerData[1], value);
        using (memory)
        {
            RuntimeContractTarget target = Target(memory);

            Assert.True(target.TryReadGlobalPointer("AppDomain", out ulong resolved));
            Assert.Equal(appDomain, resolved);
        }
    }

    [Fact]
    public void TryReadGlobalPointer_FailsWhenTheGlobalItselfIsUnreadable()
    {
        // Nothing is mapped at &AppDomain here. The address resolves; the read does not.
        RuntimeContractTarget target = FixtureTarget();

        Assert.True(target.TryGetGlobalPointer("AppDomain", out _));
        Assert.False(target.TryReadGlobalPointer("AppDomain", out ulong value));
        Assert.Equal(0UL, value);
    }

    [Fact]
    public void TheTwoGlobalFormsDoNotBleedIntoEachOther()
    {
        // Returning pointer_data[i] from TryGetGlobalValue would hand back an address
        // where the caller asked for a value — plausible, wrong, and expensive to find.
        RuntimeContractTarget target = FixtureTarget();

        Assert.False(target.TryGetGlobalValue("AppDomain", out ulong asValue));
        Assert.Equal(0UL, asValue);
        Assert.False(target.TryGetGlobalPointer("ObjectToMethodTableUnmask", out ulong asPointer));
        Assert.Equal(0UL, asPointer);
    }

    [Fact]
    public void TerseIndirectGlobals_ResolveThroughPointerDataLikeTypedOnes()
    {
        // The lookup surface must behave identically for both spellings, or a .NET 10+ /
        // non-CoreCLR descriptor using the terse form would hand every caller an index
        // where it asked for a value.
        const string blob = """
            {"version":0,"baseline":"empty","globals":{"Terse":[1],"Typed":[[1],"pointer"]}}
            """;

        Assert.True(RuntimeDescriptor.TryParse(blob, [0, 0xABCD], out RuntimeDescriptor? descriptor));
        Assert.NotNull(descriptor);

        using var memory = new FakeMemory();
        RuntimeContractTarget target = RuntimeContractTarget.Create(memory, descriptor);

        Assert.False(target.TryGetGlobalValue("Terse", out ulong leaked));
        Assert.Equal(0UL, leaked);
        Assert.True(target.TryGetGlobalPointer("Terse", out ulong terse));
        Assert.True(target.TryGetGlobalPointer("Typed", out ulong typed));
        Assert.Equal(0xABCDUL, terse);
        Assert.Equal(typed, terse);
    }

    [Fact]
    public void TryGetGlobalPointer_FailsWhenPointerDataIsShorterThanTheIndex()
    {
        // A descriptor whose pointer_data could not be fully read must not index past it.
        Assert.True(RuntimeDescriptor.TryParse(DescriptorFixture.Json, [0, 0x1234], out RuntimeDescriptor? descriptor));
        Assert.NotNull(descriptor);

        using var memory = new FakeMemory();
        RuntimeContractTarget target = RuntimeContractTarget.Create(memory, descriptor);

        Assert.True(target.TryGetGlobalPointer("AppDomain", out ulong appDomain));   // index 1, present
        Assert.Equal(0x1234UL, appDomain);
        Assert.False(target.TryGetGlobalPointer("StringMethodTable", out _));        // index 10, absent
    }

    // ---- field reads through published offsets ---------------------------------------

    [Fact]
    public void TryReadField_UsesThePublishedOffset()
    {
        // The §12.2 walk in miniature: a MethodTable at a known address, read with
        // nothing hardcoded but the field name.
        const ulong methodTable = 0x0000_7FFD_D134_BF40;
        const uint baseSize = 22;                        // String.BaseSize, §12.2
        const ulong module = 0x0000_7FFD_D100_0000;

        var mt = new byte[64];
        BinaryPrimitives.WriteUInt32LittleEndian(mt.AsSpan(4), baseSize);
        BinaryPrimitives.WriteUInt64LittleEndian(mt.AsSpan(24), module);

        FakeMemory memory = SyntheticDescriptor.BuildTarget().Map(methodTable, mt);
        using (memory)
        {
            RuntimeContractTarget target = Target(memory);

            Assert.True(target.TryReadField(methodTable, "MethodTable", "BaseSize", out uint readBaseSize));
            Assert.Equal(baseSize, readBaseSize);

            Assert.True(target.TryReadFieldPointer(methodTable, "MethodTable", "Module", out ulong readModule));
            Assert.Equal(module, readModule);

            Assert.True(target.TryGetFieldAddress(methodTable, "MethodTable", "Module", out ulong fieldAddress));
            Assert.Equal(methodTable + 24, fieldAddress);
        }
    }

    [Fact]
    public void TryReadField_FailsOnAnUnreadableInstance()
    {
        RuntimeContractTarget target = FixtureTarget();

        Assert.False(target.TryReadField(0xDEAD_0000, "MethodTable", "BaseSize", out uint value));
        Assert.Equal(0u, value);
    }

    [Fact]
    public void TryGetFieldType_ReturnsTheHintOnlyWhenPublished()
    {
        RuntimeContractTarget target = FixtureTarget();

        Assert.True(target.TryGetFieldType("Thread", "GCHandle", out string? hinted));
        Assert.Equal("GCHandle", hinted);

        Assert.True(target.HasField("MethodTable", "Module"));
        Assert.False(target.TryGetFieldType("MethodTable", "Module", out string? unhinted));
        Assert.Null(unhinted);
    }

    // ---- bootstrap -------------------------------------------------------------------

    [Fact]
    public void TryCreate_WalksExportToDescriptorInOneStep()
    {
        // §12.1 as one call: module base → export walk → header → JSON → pointer_data.
        using FakeMemory memory = SyntheticDescriptor.BuildTarget();

        Assert.True(RuntimeContractTarget.TryCreate(memory, SyntheticPe.DefaultImageBase, out RuntimeContractTarget? target));
        Assert.NotNull(target);
        Assert.Same(memory, target.Memory);
        Assert.True(target.TryGetFieldOffset("MethodTable", "Module", out int offset));
        Assert.Equal(24, offset);
    }

    [Fact]
    public void TryCreate_ReturnsFalseForARuntimeWithoutTheDescriptor()
    {
        // .NET 8 and earlier export g_dacTable but not the contract descriptor. Probing
        // such a process is an ordinary outcome, not an error.
        (string Name, uint Rva)[] exports = [.. SyntheticPe.CoreClrExports.Where(e => e.Name != DescriptorLocator.ExportName)];
        using var memory = new FakeMemory().Map(SyntheticPe.DefaultImageBase, SyntheticPe.Build(exports));

        Assert.False(RuntimeContractTarget.TryCreate(memory, SyntheticPe.DefaultImageBase, out RuntimeContractTarget? target));
        Assert.Null(target);
    }

    [Fact]
    public void TryCreate_ReturnsFalseWhenTheModuleBaseIsWrong()
    {
        using FakeMemory memory = SyntheticDescriptor.BuildTarget();

        Assert.False(RuntimeContractTarget.TryCreate(memory, SyntheticPe.DefaultImageBase + 0x1000, out _));
    }
}
