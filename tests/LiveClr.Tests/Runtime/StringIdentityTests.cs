namespace LiveClr.Tests.Runtime;

using LiveClr.Memory;
using LiveClr.Runtime;

/// <summary>
/// How a live runtime says "this type is <c>System.String</c>" — and how it does not.
/// </summary>
/// <remarks>
/// <para>
/// <c>ClrTypeInfo.IsString</c> originally read <c>EEClass.InternalCorElementType</c> and compared
/// it to <c>ELEMENT_TYPE_STRING</c>. Measured against a live .NET 9 process (§17): that value
/// never appears — 0 of 12,283 loaded method tables carry it, and <c>System.String</c>'s own
/// <c>EEClass</c> reports <c>ELEMENT_TYPE_CLASS</c>. <c>AsString()</c> therefore returned null for
/// every string in every real process while the whole test suite passed, because the fixture wrote
/// the value the code was looking for.
/// </para>
/// <para>
/// These tests exist to make that impossible to reintroduce quietly. The fixture now writes the
/// measured norm type by default, so a revert of the production predicate reddens the ordinary
/// string tests, and a revert of the fixture reddens
/// <see cref="TheFixtureWritesTheNormTypeARealRuntimeWrites"/>.
/// </para>
/// </remarks>
public sealed class StringIdentityTests
{
    [Fact]
    public void TheFixtureWritesTheNormTypeARealRuntimeWrites()
    {
        using SyntheticClrTarget target = SyntheticClrTarget.Build();
        using LiveProcess process = target.Attach();

        Assert.True(process.TypeSystem.TryFindType(process.Memory, "System.String", out ClrTypeInfo? stringType));

        // The measured value, pinned as a constant rather than derived from anything the
        // production code does with it (§13.11 #3: a self-derived expectation cannot fail).
        Assert.Equal(ClrElementType.Class, stringType.ElementType);
        Assert.Equal(0x12, (byte)stringType.ElementType);

        // And the other half of what the live method table reports about String: a component
        // size of 2 with the has-component-size bit set, i.e. MTFlags 0x80000002.
        Assert.Equal(2, stringType.ComponentSize);
        Assert.True(process.Memory.TryRead<uint>(
            stringType.MethodTable + (ulong)process.Layouts.MethodTableFlagsOffset, out uint flags));
        Assert.Equal(0x8000_0002u, flags);
    }

    [Fact]
    public void StringIdentityComesFromThePublishedGlobalRatherThanTheElementType()
    {
        using SyntheticClrTarget target = SyntheticClrTarget.Build();
        using LiveProcess process = target.Attach();

        Assert.True(process.TypeSystem.StringIdentityIsPublished);
        Assert.True(process.TypeSystem.TryFindType(process.Memory, "System.String", out ClrTypeInfo? stringType));
        Assert.Equal(stringType.MethodTable, process.TypeSystem.StringMethodTable);
        Assert.True(stringType.IsString);

        // Nothing else in the target is a string, including the type whose EEClass says CLASS
        // just as String's does.
        Assert.True(process.TypeSystem.TryGetType(process.Memory, target.DerivedMethodTable, out ClrTypeInfo? derived));
        Assert.False(derived.IsString);
    }

    [Fact]
    public void ATypeThatClaimsElementTypeStringIsNotDecodedAsAString()
    {
        // The hostile inverse of the original bug: a live object whose EEClass says
        // ELEMENT_TYPE_STRING. Believing that reads its first fields as a length and a run of
        // characters — a fabricated string rather than a refusal.
        using SyntheticClrTarget target = SyntheticClrTarget.Build(
            new SyntheticTargetOptions { ImpersonateStringElementType = true });
        using LiveProcess process = target.Attach(new LiveProcessOptions { StaticRoots = target.StaticRoots() });
        using ISnapshot snapshot = process.BeginSnapshot();

        IClrObject impostor = snapshot.Object(target.DerivedAddress)!;
        Assert.True(process.TypeSystem.TryGetType(process.Memory, impostor.Type.MethodTable, out ClrTypeInfo? info));

        Assert.Equal(ClrElementType.String, info.ElementType);
        Assert.False(info.IsString);

        // Reached as a value, the impostor is still an object and still not a string.
        IClrObject second = snapshot.Object(target.DerivedAddress)!;
        IClrValue link = second.Field(nameof(FixtureDerived.Link))!;
        Assert.Null(link.AsString());

        // The real string next to it still decodes, so this is not "strings stopped working".
        Assert.Equal(SyntheticClrTarget.ExpectedName, impostor.Field(nameof(FixtureDerived.Name))!.AsString());
    }

    [Fact]
    public void StringsStillDecodeOnARuntimeThatPublishesNoStringMethodTable()
    {
        // §5.5: descriptor coverage is a goal, not a guarantee. With the global gone, identity
        // falls back to two independent signals — the ECMA-335 name and the MTFlags stride —
        // and the fallback is exercised here rather than asserted about.
        using SyntheticClrTarget target = SyntheticClrTarget.Build(new SyntheticTargetOptions
        {
            OmitDescriptorEntries = ["globals.StringMethodTable"],
        });

        using LiveProcess process = target.Attach(new LiveProcessOptions { StaticRoots = target.StaticRoots() });
        using ISnapshot snapshot = process.BeginSnapshot();

        Assert.False(process.TypeSystem.StringIdentityIsPublished);
        Assert.Equal(0UL, process.TypeSystem.StringMethodTable);

        IClrObject derived = snapshot.Object(target.DerivedAddress)!;
        Assert.Equal(SyntheticClrTarget.ExpectedName, derived.Field(nameof(FixtureDerived.Name))!.AsString());

        // The honest cost of the missing global, stated rather than hidden: the component-size
        // encoding can no longer be checked against String's published method table, so arrays
        // degrade to unreadable.
        Assert.False(process.TypeSystem.ComponentSizeIsTrusted);
    }

    [Fact]
    public void TheFallbackRefusesATypeThatOnlyLooksLikeAString()
    {
        // Same runtime as above — no published global — but the corroboration must still be two
        // signals: a type named System.String whose stride is wrong is not a string.
        using SyntheticClrTarget target = SyntheticClrTarget.Build(new SyntheticTargetOptions
        {
            OmitDescriptorEntries = ["globals.StringMethodTable"],
            BreakComponentSizeEncoding = true,
        });

        using LiveProcess process = target.Attach(new LiveProcessOptions { StaticRoots = target.StaticRoots() });
        using ISnapshot snapshot = process.BeginSnapshot();

        Assert.True(process.TypeSystem.TryFindType(process.Memory, "System.String", out ClrTypeInfo? stringType));
        Assert.Equal(3, stringType.ComponentSize);
        Assert.False(stringType.IsString);

        IClrObject derived = snapshot.Object(target.DerivedAddress)!;
        Assert.Null(derived.Field(nameof(FixtureDerived.Name))!.AsString());
    }

    [Fact]
    public void GenericInstantiationsAreNotNamedOnALiveShapedTarget()
    {
        // NOT a fix — a pin on a defect of the same species as the string one, measured on the
        // same process (§17). A live List<T> instance's method table resolves to no TypeDef row,
        // so the name-prefix IsList is false and AsList() refuses. 9 of 9 slots whose signature
        // declared List<T> behaved exactly like this live. The fixture's default shape hides it
        // by pointing the instantiation at the mapped typical instantiation, which no runtime
        // does.
        using SyntheticClrTarget target = SyntheticClrTarget.Build(
            new SyntheticTargetOptions { SharedCanonicalInstantiation = true });
        using LiveProcess process = target.Attach(new LiveProcessOptions { StaticRoots = target.StaticRoots() });
        using ISnapshot snapshot = process.BeginSnapshot();

        IClrObject holder = snapshot.Object(target.HolderAddress)!;
        IClrValue items = holder.Field(nameof(FixtureHolder.Items))!;

        IClrObject list = items.AsObject()!;
        Assert.StartsWith("<mt:0x", list.Type.Name, StringComparison.Ordinal);
        Assert.False(process.TypeSystem.TryGetType(process.Memory, list.Type.MethodTable, out ClrTypeInfo? info) && info.IsList);

        // Refusal, not fabrication: nothing is reported as an empty list either.
        Assert.Null(items.AsList());

        // The same holder on the fixture's default shape does produce a list, so this test is
        // measuring the SHAPE and not simply a broken fixture.
        using SyntheticClrTarget mapped = SyntheticClrTarget.Build();
        using LiveProcess mappedProcess = mapped.Attach(new LiveProcessOptions { StaticRoots = mapped.StaticRoots() });
        using ISnapshot mappedSnapshot = mappedProcess.BeginSnapshot();

        IClrList? decoded = mappedSnapshot.Object(mapped.HolderAddress)!.Field(nameof(FixtureHolder.Items))!.AsList();
        Assert.NotNull(decoded);
    }
}
