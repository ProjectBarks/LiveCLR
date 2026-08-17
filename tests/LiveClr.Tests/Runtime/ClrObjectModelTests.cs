namespace LiveClr.Tests.Runtime;

using LiveClr.Memory;
using LiveClr.Runtime;

/// <summary>
/// The §12.4d route end to end against a CLR-shaped heap: object → method table → module →
/// metadata → names, then names → runtime field offsets → values.
/// </summary>
public sealed class ClrObjectModelTests : IDisposable
{
    private readonly SyntheticClrTarget _target = SyntheticClrTarget.Build();
    private readonly LiveProcess _process;

    public ClrObjectModelTests() =>
        _process = _target.Attach(new LiveProcessOptions { StaticRoots = _target.StaticRoots() });

    public void Dispose()
    {
        _process.Dispose();
        _target.Dispose();
    }

    [Fact]
    public void ResolvesAnObjectsTypeNameThroughItsMethodTable()
    {
        using ISnapshot snapshot = _process.BeginSnapshot();

        IClrObject? derived = snapshot.Object(_target.DerivedAddress);

        Assert.NotNull(derived);
        Assert.Equal(typeof(FixtureDerived).FullName, derived.Type.Name);
        Assert.Equal(_target.DerivedMethodTable, derived.Type.MethodTable);
    }

    [Fact]
    public void WalksInheritanceThroughParentMethodTable()
    {
        using ISnapshot snapshot = _process.BeginSnapshot();
        IClrObject derived = snapshot.Object(_target.DerivedAddress)!;

        // §5.2's MethodTable.ParentMethodTable (16), not the metadata Extends row: §12.2
        // verified the runtime chain live, and it is the one that survives generics.
        IClrType? baseType = derived.Type.BaseType;

        Assert.NotNull(baseType);
        Assert.Equal(typeof(FixtureBase).FullName, baseType.Name);
        Assert.Equal("System.Object", baseType.BaseType?.Name);
        Assert.Null(baseType.BaseType?.BaseType);
    }

    [Fact]
    public void ReadsAFieldDeclaredOnABaseClass()
    {
        using ISnapshot snapshot = _process.BeginSnapshot();
        IClrObject derived = snapshot.Object(_target.DerivedAddress)!;

        Assert.Equal(61, derived.Field(nameof(FixtureBase.Hp))!.Read<int>());
        Assert.True(derived.Type.HasField(nameof(FixtureBase.Hp)));
        Assert.Contains(nameof(FixtureBase.Hp), derived.Type.FieldNames);
        Assert.Contains(nameof(FixtureDerived.Name), derived.Type.FieldNames);
    }

    [Fact]
    public void DecodesAString()
    {
        using ISnapshot snapshot = _process.BeginSnapshot();
        IClrObject derived = snapshot.Object(_target.DerivedAddress)!;

        Assert.Equal(SyntheticClrTarget.ExpectedName, derived.Field(nameof(FixtureDerived.Name))!.AsString());
    }

    [Fact]
    public void FollowsAReferenceFieldToAnotherObject()
    {
        using ISnapshot snapshot = _process.BeginSnapshot();
        IClrObject derived = snapshot.Object(_target.DerivedAddress)!;

        // The first element's Link is null; the second element links back to it.
        Assert.True(derived.Field(nameof(FixtureDerived.Link))!.IsNull);
        Assert.Null(derived.Field(nameof(FixtureDerived.Link))!.AsObject());

        IClrObject holder = snapshot.Object(_target.HolderAddress)!;
        IClrObject second = holder.Field(nameof(FixtureHolder.Items))!.AsList()![1].AsObject()!;
        IClrObject? linked = second.Field(nameof(FixtureDerived.Link))!.AsObject();

        Assert.NotNull(linked);
        Assert.Equal(_target.DerivedAddress, linked.Address);
        Assert.Equal(61, linked.Field(nameof(FixtureBase.Hp))!.Read<int>());
    }

    [Fact]
    public void ListCountComesFromSizeNotFromBackingArrayLength()
    {
        using ISnapshot snapshot = _process.BeginSnapshot();
        IClrObject holder = snapshot.Object(_target.HolderAddress)!;

        var list = (ClrList)holder.Field(nameof(FixtureHolder.Items))!.AsList()!;

        // §12.4, API fact 2. Using _items.Length here would report 4 and hand back a stale
        // entry at index 2 as if it were live data.
        Assert.Equal(SyntheticClrTarget.ListCount, list.Count);
        Assert.Equal(SyntheticClrTarget.ListCapacity, list.Capacity);

        Assert.Equal(61, list[0].AsObject()!.Field(nameof(FixtureBase.Hp))!.Read<int>());
        Assert.Equal(66, list[1].AsObject()!.Field(nameof(FixtureBase.Hp))!.Read<int>());

        // Index 2 exists in the backing array and is deliberately not reachable.
        Assert.True(list[2].IsNull);
        Assert.Null(list[2].AsObject());
    }

    [Fact]
    public void ListDetectsTheGenericInstantiationThroughTheCanonicalMethodTable()
    {
        using ISnapshot snapshot = _process.BeginSnapshot();
        IClrObject holder = snapshot.Object(_target.HolderAddress)!;

        IClrObject list = holder.Field(nameof(FixtureHolder.Items))!.AsObject()!;

        // §12.4b's probe bug: List`1 HAS a class name, so "has a name ⇒ treat as an object"
        // reports every collection as empty. The name must be matched explicitly.
        Assert.StartsWith("System.Collections.Generic.List`1", list.Type.Name, StringComparison.Ordinal);
        Assert.NotNull(holder.Field(nameof(FixtureHolder.Items))!.AsList());
    }

    [Fact]
    public void ReadsAPrimitiveArray()
    {
        using ISnapshot snapshot = _process.BeginSnapshot();
        IClrObject holder = snapshot.Object(_target.HolderAddress)!;

        var numbers = (ClrArray)holder.Field(nameof(FixtureHolder.Numbers))!.AsArray()!;

        Assert.Equal(3, numbers.Count);
        Assert.Equal(3, numbers[0].Read<int>());
        Assert.Equal(1, numbers[1].Read<int>());
        Assert.Equal(4, numbers[2].Read<int>());

        // Out of range degrades rather than throwing (§5.5).
        //
        // IsNull, not Read<int>() == 0, and the two indices are chosen rather than arbitrary.
        // A zero-valued read is exactly what an UNGUARDED index returns from mapped-but-empty
        // bytes, so asserting one left the bounds check deletable (§13.11). Both slots below
        // are mapped and hold NON-zero bytes, which is what makes "null" attributable to the
        // bound rather than to the contents.
        ulong first = numbers.Address + 16;

        // -1 straddles m_NumComponents and element 0: unguarded it decodes as 0x3_00000000.
        Assert.True(_target.Memory.TryRead(first - 4, out ulong beforeStart) && beforeStart != 0);
        Assert.True(numbers[-1].IsNull);
        Assert.Null(numbers[-1].AsObject());

        // 4 is one past the end, where the fixture's next allocation begins.
        Assert.True(_target.Memory.TryRead(first + (4 * 4), out ulong pastEnd) && pastEnd != 0);
        Assert.True(numbers[4].IsNull);
        Assert.True(numbers[7].IsNull);
    }

    [Fact]
    public void ResolvesATypeByNameOnceItsModuleIsKnown()
    {
        using ISnapshot cold = _process.BeginSnapshot();

        // The application module is not reachable from the descriptor alone (§5.5), so before
        // anything in it has been touched the name does not resolve...
        Assert.Null(cold.Type(typeof(FixtureDerived).FullName!));

        // ...and resolving one object registers it, which is §5.5's "go upward from any known
        // managed object".
        Assert.NotNull(cold.Object(_target.DerivedAddress));

        IClrType? type = cold.Type(typeof(FixtureDerived).FullName!);
        Assert.NotNull(type);
        Assert.Equal(_target.DerivedMethodTable, type.MethodTable);
    }

    [Fact]
    public void ResolvesAStaticRootAndTheGraphBelowIt()
    {
        _process.RegisterManagedModule(_target.AppModulePointer);
        using ISnapshot snapshot = _process.BeginSnapshot();

        // §8.8's API invariant, in the shape a consumer writes it.
        IClrObject? holder = snapshot
            .Type(typeof(FixtureHolder).FullName!)!
            .Static(nameof(FixtureHolder.Instance))!
            .AsObject();

        Assert.NotNull(holder);
        Assert.Equal(_target.HolderAddress, holder.Address);
        Assert.Equal(SyntheticClrTarget.ListCount, holder.Field(nameof(FixtureHolder.Items))!.AsList()!.Count);
    }

    [Fact]
    public void RejectsAnAddressThatIsNotAManagedObject()
    {
        using ISnapshot snapshot = _process.BeginSnapshot();

        Assert.Null(snapshot.Object(0));
        Assert.Null(snapshot.Object(_target.DerivedAddress + 3));   // unaligned
        Assert.Null(snapshot.Object(0xDEAD_BEEF_0000_0000));        // unmapped

        // The case the other three cannot reach: mapped, aligned, and its first word IS a
        // pointer — just not one that round-trips through EEClass. Zero, an odd address and
        // an unmapped address are all refused before the method-table validation runs at all,
        // so without this the §5.2 round-trip is unexercised (§13.11).
        Assert.True(_target.Memory.TryRead(_target.HolderAddress + 8, out ulong itemsPointer));
        Assert.NotEqual(0UL, itemsPointer);
        Assert.Null(snapshot.Object(_target.HolderAddress + 8));
    }

    /// <summary>
    /// §7b.2's precedence policy, applied to CLR field offsets: a runtime that can answer is
    /// always believed over a hand-maintained profile.
    /// </summary>
    /// <remarks>
    /// The profile deliberately DISAGREES, and disagrees implausibly. Attaching with no
    /// <c>FieldLayout</c> at all — as this test used to — leaves <c>Runtime</c> the only
    /// obtainable value, so inverting the composite to "profile beats runtime" left the whole
    /// suite green. A precedence test needs two sources that both have an answer (§13.11).
    /// </remarks>
    [Fact]
    public void FieldOffsetsComeFromTheRuntimeNotFromAProfile()
    {
        var profile = new ExplicitFieldLayoutSource()
            .Add(typeof(FixtureDerived).FullName!, nameof(FixtureDerived.Name), 999)
            .Add(typeof(FixtureDerived).FullName!, nameof(FixtureDerived.ProfiledOnly), 40);

        using LiveProcess process = _target.Attach(new LiveProcessOptions
        {
            StaticRoots = _target.StaticRoots(),
            FieldLayout = profile,
        });

        using ISnapshot snapshot = process.BeginSnapshot();
        var derived = (ClrObject)snapshot.Object(_target.DerivedAddress)!;

        Assert.True(derived.TryGetFieldLocation(nameof(FixtureDerived.Name), out ClrFieldLocation location));
        Assert.Equal(FieldOffsetSource.Runtime, location.Source);
        Assert.Equal(16, location.Offset);

        // And the value read through it is the real one, not whatever sits at the profile's
        // offset — the offset is the mechanism, the string is the consequence.
        Assert.Equal(SyntheticClrTarget.ExpectedName, derived.Field(nameof(FixtureDerived.Name))!.AsString());

        // The profile is not being ignored: for the one field the fixture gives no FieldDesc,
        // it is the only source with an answer and it supplies one. So the ordering above is a
        // contest between two live sources, not a walkover.
        Assert.True(derived.TryGetFieldLocation(nameof(FixtureDerived.ProfiledOnly), out ClrFieldLocation profiled));
        Assert.Equal(FieldOffsetSource.Explicit, profiled.Source);
        Assert.Equal(40, profiled.Offset);
    }

    [Fact]
    public void UnknownNamesDegradeToNullRatherThanThrowing()
    {
        using ISnapshot snapshot = _process.BeginSnapshot();
        IClrObject derived = snapshot.Object(_target.DerivedAddress)!;

        Assert.Null(snapshot.Type("No.Such.Type"));
        Assert.Null(derived.Field("NoSuchField"));
        Assert.False(derived.Type.HasField("NoSuchField"));
        Assert.Null(derived.Type.Static("NoSuchStatic"));
        Assert.Null(derived.Field(nameof(FixtureBase.Hp))!.AsObject());
        Assert.Null(derived.Field(nameof(FixtureBase.Hp))!.AsString());
    }
}
