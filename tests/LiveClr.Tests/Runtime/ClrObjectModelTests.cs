namespace LiveClr.Tests.Runtime;

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

        IClrArray? numbers = holder.Field(nameof(FixtureHolder.Numbers))!.AsArray();

        Assert.NotNull(numbers);
        Assert.Equal(3, numbers.Count);
        Assert.Equal(3, numbers[0].Read<int>());
        Assert.Equal(1, numbers[1].Read<int>());
        Assert.Equal(4, numbers[2].Read<int>());

        // Out of range degrades rather than throwing (§5.5).
        Assert.True(numbers[7].IsNull);
        Assert.Equal(0, numbers[-1].Read<int>());
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
        Assert.Null(snapshot.Object(_target.DerivedAddress + 3));
        Assert.Null(snapshot.Object(0xDEAD_BEEF_0000_0000));
    }

    [Fact]
    public void FieldOffsetsComeFromTheRuntimeNotFromAProfile()
    {
        using ISnapshot snapshot = _process.BeginSnapshot();
        var derived = (ClrObject)snapshot.Object(_target.DerivedAddress)!;

        Assert.True(derived.TryGetFieldLocation(nameof(FixtureDerived.Name), out ClrFieldLocation location));
        Assert.Equal(FieldOffsetSource.Runtime, location.Source);
        Assert.Equal(16, location.Offset);
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
