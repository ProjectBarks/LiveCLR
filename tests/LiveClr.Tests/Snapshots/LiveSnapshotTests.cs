namespace LiveClr.Tests.Snapshots;

using LiveClr.Runtime;
using LiveClr.Snapshots;
using LiveClr.Tests.Runtime;

/// <summary>
/// Snapshot lifetime and the §8.8 API invariant: everything semantic hangs off a snapshot, and
/// nothing outlives one.
/// </summary>
public sealed class LiveSnapshotTests : IDisposable
{
    private readonly SyntheticClrTarget _target = SyntheticClrTarget.Build();
    private readonly LiveProcess _process;

    public LiveSnapshotTests() =>
        _process = _target.Attach(new LiveProcessOptions { StaticRoots = _target.StaticRoots() });

    public void Dispose()
    {
        _process.Dispose();
        _target.Dispose();
    }

    [Fact]
    public void AttachExposesModulesAndTheDescriptorWithoutAnySemanticReadApi()
    {
        Assert.Contains("coreclr", _process.ModuleNames);
        Assert.Contains("LiveClr.Tests", _process.ModuleNames);
        Assert.Equal(0, _process.Runtime.DescriptorVersion);

        // §8.8: the invariant is that ILiveProcess has no way to read an object. If one is
        // ever added, this fails and the reviewer is pointed at §7b.1 and §12.4e.
        Type contract = typeof(ILiveProcess);
        Assert.Empty(Array.FindAll(
            contract.GetMethods(),
            m => m.Name is "ReadObject" or "Object" or "Field" or "GetField" or "Read"));
    }

    [Fact]
    public void HandlesGoInertWhenTheirSnapshotIsDisposed()
    {
        ISnapshot snapshot = _process.BeginSnapshot();
        IClrObject derived = snapshot.Object(_target.DerivedAddress)!;

        Assert.Equal(61, derived.Field(nameof(FixtureBase.Hp))!.Read<int>());

        snapshot.Dispose();

        // §7b.1: a managed address that outlives its snapshot does not become invalid, it
        // becomes a different object. Disposal makes that unreachable rather than wrong.
        Assert.Null(derived.Field(nameof(FixtureBase.Hp)));
        Assert.Null(derived.Type.BaseType);
        Assert.Empty(derived.Type.FieldNames);
        Assert.False(snapshot.Validate().IsUsable);
    }

    [Fact]
    public void EachSnapshotReResolvesRootsRatherThanReusingAnAddress()
    {
        _process.RegisterManagedModule(_target.AppModulePointer);

        using (ISnapshot first = _process.BeginSnapshot())
        {
            Assert.Equal(_target.HolderAddress, Root(first).Address);
        }

        using ISnapshot second = _process.BeginSnapshot();
        Assert.Equal(_target.HolderAddress, Root(second).Address);

        static IClrObject Root(ISnapshot snapshot) =>
            snapshot.Type(typeof(FixtureHolder).FullName!)!.Static(nameof(FixtureHolder.Instance))!.AsObject()!;
    }

    [Fact]
    public void APageCacheGivesOneTraversalOneMemoryImage()
    {
        // §4.7 / §6.4: the snapshot's reader is a cache, not the raw process reader, so a
        // pointer and its target come from the same moment.
        using var snapshot = (LiveSnapshot)_process.BeginSnapshot();

        Assert.NotSame(_process.Memory, snapshot.Memory);
        Assert.Equal(SnapshotMode.LiveValidated, snapshot.Mode);

        IClrObject holder = snapshot.Object(_target.HolderAddress)!;
        Assert.Equal(SyntheticClrTarget.ListCount, holder.Field(nameof(FixtureHolder.Items))!.AsList()!.Count);
        Assert.True(snapshot.Validate().IsUsable);
    }

    [Fact]
    public void MethodTableToTypeMappingIsCachedAcrossSnapshots()
    {
        // §8.8's lifetime tiers: MethodTable → ClrType is process tier because §7b.1 measured
        // method-table addresses stable; only managed addresses are snapshot tier.
        ClrTypeInfo first;
        ClrTypeInfo second;

        using (ISnapshot a = _process.BeginSnapshot())
        {
            first = ((ClrObject)a.Object(_target.DerivedAddress)!).TypeInfo;
        }

        using (ISnapshot b = _process.BeginSnapshot())
        {
            second = ((ClrObject)b.Object(_target.DerivedAddress)!).TypeInfo;
        }

        Assert.Same(first, second);
    }

    [Fact]
    public void ProcessSnapshotModeIsRefusedRatherThanFakedForANonLiveTarget()
    {
        Assert.Throws<NotSupportedException>(() => _process.BeginSnapshot(SnapshotMode.ProcessSnapshot));
    }
}
