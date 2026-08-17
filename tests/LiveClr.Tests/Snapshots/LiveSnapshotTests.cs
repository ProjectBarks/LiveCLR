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

    /// <summary>
    /// §4.7 / §6.4: the snapshot's reader is a cache, not the raw process reader, so a pointer
    /// and its target come from the same moment.
    /// </summary>
    /// <remarks>
    /// Measured as CACHING, not as identity. <c>Assert.NotSame(process.Memory, snapshot.Memory)</c>
    /// is satisfied by the <c>CountingMemoryReader</c> that wraps every snapshot regardless, so
    /// replacing <c>new PageCache(Memory, ...)</c> with the bare reader failed exactly one test
    /// in the suite — and not this one (§13.11). What only a cache can do is serve the second
    /// traversal without touching the target.
    /// </remarks>
    [Fact]
    public void APageCacheGivesOneTraversalOneMemoryImage()
    {
        using var counting = new CountingMemory(_target.Memory);
        using LiveProcess process = LiveProcess.Create(
            0,
            counting,
            ownsMemory: false,
            _target.Modules,
            _target.CoreClr,
            new LiveProcessOptions { StaticRoots = _target.StaticRoots() });

        using var snapshot = (LiveSnapshot)process.BeginSnapshot();

        Assert.NotSame(process.Memory, snapshot.Memory);
        Assert.Equal(SnapshotMode.LiveValidated, snapshot.Mode);

        int start = counting.Reads;
        Assert.Equal(SyntheticClrTarget.ListCount, Walk(snapshot));
        int firstWalk = counting.Reads - start;
        Assert.True(firstWalk > 0, "the first traversal must reach the target at all");

        // The identical walk again, inside the SAME snapshot. Every byte it needs is already
        // in the cache, so nothing reaches the target.
        Assert.Equal(SyntheticClrTarget.ListCount, Walk(snapshot));
        Assert.Equal(firstWalk, counting.Reads - start);

        Assert.True(snapshot.Validate().IsUsable);

        // A NEW snapshot gets a new cache, because §8.8 puts the cache in the snapshot tier: a
        // long-lived one keeps serving a moment that has passed without being able to tell.
        using var second = (LiveSnapshot)process.BeginSnapshot();
        int beforeSecond = counting.Reads;
        Assert.Equal(SyntheticClrTarget.ListCount, Walk(second));
        Assert.True(counting.Reads > beforeSecond, "a fresh snapshot must re-read rather than inherit a cache");

        int Walk(ISnapshot s) =>
            s.Object(_target.HolderAddress)!.Field(nameof(FixtureHolder.Items))!.AsList()!.Count;
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
