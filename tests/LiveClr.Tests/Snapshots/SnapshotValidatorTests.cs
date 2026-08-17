namespace LiveClr.Tests.Snapshots;

using LiveClr.Snapshots;
using LiveClr.Tests.Runtime;

/// <summary>
/// The §12.4e class: a traversal that comes up short while every individual read succeeds.
/// </summary>
/// <remarks>
/// This is the finding §6.4 calls "the single most important implementation finding in the
/// document", and the reason <c>SnapshotHealth</c> separates <c>FailedReads</c> from
/// <c>StructuralAnomalies</c>. The tests below assert both halves of the required behaviour:
/// the anomaly is REPORTED, and reporting it does not throw — §8.8, because an overlay's
/// correct response to a suspect snapshot is to reuse the last good one, which a throwing
/// validator makes impossible.
/// </remarks>
public sealed class SnapshotValidatorTests : IDisposable
{
    private readonly SyntheticClrTarget _target = SyntheticClrTarget.Build();
    private readonly LiveProcess _process;

    public SnapshotValidatorTests() => _process = _target.Attach();

    public void Dispose()
    {
        _process.Dispose();
        _target.Dispose();
    }

    [Fact]
    public void AHealthyTraversalReportsOk()
    {
        using ISnapshot snapshot = _process.BeginSnapshot();

        IClrObject holder = snapshot.Object(_target.HolderAddress)!;
        Assert.Equal(SyntheticClrTarget.ListCount, holder.Field(nameof(FixtureHolder.Items))!.AsList()!.Count);

        SnapshotHealth health = snapshot.Validate();

        Assert.True(health.IsUsable);
        Assert.Equal(0, health.StructuralAnomalies);
        Assert.Equal(0, health.FailedReads);
    }

    [Fact]
    public void ATruncatedTraversalIsReportedAsAStructuralAnomalyAndDoesNotThrow()
    {
        using ISnapshot snapshot = _process.BeginSnapshot();

        IClrObject torn = snapshot.Object(_target.TornHolderAddress)!;

        // _size says 5, the backing array holds 4. Both fields read cleanly — this is exactly
        // §12.4e's shape, and read-level retry cannot see it.
        IClrList list = torn.Field(nameof(FixtureHolder.Items))!.AsList()!;

        Assert.Equal(SyntheticClrTarget.ListCapacity, list.Count);

        SnapshotHealth health = snapshot.Validate();

        Assert.False(health.IsUsable);
        Assert.Equal(1, health.StructuralAnomalies);
        Assert.Equal(0, health.FailedReads);
        Assert.Contains("§12.4e", health.Detail!, StringComparison.Ordinal);
        Assert.Contains($"_size={SyntheticClrTarget.TornListSize}", health.Detail!, StringComparison.Ordinal);
    }

    [Fact]
    public void ValidateIsInspectableAndNeverThrows()
    {
        ISnapshot snapshot = _process.BeginSnapshot();
        snapshot.Object(_target.TornHolderAddress)!.Field(nameof(FixtureHolder.Items))!.AsList();

        SnapshotHealth beforeDispose = snapshot.Validate();
        snapshot.Dispose();
        SnapshotHealth afterDispose = snapshot.Validate();

        // Both calls return a verdict. Neither throws — the property §8.8 makes non-negotiable.
        Assert.False(beforeDispose.IsUsable);
        Assert.False(afterDispose.IsUsable);
        Assert.Equal(1, afterDispose.StructuralAnomalies);
    }

    [Fact]
    public void FailedReadsAreCountedSeparatelyFromStructuralAnomalies()
    {
        using var snapshot = (LiveSnapshot)_process.BeginSnapshot();

        // An unmapped address: the §4.8 retryable class.
        Assert.Null(snapshot.Object(0x0000_7000_0000_0000));

        SnapshotHealth health = snapshot.Validate();

        Assert.True(health.FailedReads > 0);
        Assert.Equal(0, health.StructuralAnomalies);

        // Read failures alone do not condemn a snapshot: probing a pointer that turns out not
        // to be an object is a normal part of validating one (§4.8, §6.4).
        Assert.True(health.IsUsable);
    }

    [Fact]
    public void BoundedWalkFlagsAShortTraversal()
    {
        var validator = new SnapshotValidator();

        Assert.True(validator.CheckWalk("scene tree", expected: 2306, actual: 2306));
        Assert.False(validator.CheckWalk("scene tree", expected: 2306, actual: 2296));

        SnapshotHealth health = validator.ToHealth();

        Assert.False(health.IsUsable);
        Assert.Equal(1, health.StructuralAnomalies);
        Assert.Contains("2296 of 2306", health.Detail!, StringComparison.Ordinal);
    }

    [Fact]
    public void AgreeAcrossSnapshotsFiresWhenTheTargetChangedBetweenImages()
    {
        // A real mutation between two real memory images — the only situation in which
        // agree-twice can say anything, since §4.7's page cache makes two samples within one
        // snapshot identical by construction.
        using var overlay = new MutableMemoryOverlay(_target.Memory);
        using LiveProcess process = LiveProcess.Create(0, overlay, ownsMemory: false, _target.Modules, _target.CoreClr);

        ulong holder = _target.HolderAddress;
        int ItemCount(ISnapshot s) => s.Object(holder)!.Field(nameof(FixtureHolder.Items))!.AsList()!.Count;

        using ISnapshot first = process.BeginSnapshot();
        Assert.Equal(SyntheticClrTarget.ListCount, ItemCount(first));

        using (var unchanged = (LiveSnapshot)process.BeginSnapshot())
        {
            Assert.True(unchanged.AgreesWith("holder items", first, ItemCount));
            Assert.True(unchanged.Validate().IsUsable);
        }

        overlay.WriteI32(_target.ListSizeSlot, 1);

        using var changed = (LiveSnapshot)process.BeginSnapshot();

        Assert.False(changed.AgreesWith("holder items", first, ItemCount));
        Assert.Equal(1, changed.Validate().StructuralAnomalies);
        Assert.Contains("§6.4", changed.Validate().Detail!, StringComparison.Ordinal);
    }

    [Fact]
    public void AgreeAcrossSnapshotsRefusesToCompareASnapshotWithItself()
    {
        // The guard that cannot fire: comparing one snapshot to itself always agrees, so it is
        // reported as an anomaly instead of returning a meaningless true.
        using var snapshot = (LiveSnapshot)_process.BeginSnapshot();

        Assert.False(snapshot.AgreesWith("self", snapshot, s => s.Object(_target.HolderAddress)?.Address ?? 0));
        Assert.Equal(1, snapshot.Validate().StructuralAnomalies);
        Assert.Contains("§4.7", snapshot.Validate().Detail!, StringComparison.Ordinal);
    }

    [Fact]
    public void AnomalyDetailsAreRetainedButBounded()
    {
        var validator = new SnapshotValidator();
        for (int i = 0; i < 100; i++) validator.NoteAnomaly($"anomaly {i}");

        Assert.Equal(100, validator.StructuralAnomalies);
        Assert.Equal(32, validator.Anomalies.Count);
    }
}
