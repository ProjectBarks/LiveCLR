namespace LiveClr.Snapshots;

using LiveClr.Memory;
using LiveClr.Runtime;

/// <summary>
/// One unit of consistency: a frozen-enough view of the target, and every managed handle read
/// through it.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why the snapshot owns the reader.</b> §4.7's page cache is not a performance tweak — §6.4
/// calls it "the structural fix" for §12.4e's silent tearing, because a pointer and its target
/// then come from the same moment instead of from dozens of independent reads across a
/// mutating heap. That guarantee is exactly as long-lived as the cache, so the cache is created
/// with the snapshot and dies with it. §8.8 puts it in the snapshot tier for the same reason.
/// </para>
/// <para>
/// <b>Why handles die with it.</b> §7b.1 measured a singleton at two different managed
/// addresses minutes apart; a compacting GC had moved it. An address that outlives its snapshot
/// does not become invalid in a detectable way, it becomes a different object. Disposing the
/// snapshot makes every handle it produced inert, which turns that finding into behaviour
/// rather than a comment.
/// </para>
/// <para>
/// <b>Roots are re-resolved, not remembered.</b> There is deliberately no way to carry an
/// object from one snapshot into the next. §7b.1: "re-resolve from the static each snapshot;
/// resolution is cheap, a stale pointer is silently wrong."
/// </para>
/// </remarks>
public sealed class LiveSnapshot : ISnapshot, ISnapshotContext
{
    private readonly CountingMemoryReader _reader;
    private bool _disposed;

    internal LiveSnapshot(
        SnapshotMode mode,
        IMemoryReader reader,
        bool ownsReader,
        ClrTypeSystem typeSystem,
        IClrStaticRootSource staticRoots)
    {
        Mode = mode;
        Validator = new SnapshotValidator();
        _reader = new CountingMemoryReader(reader, Validator, ownsReader);
        TypeSystem = typeSystem;
        StaticRoots = staticRoots;
    }

    /// <inheritdoc/>
    public SnapshotMode Mode { get; }

    /// <summary>The tallies behind <see cref="Validate"/>. Exposed so a walk can report into it.</summary>
    public SnapshotValidator Validator { get; }

    /// <summary>The snapshot's reader. Counting, over a page cache or a PSS clone.</summary>
    public IMemoryReader Memory => _reader;

    /// <summary>Process-tier type system this snapshot resolves through.</summary>
    public ClrTypeSystem TypeSystem { get; }

    /// <inheritdoc cref="ISnapshotContext.StaticRoots"/>
    public IClrStaticRootSource StaticRoots { get; }

    /// <inheritdoc cref="ISnapshotContext.IsDisposed"/>
    public bool IsDisposed => _disposed;

    /// <inheritdoc/>
    /// <remarks>
    /// Searches the modules the type system knows about. A module is known once anything in it
    /// has been resolved, or once it has been registered explicitly — see
    /// <see cref="ClrTypeSystem.RegisterModule"/> for why the application's own module needs a
    /// seed on .NET 9.
    /// </remarks>
    public IClrType? Type(string fullName)
    {
        if (fullName is null || _disposed) return null;
        return TypeSystem.TryFindType(Memory, fullName, out ClrTypeInfo? info) ? new ClrType(this, info) : null;
    }

    /// <inheritdoc/>
    /// <remarks>
    /// The address is validated as a managed object before anything is built on it: its method
    /// table must round-trip through <c>EEClass</c> and reach a module image (§5.2). A pointer
    /// that is merely plausible is rejected here rather than producing an object with
    /// convincing-looking fields.
    /// </remarks>
    public IClrObject? Object(ulong address)
    {
        if (address == 0 || _disposed) return null;
        return TypeSystem.TryGetTypeOfObject(Memory, address, out ClrTypeInfo? type)
            ? new ClrObject(this, address, type)
            : null;
    }

    /// <summary>
    /// Structural verdict on everything this snapshot has been asked to read so far.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Inspectable, never throwing</b> (§8.8). It is also CUMULATIVE, not a fresh probe: the
    /// anomalies that matter — a <c>List&lt;T&gt;</c> whose <c>_size</c> outran its backing
    /// array, a walk that came up short — are only observable at the moment of the traversal
    /// that hit them, and a validation pass run afterwards over a frozen page cache would see
    /// the same consistent bytes and report nothing. So the traversal reports, and this
    /// collects.
    /// </para>
    /// <para>
    /// A caller's correct use is: build the snapshot, do the walk, call this, and publish the
    /// result only if <see cref="SnapshotHealth.IsUsable"/> — otherwise keep the previous frame.
    /// </para>
    /// </remarks>
    public SnapshotHealth Validate()
    {
        try
        {
            if (_disposed)
            {
                return new SnapshotHealth(false, Validator.FailedReads, Validator.StructuralAnomalies, "snapshot disposed");
            }

            return Validator.ToHealth();
        }
        catch (Exception e)
        {
            // Belt and braces. A validator that throws defeats its own purpose (§8.8), so even
            // an unexpected failure becomes a reported verdict.
            return new SnapshotHealth(false, 0, 1, $"validation failed: {e.Message}");
        }
    }

    /// <summary>Record a structural anomaly found by a caller's own traversal.</summary>
    public void NoteAnomaly(string detail) => Validator.NoteAnomaly(detail);

    /// <summary>
    /// §6.4's agree-twice guard against the PREVIOUS snapshot, reporting into this one.
    /// </summary>
    /// <remarks>
    /// Deliberately cross-snapshot. Sampling the same structure twice within one snapshot
    /// cannot disagree — §4.7's page cache serves both reads the same frozen bytes — so the
    /// only place the guard has any force is between two memory images. See
    /// <see cref="SnapshotValidator.AgreeAcrossSnapshots"/>.
    /// </remarks>
    public bool AgreesWith<T>(
        string label,
        ISnapshot previous,
        Func<ISnapshot, T> sample,
        IEqualityComparer<T>? comparer = null) =>
        Validator.AgreeAcrossSnapshots(label, previous, this, sample, comparer);

    /// <inheritdoc/>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _reader.Dispose();
    }
}
