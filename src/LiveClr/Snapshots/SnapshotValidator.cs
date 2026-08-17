namespace LiveClr.Snapshots;

using LiveClr.Memory;

/// <summary>
/// Accumulates the two independent ways a snapshot can be wrong, and turns them into a
/// <see cref="SnapshotHealth"/>.
/// </summary>
/// <remarks>
/// <para>
/// <b>The split is the whole point.</b> §4.8's error contract and <c>isTransientRead</c> catch
/// FAILED READS. §12.4e caught something else: a live traversal that returned ten nodes short
/// during a scene-tree splice with <em>every individual read succeeding</em> — no exception, no
/// <c>memory-access-exception</c>, nothing for retry logic to key off. §6.4 calls read-level
/// retry "necessary but NOT sufficient" for exactly this reason. So structural anomalies are
/// counted separately, and they are the ones that decide usability.
/// </para>
/// <para>
/// <b>Read failures do not by themselves make a snapshot unusable.</b> They are the retryable
/// class (§4.8), and some are entirely expected — validating an arbitrary pointer as a method
/// table means probing addresses that are legitimately unmapped. They are reported so a caller
/// can apply its own <c>READ_ATTEMPTS</c> policy, not so it can panic.
/// </para>
/// <para>
/// <b>Nothing here throws.</b> §8.8: "an overlay's correct response to a suspect snapshot is
/// 'reuse the last good one', which is impossible if validation throws."
/// </para>
/// </remarks>
public sealed class SnapshotValidator
{
    /// <summary>Anomaly details are retained up to this many; the count keeps rising past it.</summary>
    private const int MaxRetainedDetails = 32;

    private readonly List<string> _anomalies = [];
    private readonly Lock _gate = new();
    private int _failedReads;
    private int _structuralAnomalies;

    /// <summary>Reads that could not be satisfied. The §4.8 retryable class.</summary>
    public int FailedReads
    {
        get { lock (_gate) return _failedReads; }
    }

    /// <summary>Inconsistencies observed while every read succeeded. The §12.4e class.</summary>
    public int StructuralAnomalies
    {
        get { lock (_gate) return _structuralAnomalies; }
    }

    /// <summary>The retained anomaly descriptions, oldest first.</summary>
    public IReadOnlyList<string> Anomalies
    {
        get { lock (_gate) return _anomalies.ToArray(); }
    }

    /// <summary>Record one failed read. Called by the snapshot's reader, not by consumers.</summary>
    public void NoteFailedRead()
    {
        lock (_gate) _failedReads++;
    }

    /// <summary>Record a structural inconsistency.</summary>
    public void NoteAnomaly(string detail)
    {
        ArgumentNullException.ThrowIfNull(detail);

        lock (_gate)
        {
            _structuralAnomalies++;
            if (_anomalies.Count < MaxRetainedDetails) _anomalies.Add(detail);
        }
    }

    /// <summary>
    /// The §6.4 bounded walk: a traversal that produced fewer items than a count field promised
    /// is suspect, and the count field is the only evidence available that it happened.
    /// </summary>
    /// <returns>True when the walk was complete.</returns>
    public bool CheckWalk(string label, int expected, int actual)
    {
        ArgumentNullException.ThrowIfNull(label);
        if (actual == expected) return true;

        NoteAnomaly(
            actual < expected
                ? $"{label}: walk returned {actual} of {expected} expected items (analysis doc §12.4e)"
                : $"{label}: walk returned {actual} items where only {expected} were expected");

        return false;
    }

    /// <summary>
    /// The §6.4 agree-twice guard, taken ACROSS two snapshots.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>There is deliberately no same-snapshot form of this.</b> §6.4 lists agree-twice and
    /// the §4.7 page cache as two mitigations for the same defect, but inside one snapshot they
    /// cancel: the cache serves the second sample the identical frozen bytes, so the comparison
    /// can only ever succeed. A guard that cannot fire is worse than no guard, because callers
    /// trust it — so the API only offers the form that works.
    /// </para>
    /// <para>
    /// Two snapshots mean two memory images, which is what makes disagreement observable at
    /// all. §12.4e measured the cost as affordable: 2,308 nodes traversed comfortably at 4 Hz.
    /// Note that legitimate change also disagrees — the target is running — so this belongs on
    /// structures the caller expects to be stable across a tick, not on live gameplay values.
    /// </para>
    /// </remarks>
    /// <param name="label">Names the structure in any anomaly recorded.</param>
    /// <param name="first">The earlier snapshot.</param>
    /// <param name="second">The later snapshot.</param>
    /// <param name="sample">Extracts the value to compare from a snapshot.</param>
    /// <param name="comparer">Optional comparison; defaults to <see cref="EqualityComparer{T}.Default"/>.</param>
    public bool AgreeAcrossSnapshots<T>(
        string label,
        ISnapshot first,
        ISnapshot second,
        Func<ISnapshot, T> sample,
        IEqualityComparer<T>? comparer = null)
    {
        ArgumentNullException.ThrowIfNull(label);
        ArgumentNullException.ThrowIfNull(first);
        ArgumentNullException.ThrowIfNull(second);
        ArgumentNullException.ThrowIfNull(sample);

        if (ReferenceEquals(first, second))
        {
            NoteAnomaly(
                $"{label}: agree-twice was given the same snapshot twice, which can only agree " +
                "(analysis doc §4.7 — the page cache serves both samples identical bytes)");
            return false;
        }

        comparer ??= EqualityComparer<T>.Default;

        T a;
        T b;
        try
        {
            a = sample(first);
            b = sample(second);
        }
        catch (MemoryAccessException e)
        {
            NoteFailedRead();
            NoteAnomaly($"{label}: sampling threw {e.GetType().Name}");
            return false;
        }

        if (comparer.Equals(a, b)) return true;

        NoteAnomaly($"{label}: two consecutive snapshots disagreed (analysis doc §6.4)");
        return false;
    }

    /// <summary>
    /// Collapse the tallies into the public health record.
    /// </summary>
    public SnapshotHealth ToHealth()
    {
        lock (_gate)
        {
            if (_structuralAnomalies == 0 && _failedReads == 0) return SnapshotHealth.Ok;

            string detail = _anomalies.Count > 0
                ? string.Join("; ", _anomalies)
                : $"{_failedReads} read(s) could not be satisfied";

            return new SnapshotHealth(
                IsUsable: _structuralAnomalies == 0,
                FailedReads: _failedReads,
                StructuralAnomalies: _structuralAnomalies,
                Detail: detail);
        }
    }
}

/// <summary>
/// An <see cref="IMemoryReader"/> that reports every failure to a
/// <see cref="SnapshotValidator"/>.
/// </summary>
/// <remarks>
/// Sits OUTSIDE the page cache so that a read served from a block that could not be fetched is
/// counted every time it is attempted, not once when the block was first missed. The caller
/// asked twice and was refused twice; a validator that saw one refusal would understate what
/// the traversal actually experienced.
/// </remarks>
internal sealed class CountingMemoryReader : IMemoryReader
{
    private readonly IMemoryReader _inner;
    private readonly SnapshotValidator _validator;
    private readonly bool _ownsInner;
    private bool _disposed;

    internal CountingMemoryReader(IMemoryReader inner, SnapshotValidator validator, bool ownsInner)
    {
        _inner = inner;
        _validator = validator;
        _ownsInner = ownsInner;
    }

    public bool Is64Bit => _inner.Is64Bit;

    public bool TryRead(ulong address, Span<byte> buffer)
    {
        if (_disposed) return false;
        if (_inner.TryRead(address, buffer)) return true;

        _validator.NoteFailedRead();
        return false;
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        if (_ownsInner) _inner.Dispose();
    }
}
