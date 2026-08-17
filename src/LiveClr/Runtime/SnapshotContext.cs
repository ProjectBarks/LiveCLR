namespace LiveClr.Runtime;

using LiveClr.Memory;

/// <summary>
/// What a snapshot must provide to the handles it hands out.
/// </summary>
/// <remarks>
/// <para>
/// Every managed handle — <see cref="ClrType"/>, <see cref="ClrObject"/>,
/// <see cref="ClrValue"/> — holds one of these and nothing else. That is what makes §8.8's
/// lifetime rule structural rather than documentary: a handle cannot read without a context,
/// a context becomes unusable when its snapshot is disposed, and there is no way to construct
/// one from a <c>LiveProcess</c>. §7b.1's "never cache a managed object address across polls"
/// therefore stops being advice.
/// </para>
/// <para>
/// Internal on purpose. Widening it would let a consumer build handles outside a snapshot,
/// which is the one thing the public API contract forbids.
/// </para>
/// </remarks>
internal interface ISnapshotContext
{
    /// <summary>The snapshot's reader — a page cache or a PSS clone, never the raw process.</summary>
    IMemoryReader Memory { get; }

    /// <summary>Process-tier type system.</summary>
    ClrTypeSystem TypeSystem { get; }

    /// <summary>Where static field addresses come from.</summary>
    IClrStaticRootSource StaticRoots { get; }

    /// <summary>True once the snapshot has been disposed; handles then read nothing.</summary>
    bool IsDisposed { get; }

    /// <summary>
    /// Record a STRUCTURAL inconsistency — the §12.4e class, where every read succeeded and
    /// the result is still wrong. Never throws; the whole point of the error model in §8.8 is
    /// that an overlay can inspect the damage and reuse its last good snapshot.
    /// </summary>
    void NoteAnomaly(string detail);
}
