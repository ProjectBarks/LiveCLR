namespace LiveClr;

using LiveClr.Cdac;
using LiveClr.Memory;

/// <summary>
/// PUBLIC API CONTRACT. Implementations live in Runtime/ and Snapshots/.
/// Consumers (including Godot.External) code against these, never concrete types.
///
/// INVARIANT: there is no semantic read API outside a snapshot. There is
/// deliberately no LiveProcess.ReadObject(address) and no LiveProcess.Field(...).
/// Analysis doc §7b.1 and §12.4e: managed addresses move under GC, and a
/// traversal can tear while every individual read succeeds. Snapshot scoping is
/// how those two findings become type errors instead of documentation.
/// </summary>
public interface ILiveProcess : IDisposable
{
    int ProcessId { get; }
    IMemoryReader Memory { get; }
    IRuntimeContractTarget Runtime { get; }

    /// <summary>Modules discovered in the target, by simple name (e.g. "sts2").</summary>
    IReadOnlyCollection<string> ModuleNames { get; }

    ISnapshot BeginSnapshot(SnapshotMode mode = SnapshotMode.LiveValidated);
}

public enum SnapshotMode
{
    /// <summary>
    /// No suspension. Per-snapshot page cache, re-resolved roots, bounded
    /// traversal, agree-twice on unstable structures.
    /// </summary>
    LiveValidated,

    /// <summary>
    /// PssCreateSnapshot-backed coherent view. Primary use is as a correctness
    /// oracle to diff against LiveValidated; may become the product mode if it
    /// benchmarks cheaply enough (analysis doc §8.8).
    /// </summary>
    ProcessSnapshot,
}

/// <summary>Unit of consistency. All managed handles die with it.</summary>
public interface ISnapshot : IDisposable
{
    SnapshotMode Mode { get; }

    IClrType? Type(string fullName);
    IClrObject? Object(ulong address);

    /// <summary>
    /// Structural validation result. MUST be inspectable and MUST NOT throw:
    /// an overlay's correct response to a suspect snapshot is to reuse the last
    /// good one, which is impossible if validation throws (analysis doc §8.8).
    /// </summary>
    SnapshotHealth Validate();
}

/// <summary>
/// Distinguishes read failure (caught by retry) from STRUCTURAL failure
/// (silent — a traversal that ended early with every read succeeding).
/// </summary>
public readonly record struct SnapshotHealth(
    bool IsUsable,
    int FailedReads,
    int StructuralAnomalies,
    string? Detail)
{
    public static SnapshotHealth Ok => new(true, 0, 0, null);
}

public interface IClrType
{
    string Name { get; }
    ulong MethodTable { get; }
    IClrType? BaseType { get; }
    IReadOnlyCollection<string> FieldNames { get; }

    bool HasField(string name);
    IClrValue? Static(string fieldName);
}

public interface IClrObject
{
    IClrType Type { get; }
    /// <summary>Diagnostic only. Never cache across snapshots — see §7b.1.</summary>
    ulong Address { get; }

    IClrValue? Field(string name);
}

public interface IClrValue
{
    bool IsNull { get; }
    IClrObject? AsObject();
    IClrArray? AsArray();
    IClrList? AsList();
    string? AsString();
    T Read<T>() where T : unmanaged;
}

public interface IClrArray
{
    int Count { get; }
    IClrValue this[int index] { get; }
}

/// <summary>
/// System.Collections.Generic.List&lt;T&gt;. NOTE: backing array length is
/// CAPACITY; the live count is _size. Using _items.Length over-reads stale
/// entries (analysis doc §12.4, API fact 2).
/// </summary>
public interface IClrList
{
    int Count { get; }
    IClrValue this[int index] { get; }
}
