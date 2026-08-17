# LiveClr

Read-only, out-of-process inspection of a **running** .NET 9+ process. Resolve types, walk object
graphs and read fields by name — with no DAC, no injection, no profiler, and **no suspension of the
target**.

```csharp
using var process  = LiveClr.Attach(pid);
using var snapshot = process.BeginSnapshot();

var state  = snapshot.Type("MyApp.GameState").Static("Instance")!.AsObject()!;
int health = state.Field("Player")!.AsObject()!.Field("_currentHp")!.Read<int>();
var deck   = state.Field("_allCards")!.AsList()!;   // List<T>: _size, never _items.Length
```

## Why not ClrMD

ClrMD is external and read-only too — it injects nothing. The difference is its **consistency
contract**: Microsoft states that inspecting a running, *unsuspended* process is unsupported, and
recommends a process snapshot instead. That is the right call for a debugger and the wrong one for
something polling a live application several times a second.

LiveClr targets exactly that case, and is explicit about what it costs (see
[Consistency](#consistency)).

## How it works

The runtime describes itself. Since .NET 9, CoreCLR exports **`DotNetRuntimeContractDescriptor`** —
the cDAC contract descriptor — publishing its own type layouts, field offsets and global locations
as JSON. LiveClr reads that out of the target process and uses it instead of shipping a
version-matched table of CLR internals.

```
coreclr module base
  → PE export table, parsed from the TARGET's memory (no LoadLibrary)
  → DotNetRuntimeContractDescriptor
  → 40-byte header → JSON descriptor + pointer_data
  → CLR type/field offsets, self-described
  → object → MethodTable → Module → Module.Base
  → ECMA-335 metadata (System.Reflection.Metadata) → real type and field NAMES
```

No hardcoded CLR version table anywhere. When the runtime changes its layout, it says so.

## Consistency

**A traversal can tear while every individual read succeeds.** Measured against a live application:
one walk in 26 came back ten nodes short during a mutation, with no read failure anywhere. Retry
logic keyed on read errors cannot see this class of bug.

So consistency is structural, not advisory:

- **`Snapshot` is the unit of work.** There is deliberately no read API outside one.
- **`LiveValidated`** — a per-snapshot page cache gives one traversal a single-moment image.
- **`ProcessSnapshot`** — PSS-backed coherent view, measured at ~1 ms per capture.
- **`Validate()`** returns an inspectable `SnapshotHealth` and never throws, separating *failed
  reads* (retryable) from *structural anomalies* (a traversal that ended early with every read
  succeeding). An overlay's correct response to a suspect snapshot is to reuse the last good one,
  which is impossible if validation throws.
- **Managed addresses are never cached across snapshots** — the GC moves them. Only loader-heap
  pointers (MethodTables, modules) are process-tier cached.

Agree-twice checking is offered **across** snapshots only. Inside one snapshot the page cache
serves identical frozen bytes, so it would be a guard that can never fire.

## What it does not do

Honest boundaries, all traceable to what the .NET 9 descriptor actually publishes:

| Gap | Status |
| --- | --- |
| **Static field addresses** | **Not available.** No `DomainLocalModule`, no MT auxiliary data, and no known-address managed static to calibrate against. Supply them via `IClrStaticRootSource` — ClrMD, suspended, once at connect. |
| Instance field offsets | Derived, not read — `FieldDesc` is unpublished, so the encoding is calibrated against eight published `System.Exception` offsets. Converges or refuses; never guesses. **Not yet live-verified.** |
| `AppDomain` / `Assembly` walk | Unpublished. Seed a module, or resolve any object and its module registers itself. |
| Segmented `ModuleLookupMap` | `Count`/`Next` unpublished. Correct for single-segment maps, degrades to "not found" past that, never to a wrong answer. |
| Non-Windows | Not supported. |

The recurring principle: **a confident wrong answer is worse than a miss.** Where the runtime does
not publish enough to be certain, LiveClr declines rather than guessing.

## Testing

`Fixtures/RecordedMemory` records and replays a target's memory, so the suite runs in CI with no
live process. Note a fixture is a *snapshot, not a history* — it cannot reproduce a torn traversal,
because coalescing collapses the very signal that defines one. PSS is the oracle for that.

## Prior art

- [ClrMD](https://github.com/microsoft/clrmd) — different consistency contract; the recommended
  cold-path bootstrap for statics.
- [chrisnas/RuntimeDataContract](https://github.com/chrisnas/RuntimeDataContract) (MIT) — an
  independent from-scratch cDAC reader. Arrived at the same remote-PE-walk-then-descriptor
  bootstrap; a useful cross-check that this approach is right.
- [dotnet/runtime datacontracts](https://github.com/dotnet/runtime/tree/main/docs/design/datacontracts)
  — the format specification.
- [hackf5/unityspy](https://github.com/hackf5/unityspy) — the architectural ancestor of this whole
  family, for Mono/Unity rather than CoreCLR.

## Licence

MIT.
