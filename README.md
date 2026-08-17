# LiveClr

**Read the object graph of a *running* .NET process from the outside — without suspending it.**

[![CI](https://github.com/ProjectBarks/LiveCLR/actions/workflows/ci.yml/badge.svg)](https://github.com/ProjectBarks/LiveCLR/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![.NET 9](https://img.shields.io/badge/.NET-9.0%2B-512BD4)](https://dotnet.microsoft.com/)
[![Windows](https://img.shields.io/badge/platform-Windows-0078D4)](#requirements)

No debugger attach. No DAC. No profiler. No DLL injection. No `WriteProcessMemory`. Just
`ReadProcessMemory` plus the runtime's own self-description.

```csharp
using var process  = LiveClr.Attach(pid);
using var snapshot = process.BeginSnapshot();

var state  = snapshot.Type("MyApp.GameState").Static("Instance")!.AsObject()!;
int health = state.Field("Player")!.AsObject()!.Field("_currentHp")!.Read<int>();
var items  = state.Field("_inventory")!.AsList()!;   // List<T> via _size, never _items.Length
```

Built for live tooling — overlays, trackers, monitors, companion apps — that need to poll a running
application several times a second and cannot pause it.

---

## Why not ClrMD?

[ClrMD](https://github.com/microsoft/clrmd) is external and read-only too; it injects nothing. The
difference is its **consistency contract**: Microsoft states that inspecting a *running,
unsuspended* process is unsupported and recommends a process snapshot instead.

That is correct for a debugger and wrong for something sampling a live application at 4 Hz.

|  | ClrMD | LiveClr |
| --- | --- | --- |
| Unsuspended live process | unsupported | **the target case** |
| CLR layout source | version-matched DAC | **cDAC descriptor, self-described** |
| Consistency model | suspend / snapshot | snapshot-scoped page cache, or PSS |
| Torn-traversal detection | — | structural, inspectable |
| Static fields | ✅ | ❌ *(see [Limits](#limits))* |
| Maturity | production, years | **new** |

They compose: ClrMD is the recommended cold-path bootstrap for the one thing LiveClr cannot do.

## How it works

Since .NET 9, CoreCLR exports **`DotNetRuntimeContractDescriptor`** — the
[cDAC](https://github.com/dotnet/runtime/issues/99298) contract descriptor — publishing its own
type layouts, field offsets and global locations as JSON, in-process, for diagnostic tools to read.

LiveClr reads that *out of the target* and uses it instead of shipping a table of CLR internals per
runtime version.

```
coreclr module base
  → PE export table, parsed from the TARGET's memory (no LoadLibrary)
  → DotNetRuntimeContractDescriptor
  → 40-byte header → JSON descriptor + pointer_data
  → CLR type/field offsets, self-described
  → object → MethodTable → Module → Module.Base
  → ECMA-335 metadata (System.Reflection.Metadata) → real type and field names
```

**No hardcoded CLR version table anywhere.** When the runtime changes its layout, it says so.

## Consistency

**A traversal can tear while every individual read succeeds.** Measured against a live application:
one walk in 26 returned ten nodes short during a mutation, with no read failure anywhere. Retry
logic keyed on read errors cannot see that class of bug.

So consistency here is structural, not advisory:

- **`Snapshot` is the unit of work** — there is deliberately no read API outside one.
- **`LiveValidated`** — a per-snapshot page cache gives one traversal a single-moment image.
- **`ProcessSnapshot`** — PSS-backed coherent view, ~1 ms per capture.
- **`Validate()`** returns an inspectable `SnapshotHealth` and **never throws**, separating *failed
  reads* (retryable) from *structural anomalies* (a traversal that ended early with every read
  succeeding). The correct response to a suspect snapshot is to reuse the last good one — which is
  impossible if validation throws.
- **Managed addresses are never cached across snapshots.** The GC moves them. Only loader-heap
  pointers (MethodTables, modules) are process-tier cached.

## Limits

Honest boundaries, each traceable to what the .NET 9 descriptor actually publishes:

| Gap | Status |
| --- | --- |
| **Static field addresses** | **Not implemented — but no longer believed impossible.** This row previously read "no MT auxiliary data, and no known-address managed static to calibrate against". Both were wrong. `m_pAuxiliaryData` is at `MethodTable+0x20`, and `DynamicStaticsInfo` sits immediately below it carrying a **back-pointer to the MethodTable at `aux-8`** — a self-validating anchor, measured at 3033/3033 across 25 assemblies on a live .NET 9 process, with GC statics at `aux-0x18` and non-GC at `aux-0x10`, masked `& ~1`. Verified end to end by reading `Environment.s_processId` and getting the target's real PID. See `docs/analysis.md` §14. Until it is implemented here, supply via `IClrStaticRootSource` — ClrMD, suspended, once at connect. |
| Instance field offsets | Derived, not read. `FieldDesc` is unpublished, so the encoding is calibrated against eight published `System.Exception` offsets. Converges or refuses; never guesses. **Not yet verified against a live runtime.** |
| `AppDomain` / `Assembly` walk | Unpublished. Seed a module, or resolve any object and its module registers itself. |
| Segmented `ModuleLookupMap` | `Count`/`Next` unpublished. Correct for single-segment maps; degrades to "not found" beyond, never to a wrong answer. |
| Platform | Windows x64 only. |

The recurring principle: **a confident wrong answer is worse than a miss.** Where the runtime does
not publish enough to be certain, LiveClr declines.

> **Status: new and not yet battle-tested.** The design is validated by 322 tests against synthetic
> and recorded memory, and the technique is validated against a real game — but *this*
> implementation has not yet been run against a live target end to end. Treat it accordingly.

## Requirements

Windows, .NET 9+ target process, and rights to open it for read (same user, or `SeDebugPrivilege`).

## Testing without a live process

`Fixtures/RecordedMemory` records and replays a target's memory, so the suite runs in CI with no
process attached. Note a fixture is a *snapshot, not a history* — it cannot reproduce a torn
traversal, because coalescing collapses the very signal that defines one. PSS is the oracle for
that.

## Prior art

- [ClrMD](https://github.com/microsoft/clrmd) — different consistency contract; the cold-path
  bootstrap for statics.
- [chrisnas/RuntimeDataContract](https://github.com/chrisnas/RuntimeDataContract) (MIT) — an
  independent from-scratch cDAC reader that arrived at the same remote-PE-walk-then-descriptor
  bootstrap. A useful cross-check that this approach is right.
- [dotnet/runtime datacontracts](https://github.com/dotnet/runtime/tree/main/docs/design/datacontracts)
  — the format specification.
- [hackf5/unityspy](https://github.com/hackf5/unityspy) — architectural ancestor of this whole
  family, for Mono/Unity rather than CoreCLR.
- [OpenTelemetry eBPF profiler](https://github.com/open-telemetry/opentelemetry-ebpf-profiler) —
  production, non-intrusive, also reads the cDAC descriptor out of process.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) — particularly the section on why "does it work" is the
wrong bar here. Security posture: [SECURITY.md](SECURITY.md).

## Licence

MIT.
