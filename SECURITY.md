# Security

## What this library does, precisely

LiveClr opens another process with `PROCESS_VM_READ | PROCESS_QUERY_INFORMATION` and reads bytes.
That is the entire capability.

It does **not**:

- write to the target (`WriteProcessMemory` is not imported)
- inject code, load a DLL into the target, or install a hook
- create remote threads
- suspend or terminate the target
- require or install a driver
- transmit anything anywhere

The whole native surface is in a single file — [`NativeMethods.cs`](src/LiveClr/Memory/NativeMethods.cs)
— specifically so that the *absence* of those imports is a reviewable property of the code rather
than a promise in a README.

The one exception worth naming: `SnapshotMode.ProcessSnapshot` uses `PssCaptureSnapshot`, which
needs `PROCESS_CREATE_PROCESS | PROCESS_VM_OPERATION` to make a copy-on-write VA clone. The clone
is a separate process we create; the target is still never written to or suspended.

## Permissions you actually need

Reading another process's memory generally requires the same user, or `SeDebugPrivilege` for
processes you do not own. LiveClr does not elevate, and will simply fail to attach without
sufficient rights.

## Untrusted input

`ModuleMetadata` copies an ECMA-335 blob out of the target and hands it to
`System.Reflection.Metadata`, which Microsoft documents as **not hardened against malformed
input**. LiveClr validates the `BSJB` signature and every stream's bounds before that hand-off, and
guards its own type-name walk against cyclic and pathologically deep `NestedClass` rows.

If you point LiveClr at a hostile process, treat that blob as attacker-controlled. Bounds
validation is structural only — it does not verify table *contents*.

## Reporting a vulnerability

Open a [security advisory](https://github.com/ProjectBarks/LiveCLR/security/advisories/new) rather
than a public issue. A reproduction against a synthetic target (see `Fixtures/RecordedMemory`) is
far more useful than a description.

Things worth reporting:

- any path that writes to, suspends, or executes code in the target
- a crafted target or metadata blob that crashes the reading process (especially uncatchably —
  `StackOverflowException`, access violation)
- a case where LiveClr returns a confidently **wrong** value rather than declining

That last category is treated as seriously as a crash here. The library's design principle is that
a confident wrong answer is worse than a miss.
