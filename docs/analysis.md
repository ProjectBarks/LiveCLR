# untapped-scry — how it works, and how to build our own

Analysis date: 2026-08-16. Subject: `vendor/untapped-scry` 6.12.6 and
`vendor/untapped-node-native` 2.3.0, as vendored in this repo.

Method: PE structure parsing, RTTI recovery, targeted decompilation (Ghidra 12.1.2 headless),
and direct extraction from the game's shipped runtime.

**Purpose: understand the mechanism well enough to build our own reader.** Function addresses
(`FUN_180039d50`) are navigation aids into the Ghidra project.

> **Headline finding.** Scry's whole .NET Core bootstrap rests on `g_dacTable` plus a
> hand-maintained offset table. StS2's shipped runtime also exports
> **`DotNetRuntimeContractDescriptor`** — the cDAC contract descriptor — which publishes the
> same information *self-describingly*. We extracted it (§5). It makes the hardcoded table
> unnecessary and is forward-compatible with every .NET ≥ 9.
>
> **Everything below has been validated against a live Slay the Spire 2** (§12): the remote
> export walk, the descriptor read, the CLR type walk with zero hardcoded offsets, and
> **111/112** recovered Godot offset checks across menu and combat scenes — the single miss
> corrected a wrong assumption (§12.3b). Full run and combat state reads live, including
> enemy intent as a string. §11 lists every open question and its answer.

---

## 1. What we vendor, and what we actually use

| Package | Size | License | What it is |
| --- | --- | --- | --- |
| `untapped-node-native` 2.3.0 | 310 KB | UNLICENSED (HearthSim) | Win32/macOS window + process helpers |
| `untapped-scry` 6.12.6 | 888 KB | UNLICENSED (HearthSim) | Out-of-process managed-runtime memory reader |

Both are proprietary, private-repo binaries distributed via `node-pre-gyp` from
`libs.hearthsim.net`. **That bucket is not public** — `HEAD` on the prebuild tarball returns
`403 Forbidden`, so there is no PDB and no source to recover. Every distinctive identifier in
the binary returns **zero web results**. This document is the reference.

**`untapped-node-native` is one call site.** `getWindowInfo('Engine', 'Slay the Spire 2')` at
`src/main/scry/connection.ts:40`. The other twelve exports have no call sites in `src/` or
`scripts/`. It returns `{ hwnd, pid, exists, active, rect, findWindowError, openProcessError }`
with `rect` in physical screen pixels (`OverlayWindow.ts:108` converts to DIP), and it is
`FindWindowW` → `GetWindowThreadProcessId` → compare against `GetForegroundWindow` →
`GetWindowRect`. With [koffi](https://koffi.dev/) it needs no compiled addon at all.

**Of scry's four backends we use two:** `DotNetCoreScry` and `GodotScry`. `MonoScry` and the
whole `Il2CppScry`/Unity tree — including the three `FingerprintHeuristic` subclasses that
carry most of the library's hard-won value — are dead weight for a Godot game.

---

## 2. Build facts

| | |
| --- | --- |
| Toolchain | MSVC linker 14.44 (VS 2022 ~17.14), x64 PE32+ DLL renamed `.node` |
| Build host | GitHub Actions — `D:\a\untapped-scry\untapped-scry\extras\untapped-scry-napi\build\Release\` |
| Binding | node-addon-api / N-API v5; exports only `napi_register_module_v1` |
| Optimization | POGO (profile-guided) + ILTCG |
| Code | 654 KB `.text`, **2,488 functions** (exact, from `.pdata` unwind entries) |
| Protection | **None.** Entropy 6.32, not packed, no obfuscation, no anti-debug, RTTI intact |

Imports are read-only by construction: `OpenProcess`, `ReadProcessMemory`, `VirtualQueryEx`,
`K32EnumProcessModulesEx`, `K32GetModuleInformation`, `K32GetModuleBaseNameW`,
`GetFileVersionInfoW`. **No `WriteProcessMemory`, no injection, no hooking, no driver.** The
whole thing is *reading another process's heap and interpreting it*.

---

## 3. The design in one page

```
Scry (abstract)                       ← read primitives, pointer-width aware
 ├─ ScryWin ─┬─ ScryWin32
 │           └─ ScryWin64
 └─ ScryCached                        ← page-cache decorator
WinNativeInterface ← ...DefaultImpl   ← Win32 behind an interface (mockable)
ScryMemoryAccessException             ← surfaces to JS as type:'memory-access-exception'
```

Above that, one templated object model — `UnityScriptObject<TValue>`,
`UnityScriptStruct<TValue>`, `UnityScriptClass<TFieldInfo,TValue>` — instantiated over
`_MonoValue` and `_Il2CppValue`. Four backends hang off it: **IL2CPP** (metadata header +
fingerprint heuristics), **Mono** (`mono_get_root_domain`), **.NET Core** (`g_dacTable`),
**Godot** (thin structs over version-keyed offsets, riding on .NET Core).

---

## 4. How scry works — mechanism, in build order

### 4.1 Attach and the read primitive set

`OpenProcess` for read + query; the handle lives behind vtable slot `+0x88`. Every read
dispatches through a small vtable — **this is the interface to implement**:

| Slot | Operation | Seen in |
| --- | --- | --- |
| `+0x00` | readBool / readByte | `isVisible` |
| `+0x10` | **readBytes (bulk block read)** | `getText` |
| `+0x18` | readCString | module-name compare |
| `+0x28` | readFloat | all Control accessors |
| `+0x30` | readInt32 | PE header parsing |
| `+0x40` | readPointer (pointer-width aware) | everywhere |
| `+0x60` | readUInt32 | `getName`, export walk |
| `+0x68` | readUInt64 / size | `CowData` length |
| `+0x70` | readInt16 | PE machine field |
| `+0x78` | is64Bit | pointer-width branches |
| `+0x88` | get process handle | module enumeration |

The bulk `+0x10` read matters for performance: one `ReadProcessMemory` for an entire string
beats one call per character, and the same argument applies to any array we walk.

`readPointer` and `is64Bit` being separate is what lets one code path serve 32- and 64-bit
targets. StS2 is x64-only, so we hardcode 8 and delete half this complexity.

### 4.2 Finding the runtime module

`FUN_180039b90`. `K32EnumProcessModulesEx`, then per module `K32GetModuleBaseNameW` and a
wide-string compare against `L"coreclr.dll"`. On match, `K32GetModuleInformation` yields
`lpBaseOfDll`. Documented Win32, no trickery.

### 4.3 Resolving an export from remote memory

`FUN_1800567d0`. Resolves an export **without loading anything locally**, by reading the
target's own PE headers over `ReadProcessMemory`:

1. Read `e_lfanew` at `base + 0x3c`
2. Validate `0x4550` (`PE\0\0`) at `base + e_lfanew`
3. Read machine at `+4` — `0x8664` (x64) or `0x14c` (x86)
4. Export data directory at `+0x78` (PE32) or `+0x88` (PE32+)
5. Walk the export name table / ordinal table / address table in remote memory

ASLR-immune, no local copy of the DLL, safe against a live process. **This step is reusable
verbatim for §5** — it is how we reach the contract descriptor too.

### 4.4 Bootstrap: the `g_dacTable` anchor

`FUN_180039d50`. CoreCLR exports a global **`g_dacTable`** whose address gives the
`DacGlobals` structure — a table of pointers to the runtime's internal roots. Resolve it via
§4.3, read a slot, and you have an entry point into CLR state. Scry then walks AppDomain →
assembly list → modules, `readCString`-ing each module name and comparing against `"sts2"`.

Implementation detail worth knowing: the string `"g_dacTable"` is **built inline on the stack**
as an SSO `std::string`, not referenced from `.rdata` (same for `"4.5.1"`). This is why
byte-level cross-reference scanning finds nothing — see §10.

### 4.5 The offset table, and why it is fragile

`FUN_180039930` maps a field ID to an offset via a bare `switch`:

| ID | Offset | | ID | Offset | | ID | Offset |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `0x00` | `0x458` | | `0x11`,`0x18`,`0x2b` | `0x10` | | `0x1e` | `0xe0` |
| `0x01` | `0x5c` | | `0x13` | `0x04` | | `0x20` | `0x3c0` |
| `0x02`,`0x03`,`0x0c`,`0x17`,`0x28` | `0x18` | | `0x14` | `0x28` | | `0x21` | `0xc0` |
| `0x04`,`0x09` | `0x41` | | `0x19` | `0x30` | | `0x22` | `0x2e8` |
| `0x05`,`0x07` | `0x42` | | `0x1a` | `0x0a` | | `0x23` | `0xa8` |
| `0x06` | `0x40` | | `0x1b` | `0x548` | | `0x24` | `0xa0` |
| `0x08` | `0x46` | | `0x1c` | `0x0e` | | `0x25` | `0x170` |
| `0x0a`,`0x23` | `0xa8` | | `0x1d` | `0x528` | | `0x2a` | `0x70` |
| `0x0b`,`0x25` | `0x170` | | `0x0d`,`0x12`,`0x1f` | `0x20` | | `0x0f` | `0x0c` |
| `0x0e`,`0x16`,`0x26`,`0x27`,`0x29` | `0x08` | | default | `0` | | | |

The caller picks the *field ID* by .NET major version: below 9 it uses one set (e.g. ID `0x0b`
→ `0x170`), at 9+ another (ID `0x0a` → `0xa8`) plus inline constants (`0x308`, `0xd8`, `0xa8`).

**Why these numbers are unstable.** Per CoreCLR's
[DAC notes](https://github.com/dotnet/runtime/blob/main/docs/design/coreclr/botr/dac-notes.md),
`DacGlobals` slot order is generated from
[`dacvars.h`](https://github.com/dotnet/runtime/blob/main/src/coreclr/inc/dacvars.h) — the
order of `DEFINE_DACVAR` invocations *is* the slot order. That file changes between releases,
and several entries are **conditional** on build configuration (ReadyToRun / interpreter JIT
managers, profiler support), so a slot can shift even between builds of the same version. A
divide-by-8 from an offset to a named global is therefore only valid against the exact
version-matched `dacvars.h`.

**This is the entire recurring cost of scry's approach**, and precisely the problem the DAC —
and now the cDAC (§5) — exist to solve.

### 4.6 The Godot layer

`GodotEngine` / `GodotNode` / `GodotControl` / `GodotCanvasItem` / `GodotLabel` /
`GodotRichTextLabel`. Almost no RTTI: thin, non-polymorphic structs over version-keyed offsets
on top of the .NET Core layer. Path: managed `GodotObject` → its `NativePtr` field → raw reads
into the C++ engine struct.

N-API registration sites: Control accessors at `FUN_180013130`; Node accessors at
`FUN_180015cd0`; engine factory (`getNode`/`getControl`/`getCanvasItem`/`getLabel`/
`getRichTextLabel`) at `FUN_180013b60`; `getGodotEngine` at `FUN_1800023c0`; Label `getText`
at `FUN_180015590` / `FUN_180017090`.

**Recovered engine struct offsets.** Each accessor reads at `nativePtr + OFFSET` through vtable
slot `+0x28` (readFloat), selecting between **two layout variants** via a flag byte on the
engine object (`engine[1] + 0x3c`).

**What the flag means — resolved.** The version parser (`FUN_1800422d0`) sets that byte to `1`
only when the supplied version string ends with `-debug`, and `0` otherwise; `FUN_1800427a0`
copies it into the engine object at `+0x3c`. So the variants are **debug vs release export
template**, *not* Godot version — debug templates carry extra fields, which is why the layouts
differ by ~80 bytes.

`connection.ts:16` passes `'4.5.1'` with no suffix, and StS2 ships a release template, so
**the release column is ours.**

| Class | Accessor | Impl | **Release** (flag = 0) | Debug (flag = 1) | Shape | Verified |
| --- | --- | --- | --- | --- | --- | --- |
| CanvasItem | `isVisible` | `FUN_180011e30` | **`0x370`** | `0x3c0` | bool (vtable `+0x00`) | branch |
| Control | `getGlobalPosition` | `FUN_180012c70` | **`0x3f8`,`0x3fc`** | `0x448`,`0x44c` | 2 floats (Vector2) | branch |
| Control | `getOffset` | `FUN_180012d60` | **`0x470 + i*4`**, i=0..3 | `0x500 + i*4` | 4 floats | branch |
| Control | `getScale` | `FUN_180012f50` | **`0x4a8`,`0x4ac`** | `0x4f8`,`0x4fc` | 2 floats | pattern |
| Control | `getPosition` | `FUN_180012e60` | **`0x4b8`,`0x4bc`** | `0x508`,`0x50c` | 2 floats | pattern |
| Control | `getSize` | `FUN_180013040` | **`0x4c0`,`0x4c4`** | `0x510`,`0x514` | 2 floats | pattern |
| Node | `getParent` | `FUN_180016110` | **`0x128`** | `0x178` | pointer | branch |
| Node | `getChildren` | `FUN_1800163a0` | delegates | | list walk | — |
| Node | `getName` | `FUN_180016580` | delegates | | string | — |
| Node | `getDotNetCoreObject` | `FUN_180016610` | delegates | | bridge | — |

**Independent corroboration.** Godot's
[`scene/gui/control.h`](https://github.com/godotengine/godot/blob/master/scene/gui/control.h)
declares `Control::Data` in the order `real_t offset[4]` → `real_t anchor[4]` → focus/grow
enums → `real_t rotation` → `Vector2 scale` → … with `pos_cache` / `size_cache` later. The
release column reproduces exactly that shape:

```
0x370  CanvasItem visible
0x3f8  (global position cache)
0x470  offset[4]        0x470..0x47c   ← Data.offset[4]
0x480  (anchor[4])                     ← Data.anchor[4], not read by scry
0x490  (focus/grow enums, rotation)
0x4a8  scale            0x4a8..0x4af   ← Data.scale        (Vector2)
0x4b8  pos_cache        0x4b8..0x4bf   ← Data.pos_cache    (Vector2)
0x4c0  size_cache       0x4c0..0x4c7   ← Data.size_cache   (Vector2)
```

Ascending, non-overlapping, and consistent with upstream field ordering and single-precision
`real_t` (4-byte reads). Two independent sources agreeing is the strongest signal available
short of a live read.

**Branch direction — settled for every accessor.** All twelve emit the identical pattern:

```c
lVar = <debug constant>;
if (*(char *)(engine[1] + 0x3c) == '\0') { lVar = <release constant>; }
```

So the **release value is uniformly the second constant**, with no exceptions. The `pattern`
rows in the table above are therefore as reliable as the `branch` rows.

That also settles the debug-column oddity: `getOffset` really does read `0x500..0x50c` while
`getPosition` reads `0x508/0x50c` on the debug path — a genuine **overlap in scry's own debug
constants**, confirmed in the disassembly, not a misreading on our part. The debug template is
presumably an untested path for them. Irrelevant to us; the release column is what we use and it
is validated 30/30 (§12.3) plus 60/60 on combat nodes (§12.4c).

> **✔ LIVE-VALIDATED.** Every release-column value above was confirmed against a running game
> across five Controls — **30/30 checks, zero mismatches** (§12). Distinctive values such as
> `BgContainer` size `[2560,1200]` / offset `[-960,-516,1600,684]` and `MainMenuTextButtons`
> offset `[-318,69,-49,519]` matched exactly. These are no longer candidates; they are correct
> for this build.

**Managed → native bridge.** A C# `GodotObject` carries the engine pointer in a managed field
literally named `NativePtr`; read it off the managed object and hand it to the native wrappers.
Confirmed live: `NGame.Instance` → `NativePtr = 0x1a9204c5580` → root node name `"Game"`.
Passing the *managed* address instead yields plausible-looking garbage (it resolved to the
string `"is_visible"`), so this is an easy and quiet mistake to make.

**Native → managed bridge — corrected.** `node + 0x68` is *not* the managed object. It is
Godot's `ScriptInstance`, and the managed object is two further hops away. Verified live:

```
Node*  +0x68 -> ScriptInstance*
                  +0x00   vtable pointer (inside the game exe's .text)
                  +0x08   back-reference to the owning Node*
                  +0x20   GCHandle  ->  *(handle) == managed C# object
```

For `NGame`: `native=0x1a9204c5580` → `scriptInstance=0x1a90351dd30` → `+0x20 = 0x1a96f941360`
→ dereference → `0x1a974c6c240`, exactly the managed object address scry reports. The `+0x08`
back-reference is a cheap self-check that you followed the right pointer.

This is the route from a scene-tree node to the C# object holding game state, so it matters.

**`getGlobalPosition` is unreliable.** Live, it returned `[0,0]` for `MainMenuTextButtons` and
`ContinueButton` despite both having real positions — it reads Godot's *cached* global
transform, which goes stale for nodes positioned via `GlobalPosition` writes. `scryObject.ts`
already works around this by summing local offsets up the tree in `computeGlobalPosition`;
keep that approach.

**Non-scalar accessors** (release offsets; all branch-verified):

| Accessor | Impl | Release / Debug | Mechanism |
| --- | --- | --- | --- |
| `Node.getChildren` | `FUN_180041180` | `0x148` / `0x198` | Head pointer at `node + 0x148`, then an intrusive **linked list**: `next = readPtr(cur + 0)`, child `Node*` = `readPtr(cur + 0x18)`. Iterate until null. |
| `Node.getName` | `FUN_180041350` | `0x1c0` / `0x210` | `readPtr(node + 0x1c0)` → `StringName::_Data`; `readPtr(that + 8)` → buffer; then **UTF-32** char-by-char (`readUInt32`, stride 4) until null. Cached on the wrapper. |
| `Node.getDotNetCoreObject` | `FUN_180041530` | `0x68` / `0x70` | **Not** a direct pointer — see the chain below. |
| `Label.getText` | `FUN_180042040` | `0x800` / `0x848` | `CowData` read, below. |
| `RichTextLabel.getText` | `FUN_180041e50` | `0xa78` / `0xb18` | Same. |

**Godot `String` is `CowData<char32_t>`, and its length lives *before* the buffer.** The
`getText` path is the clean implementation and the one to copy:

1. `buf = readPtr(obj + OFFSET)` — null means empty string
2. `len = read(buf - 8)` via vtable `+0x68` — **CowData stores `[refcount][size]` ahead of the
   data**, and the pointer points at the data
3. bulk-read `len * 4` bytes via vtable `+0x10` (one block read, not per-character)
4. decode

`getName` instead walks code units one remote read at a time — noticeably worse, and both paths
then truncate each `char32_t` to a byte when building the JS string. **Fine for ASCII, lossy for
anything else.** Our implementation should decode UTF-32 properly and always use the bulk read.

Vtable slots observed across the Godot layer: `+0x00` bool/byte, `+0x10` readBytes (bulk),
`+0x28` float, `+0x40` pointer, `+0x60` uint32, `+0x68` uint64/size.

**`getGlobalPosition` is a cached field, not a computed transform — settled.** The accessor
(`FUN_180012c70`) performs exactly two `readFloat` calls at `0x3f8`/`0x3fc` and no arithmetic:
there is no transform composition anywhere in it. That is why it returns stale `[0,0]` for nodes
positioned via `GlobalPosition` writes (observed live, §12.3). Reading it is cheap but
untrustworthy; `computeGlobalPosition` in `scryObject.ts` summing local offsets up the tree is
the correct approach and should stay.

`"4.5.1"` is a **default** used when no version string is supplied — parsed by `FUN_1800422d0`,
which strips a `-debug` suffix. Version handling is parsing plus conditional logic in code,
**not** a liftable data table. Our call sites pass `'4.5.1'` and `'9.0.2'` explicitly
(`connection.ts:16-18`).

### 4.6b Module impl and caching

`DotNetCoreModuleImpl`'s constructor (`FUN_180056c20`, reached via `FUN_18003a620`) allocates a
`0x120`-byte object containing **seven separate red-black-tree caches** (identifiable by the
`0x101` header sentinel) before touching the target. Class lookups, field descriptors, and name
resolution are all memoized per module — consistent with the `Cached` decorator classes in §3.

Field-name → offset resolution was not traced through scry's seven memoized layers, and it does
not need to be — **the route around it is proven live** (probe 13, §12.4d): using only offsets
published by the runtime's own descriptor, a managed object reaches its ECMA-335 metadata, from
which type and field *names* are readable directly. Neither scry nor ClrMD is required.

**Resolved: no drift.** An earlier draft flagged the `0xb8` constant as possible drift. That was
wrong, and tracing all eight callers of the offset table settles it.

**Nine** field IDs are used across **13 call sites** in 8 caller functions, each paired with an
inline constant on the .NET ≥ 9 branch:

| Field ID | Table (<9) | Inline (≥9) | Cross-check against the live descriptor |
| --- | --- | --- | --- |
| `0x00` | `0x458` | `0x308` | not a published `Module` field |
| `0x0a` | `0xa8` | `0x308` | not a published `Module` field |
| `0x0b` | `0x170` | *(pointer-width branch)* | — |
| `0x0c` | `0x18` | `0x08` / `0x10` by bitness | *matches `TypeRefToMethodTableMap=8`, but the bitness branch makes this coincidental — do not rely on it* |
| `0x21` | `0xc0` | **`0xd8`** | **`Module.Assembly = 216 = 0xd8`** ✔ |
| `0x23` | `0xa8` | `0xb8` | not published (sits between `Path` 176 and `Base` 192) |
| `0x24` | `0xa0` | `0xa8` | not published |
| `0x25` | `0x170` | **`0x150`** | **`Module.TypeDefToMethodTableMap = 336 = 0x150`** ✔ |
| `0x27` | `0x08` | — | — |

**Two independent exact matches** (`0x21` → `Assembly`, `0x25` → `TypeDefToMethodTableMap`) confirm
these are `Module` field offsets and that scry's .NET 9 values are correct for this build. The
remaining IDs map to fields the cDAC descriptor does not publish, so they cannot be cross-checked —
but **nothing contradicts the descriptor anywhere**.

> **Correction.** An earlier revision of this document claimed only three IDs were used. That was
> an extraction error on our side, not a property of the binary: the regex `FUN_180039930\([^)]*\)`
> terminates at the `)` inside `(longlong)param_1`, silently dropping most call sites. The
> conclusion (no drift) survives and is now better supported; the supporting data was wrong.

None of this affects our design (§5.2 derives offsets rather than hardcoding them), but the
suspicion is now closed rather than left hanging.

### 4.7 Consistency: the page cache

`ScryCached` decorates `Scry`; `withPageCache` / `pageSize` / `pageCount` on the JS surface.
Cache whole pages for the duration of one snapshot so a pointer and its target come from the
same moment, instead of dozens of independent `ReadProcessMemory` calls across a mutating
heap. This is why our retry logic works as well as it does, and we want it.

### 4.8 Error surface

`ScryMemoryAccessException` → JS `type: 'memory-access-exception'`. Read failures format as
`Failed to read <N> bytes from remote address <ADDR>:` (`FUN_180051620`). Both are load-bearing
in `scryObject.ts:23` — `isTransientRead` keys off the exception type and the
`remote address 0+:` pattern. **Our implementation must preserve this contract** or that retry
logic silently stops working.

---

## 5. The better anchor: the cDAC contract descriptor

**Verified present on our exact target.** `data_sts2_windows_x86_64/coreclr.dll` exports only
12 symbols; three matter:

```
DotNetRuntimeContractDescriptor      ← the self-describing route
g_CLREngineMetrics
g_dacTable                           ← what scry uses
```

The [cDAC](https://github.com/dotnet/runtime/issues/99298) replaces the DAC with versioned
data contracts and ships with SOS in .NET 11. Microsoft's stated **goal** is that each future
cDAC reader understands every CoreCLR ≥ .NET 9.

**Read that precisely.** It is a compatibility goal for *readers and contracts* — not a promise
that .NET 9's descriptor publishes every structure a given consumer wants. Our own §5.5 finding
proves the distinction: the shipped .NET 9 descriptor omits `AppDomain`, `Assembly`, and
`ArrayListBase`. Guard every lookup with a presence check (§8.3) rather than assuming coverage.

### 5.1 Descriptor binary layout

Reachable with the *same* §4.3 remote-export technique. 40 bytes on x64:

| Offset | Field | Size | Notes |
| --- | --- | --- | --- |
| 0 | magic | 8 | `"DNCCDAC\0"` — also determines endianness |
| 8 | flags | 4 | bit0 = 1; bit1 = ptrSize (0 = 64-bit, 1 = 32-bit) |
| 12 | descriptor_size | 4 | byte count of the UTF-8 JSON |
| 16 | descriptor | 8 | pointer to the JSON blob |
| 24 | pointer_data_count | 4 | |
| 28 | pad0 | 4 | |
| 32 | pointer_data | 8 | array of pointers to runtime globals |

**Verified bytes from the shipped DLL** (export RVA `0x461d30`):

```
444e434344414300 01000000 810c0000 a0c23e8001000000 0e000000 00000000 f0f4458001000000
magic="DNCCDAC\0"  flags=0x1 (64-bit)  descriptor_size=3201  descriptor=0x1803ec2a0
pointer_data_count=14  pointer_data=0x18045f4f0
```

### 5.2 What StS2's runtime publishes about itself

3,201 bytes of JSON, `version: 0`, `baseline: "empty"`, **29 types / 22 globals / 7 contracts**
(`DacStreams`, `EcmaMetadata`, `Exception`, `Loader`, `Object`, `RuntimeTypeSystem`, `Thread` —
all v1). The layouts we care about, extracted verbatim:

```jsonc
"Object":      { "m_pMethTab": 0 }
"String":      { "m_StringLength": 8, "m_FirstChar": 12 }
"Array":       { "m_NumComponents": 8, "!": 16 }        // "!" = element base
"MethodTable": { "MTFlags": 0, "BaseSize": 4, "MTFlags2": 8, "NumVirtuals": 12,
                 "NumInterfaces": 14, "ParentMethodTable": 16, "Module": 24,
                 "EEClassOrCanonMT": 40, "PerInstInfo": 48 }
"EEClass":     { "MethodTable": 16, "CorTypeAttr": 56, "InternalCorElementType": 64,
                 "NumMethods": 68, "NumNonVirtualSlots": 78 }
"Module":      { "TypeRefToMethodTableMap": 8, "ManifestModuleReferencesMap": 40,
                 "MemberRefToDescMap": 72, "LoaderAllocator": 152, "Path": 176,
                 "Base": 192, "Flags": 200, "Assembly": 216, "TypeDefToMethodTableMap": 336,
                 "MethodDefToDescMap": 368, "MethodDefToILCodeVersioningStateMap": 400,
                 "FieldDefToDescMap": 432, "ThunkHeap": 648, "DynamicMetadata": 736 }
"MethodDesc":  { "Flags3AndTokenRemainder": 0, "ChunkIndex": 2, "Slot": 4, "Flags": 6 }
"ArrayClass":  { "Rank": 88 }
"ModuleLookupMap": { "TableData": 8 }
```

Relevant scalar globals: `ObjectToMethodTableUnmask: 0x7`, `ObjectHeaderSize: 0x8`,
`MethodDescAlignment: 0x8`, `MethodDescTokenRemainderBitCount: 0xc`,
`SOSBreakingChangeVersion: 0x5`.

**This is the same information scry's §4.5 table encodes — published by the runtime, versioned,
and self-describing.**

The full extracted blob is checked in at
[`docs/reference/sts2-coreclr-contract-descriptor.json`](reference/sts2-coreclr-contract-descriptor.json)
(pretty-printed; extracted from `coreclr.dll` build 9.0.725.31616). Re-extract after any game
update that bumps the runtime — the procedure is in §10.

### 5.3 How globals resolve

Globals appear as `"AppDomain": [[1], "pointer"]` — the inner number is an **index into
`pointer_data`**, which holds the *address of* the global. Verified against the shipped DLL:

| Index | Global | Address (`.data`) |
| --- | --- | --- |
| 1 | AppDomain | `0x180462780` |
| 2 | ThreadStore | `0x180463218` |
| 3 | FinalizerThread | `0x1804632c0` |
| 8 | ObjectMethodTable | `0x180463400` |
| 10 | StringMethodTable | `0x180463368` |
| 11 | SyncTableEntries | `0x180463438` |

So: resolve descriptor → read `pointer_data[1]` → deref → AppDomain. Index 0 is unused.

### 5.4 The documented walk

The [Loader contract](https://github.com/dotnet/runtime/blob/main/docs/design/datacontracts/Loader.md)
specifies the algorithm, so it need not be reverse engineered: AppDomain → `AssemblyList`
(an `ArrayListBase` of chained `ArrayListBlock`s, walked via `Next`/`ArrayStart`) → filter by
`IsLoaded`/`IsCollectible`/`Error` → `Assembly.Module` → `SimpleName` (UTF-8), `Path`/`FileName`
(UTF-16). `ModuleLookupMap`s are segmented: read a segment's `Count`, index `TableData` if in
range, else subtract and follow `Next`; mask flag bits with `SupportedFlagsMask` (valid only on
the first segment); enumeration starts at index 1.

### 5.5 The honest gap

The .NET 9 descriptor's 29 types **do not include `AppDomain`, `Assembly`, or `ArrayListBase`**
(`baseline: "empty"` means nothing is inherited). So the descriptor gives us everything from a
*module or object pointer downward*, but not the layout needed to walk the assembly list from
the AppDomain root.

That is a one-time, cold-path problem with two clean answers:

- **ClrMD** (suspended, once at connect) to resolve the `sts2.dll` module pointer and any
  static-field addresses, then hand off; or
- start from any known managed object and go *upward*: `Object.m_pMethTab` (mask `0x7`) →
  `MethodTable.Module` (24) → the full `Module` layout above.

Either way, **nothing is hardcoded** and nothing depends on a per-version table.

---

## 6. Building our own

### 6.1 Scope

Not 888 KB. We need `Scry` (read primitives), the .NET Core module/object walk, and the Godot
struct layer. Mono, IL2CPP, the fingerprint heuristics, 32-bit variants, and the templated
dual-runtime object model are all out of scope.

### 6.2 Architecture

1. **Attach + primitives** (§4.1) — x64-only; drop pointer-width abstraction.
2. **Module discovery** (§4.2) — `coreclr.dll` by base name.
3. **Remote export resolution** (§4.3) — reused for the descriptor.
4. **Read the contract descriptor** (§5.1–5.3) — 40-byte header, JSON blob, `pointer_data`.
   Parse once at connect; cache the type/field map.
5. **Root bootstrap** (§5.5) — ClrMD cold, or object-upward.
6. **Hot loop** — raw `ReadProcessMemory` down offsets taken from the descriptor. No suspend.
7. **Godot layer** — `NativePtr` bridge, then engine struct offsets.
8. **Page cache + error contract** (§4.7, §4.8).

This is scry's runtime behavior with **zero hardcoded CLR offsets**, and it gets *better* over
time rather than worse: the cDAC's compatibility promise covers all runtimes ≥ .NET 9.

### 6.3 Component sources of truth

| Component | Source of truth |
| --- | --- |
| Attach, read primitives, module discovery | Documented Win32 |
| Remote PE export resolution | PE specification |
| CLR type/field offsets | **Contract descriptor (§5.2)** |
| CLR globals | **`pointer_data` (§5.3)** |
| Module/assembly walk algorithm | **Loader contract doc (§5.4)** |
| Root bootstrap | ClrMD, cold phase |
| Godot native layer | **§4.6 release table**, corroborated by Godot source |
| Error contract | §4.8 |

**Godot status — largely solved.** §4.6 now carries branch-verified release-template offsets for
`isVisible`, `getGlobalPosition`, `getOffset`, `getScale`, `getPosition`, `getSize`,
`Node.getParent`/`getChildren`/`getName`/`getDotNetCoreObject`, and `Label`/`RichTextLabel`
text — plus the linked-list and `CowData` mechanisms. The ordering independently matches
upstream `Control::Data`, and the variant flag is understood (debug vs release template, not
version).

**No fully external, non-injected Godot reader exists publicly** (§8.2 — Zolt-Dump is real prior
art, but injected and GPL v3), so this remains the novel part of the work —
but it is no longer the unknown part. Remaining risk is that StS2 runs a *modified* Godot 4.5.1;
confirm the offsets against a live process before shipping, and re-confirm after engine bumps.

### 6.4 Torn reads — retry is necessary but NOT sufficient

The hot phase is unsynchronized reads of a running game. `isTransientRead` and `READ_ATTEMPTS`
in `scryObject.ts:29` — including the half-written-pointer case and the deliberate exclusion of
address-zero reads — remain necessary, and port unchanged provided §4.8's error contract holds.

**But they are not enough.** §12.4e caught a live traversal returning 10 nodes short during a
scene-tree splice, with **every individual read succeeding**. Retry logic keyed on read failure
cannot see that class of bug; the result is a silently incomplete snapshot, which for an overlay
means a card or an enemy quietly missing rather than an error.

Add a structural guard:

- **Agree-twice** — traverse the subtree twice and accept only on identical results. Cheap given
  the measured cost (2,300 nodes traversed comfortably at 4 Hz, §12.4e).
- **Bounded walk** — where a count field exists, treat a shorter walk as a re-sample trigger.
- **Snapshot page cache** (§4.7) — the structural fix: one consistent memory image per snapshot
  closes most of the window rather than detecting after the fact.

This is the single most important implementation finding in the document.

### 6.5 Milestones

1. ~~**Descriptor spike**~~ — **DONE** (§12.1). Remote export walk, descriptor read, JSON
   byte-identical to static, AppDomain resolved.
2. ~~**Primitives**~~ — **DONE in prototype** (§12.1): attach, module discovery, remote export
   resolution, read set. Needs porting from PowerShell into the real sidecar.
3. ~~**Root + object walk**~~ — **DONE** (§12.2), with zero hardcoded CLR offsets.
4. ~~**Godot offsets**~~ — **DONE** (§12.3), 30/30 against a live game. Remaining: `Label.text`
   decode and the child-list walk under mutation.
5. **Consistency + contract** — page cache, error shapes, wire into `readerProcess.ts`.
   *The only milestone with no live evidence yet.* Build the PSS-vs-live diff oracle here (§8.8);
   it is the only way to catch §12.4e's silent tearing.
6. **ABI grid harness** (§8.9) — the Godot test project plus export/calibrate/report script.
   Gate for publishing `Godot.External`; also the first thing that exercises the §4.6 debug column.
   Start with 4.5.1-release, which is known-good, to validate the harness before trusting it.

The risky unknowns are gone. What is left is engineering: port the probes into a real sidecar,
add snapshot consistency, preserve the §4.8 error contract, and build the grid that decides
whether the Godot half is publishable.

Sidecar over N-API addon: a C# process on stdio/JSON needs no node-gyp and no
per-Electron-ABI rebuild, and matches how `readerProcess.ts` is already shaped.

---

## 7. Rejected alternative, for the record

**In-process mod.** StS2 ships a first-party mod loader (`mods/<Name>/{dll,pck,json}`,
`[ModInitializer]`, `0Harmony.dll` in the game directory, no exe patching), with `sts2.dll` and
`GodotSharp.dll` right there for typed access. Least work by far; removes offsets, torn reads,
and version fragility entirely. Rejected because it modifies the game install, which changes
the product. *(Unverified: achievement, Steam, multiplayer interactions.)*

---

## 7b. Investigate before building

Two things that are not "open questions about scry" but *are* prerequisites for our own reader.

### 7b.1 Managed addresses move; native pointers do not

Sampling `NGame.Instance` at 1.5 s intervals (probe 14) showed the managed address, native
pointer, and MethodTable all **stable across 30 s**. But comparing across sessions minutes apart,
the same singleton reported **`0x1a974c6c3e0` and later `0x1a974c6c240`** — it moved.

That is exactly what a compacting GC does. Consequences:

- **Never cache a managed object address across polls.** Re-resolve from the static each snapshot
  (`RunManager.Instance` → `RunState` → …). Resolution is cheap; a stale pointer is silently wrong.
- **Native Godot pointers are safe to cache within a scene** — unmanaged heap, and observed stable.
- `MethodTable` addresses live in loader heaps and were stable; they are reasonable to cache per
  module, which is what makes the §12.4d name-resolution route cheap.

This compounds §6.4's tearing problem: both failure modes produce *plausible* data rather than an
error, so a snapshot needs structural validation, not just successful reads.

### 7b.2 Godot offsets can be DERIVED, not hardcoded (proven)

The §4.6 table is build-specific — Godot version × release/debug template × precision × engine
fork. Hardcoding it means one validated cell of a large matrix. **Probe 15 shows the table can be
rediscovered at connect time instead**, against a fresh process with new ASLR and zero prior
knowledge of the offsets:

| Offset | How it was derived | Result |
| --- | --- | --- |
| child-list head `0x148` | the only pointer `p` in the object where `*(p + 0x18)` is a known child | **MATCH** |
| parent `0x128` | the only field equal to the known parent's native pointer | **MATCH** |
| size `0x4c0` | scan for the design viewport (`1920×1080`) on a full-screen Control, then **intersect** with a second Control of different size (`200×50`) | **uniquely derived** |

The intersection step matters: one sample gave a single candidate here but the second Control
alone produced four (`0x4c0`, `0x4c8`, `0x4d4`, `0x4f4`). Two samples with different values
collapse it to one. A third would harden it further.

**Caveat on this experiment.** Ground truth for the structural derivations came from scry, which a
real implementation would not have. It does not need it — the managed side supplies the same
truth: any two C# `GodotObject`s in a known parent/child relationship (e.g. `NGame` →
`RootSceneContainer`) expose `NativePtr`, giving the pointer pair to search for. Managed access is
fully self-describing (§5, §12.4d), so calibration bootstraps from the runtime with nothing
hardcoded. That path is designed but not yet implemented.

**Consequence for design:** the offset table becomes a *cache and a fallback*, not the source of
truth. Calibrate at connect, verify the derived values against the shipped table, and warn on
divergence — that turns an engine update from a silent breakage into a startup diagnostic.

### 7b.3 Read the metadata blob once, not per lookup

`Module.Base` → CLI header → metadata is **4,967,924 bytes** for `sts2.dll` (§12.4d). Do not walk
it remotely field-by-field. Bulk-copy it once per module at connect (§4.1 slot `+0x10` shows scry
already favours block reads) and parse locally — see §8.1 for the library that makes this trivial.

---

## 8. Prior art

- [microsoft/clrmd](https://github.com/microsoft/clrmd) — live-process CLR inspection (MIT).
  The cold-phase bootstrap.
- [dotnet/runtime datacontracts](https://github.com/dotnet/runtime/tree/main/docs/design/datacontracts)
  — descriptor format, Loader/Object/RuntimeTypeSystem contracts. **Primary reference for §5.**
- [GhostPack/KeeThief](https://github.com/GhostPack/KeeThief) — closest structural analogue:
  ClrMD against a live process, find a type, read its fields.
- [goldshtn/msos](https://github.com/goldshtn/msos) — SOS-like console on ClrMD.
- [JeffCyr/ClrMD.Extensions](https://github.com/JeffCyr/ClrMD.Extensions) — dynamic field
  access; maps onto our `ScryObject.read(key)` proxy.
- [hackf5/unityspy](https://github.com/hackf5/unityspy) — MIT rewrite of HearthSim's own (now
  closed) HearthMirror. **The direct architectural ancestor of this design**, not merely proof of
  feasibility: same external-read → managed-runtime → static-root → live-state → overlay pipeline.
  The difference is Mono/Unity rather than CoreCLR/Godot. See §8.4.
- [theXappy/RemoteNET](https://github.com/theXappy/RemoteNET) — `QueryInstances` / `Dynamify()`
  reflection-like remote access. Unusable here (injects a .NET host, uses Detours, executes code
  in-target), but **worth copying the API shape**: our consumer surface should read like
  `runManager.get('Instance').get('_players')`, not `readPtr(base + 0x…)`.

### 8.1 Libraries that remove work

| Need | Library | Verdict |
| --- | --- | --- |
| Parse ECMA-335 metadata (§12.4d) | **`System.Reflection.Metadata`** — `MetadataReader(byte*, int)` / `MetadataReaderProvider.FromMetadataImage` | **Use it.** Built into .NET, no extra dependency. Bulk-read the ~5 MB blob (§7b.2) and get fully typed table/heap access instead of hand-parsing `#~`, `#Strings`, `#Blob`. This is the single biggest saving available. |
| Parse the cDAC descriptor (§5.1) | **[chrisnas/RuntimeDataContract](https://github.com/chrisnas/RuntimeDataContract)** — **MIT** | **Vendor and adapt.** See §8.3 — this is our §6.2 steps 1–4, already written, under a permissive licence. |
| Parse the cDAC descriptor (official) | `Microsoft.Diagnostics.DataContractReader` (dotnet/runtime `src/native/managed/cdac`) | **Skip.** Not on NuGet — source-only. Useful as a semantics reference. |
| CLR object graph | [`Microsoft.Diagnostics.Runtime`](https://www.nuget.org/packages/Microsoft.Diagnostics.Runtime/) (ClrMD 4.x) | **Optional now.** §12.4d removed the need in the hot path. **Note:** ClrMD *is* external and read-only — its [security doc](https://github.com/microsoft/clrmd/blob/main/SECURE-CONFIGURATION.md) states it uses `OpenProcess`/`ReadProcessMemory` and injects nothing. It is unsuitable for the hot path purely because of its **consistency contract**, not invasiveness. |
| PE header parsing (§4.3) | `System.Reflection.PortableExecutable`, or hand-rolled | Hand-rolled is ~40 lines and already proven in probes 01/13; the BCL types expect a stream, which is awkward against a remote process. |
| Godot engine structs | [bbfox0703/Zolt-Dump](https://github.com/bbfox0703/Zolt-Dump) | **Do not link. Study only with care — see §8.2.** Substantial prior art, but injected and **GPL v3**. |

The shape this implies: **borrow for metadata, hand-roll the rest.** The remote read primitives,
PE export walk, and descriptor parse are each small and already validated by probes; metadata is
the one genuinely large format, and Microsoft ships a reader for it.

### 8.2 Correction: Zolt-Dump is real prior art

An earlier revision claimed *"no Godot external memory reader exists publicly."* **That was too
strong.** [bbfox0703/Zolt-Dump](https://github.com/bbfox0703/Zolt-Dump) is a real-time Godot
memory viewer that reads `ObjectDB`, `ClassDB`, `SceneTree`, `StringName`, and `Variant`, resolves
C# field names, covers Godot 3.5 through 4.6.x, and lists **Slay the Spire 2 (4.5.1, .NET/C#) as
an explicitly tested target**.

The accurate claim is narrower: **no public *fully external, non-injected* Godot runtime reader
was found.** Zolt-Dump reaches its capability by the opposite architecture:

| | Zolt-Dump | This design |
| --- | --- | --- |
| Access | proxy `winmm.dll` → injects `ZoltDumper.dll` | `ReadProcessMemory` only |
| .NET names | `ZoltReflector.dll` loaded into the target CLR | ECMA-335 read externally (§12.4d) |
| CLR offsets | version/game-specific, manual calibration | cDAC descriptor, self-describing (§5) |
| Status | **archived 2026-05-04** | — |
| License | **GPL v3** | — |

**Three reasons it is not a shortcut for us:**

1. **Injection is the constraint we exist to avoid.** Loading two DLLs into the game is a bigger
   modification than the mod-loader option already rejected in §7 — which at least is
   first-party and supported.
2. **GPL v3 is load-bearing.** Copying or linking its code would make this project GPL v3.
   Studying GPL source and then writing a same-purpose implementation also carries
   derivative-work risk. Treat it as *evidence that the problem is solvable*, not as a source.
3. **Its main asset is the one we need least.** Zolt-Dump's value is per-version offset/signature
   knowledge. §12.5 demonstrates those offsets can be **derived at runtime** — so we would be
   taking on a licensing liability to obtain a table we can compute.

**The clean path to the same knowledge: Godot itself is MIT.** `ObjectDB`, `ClassDB`, `SceneTree`,
`StringName` and `Variant` are all in
[godotengine/godot](https://github.com/godotengine/godot) under a permissive license. Anything
Zolt-Dump learned about Godot internals is derivable from that source without touching GPL code.

**Licence interaction worth knowing:** if this project ever ships **GPL v3 itself**, Zolt-Dump's
code becomes usable and objections 1–3 collapse to just "injection is the wrong architecture."
The licence decision therefore has strategic consequences (§8.4), not merely legal ones.

**Worth investigating (independently):** `ClassDB` is Godot's own self-description registry — the
engine analogue of the cDAC descriptor. If class/property information is reachable out-of-process
it could generalise the Godot layer the way the descriptor generalised the CLR layer. Caveat from
reading the engine design: `ClassDB` stores property *getter/setter method* bindings rather than
field offsets, so it likely yields names and class identity but **not** layout — useful, probably
not sufficient. Confirm against Godot source before relying on it.

**Caveat on `MetadataReader`:** Microsoft documents it as *not hardened against untrusted input* —
malformed metadata can cause out-of-bounds access. Here the input is the game's own metadata read
from its own mapped image, which is trusted, but validate the `BSJB` signature and stream bounds
(as probe 13 does) before handing the blob over.

---

### 8.3 RuntimeDataContract — our CLR substrate, already written

[chrisnas/RuntimeDataContract](https://github.com/chrisnas/RuntimeDataContract) (**MIT**) is an
independent from-scratch cDAC reader — no ClrMD, no matching DAC. Verified contents:

- **Three `IMemoryReader` backends** behind `bool ReadMemory(ulong, Span<byte>)`:
  `SelfMemoryReader`, **`LiveProcessMemoryReader` (`ReadProcessMemory`)**, `MinidumpMemoryReader`
- **`DescriptorLocator`** — for remote targets, `PeImage.FindExport` parses the CoreCLR module's
  PE export table **out of target memory** to locate `DotNetRuntimeContractDescriptor`
- **`Target` API**: `Read<T>` / `ReadPointer` / `HasGlobal` / `ReadGlobalPointer` / `HasType` /
  `HasField` / `GetFieldOffset` / `FieldAddress` / `ReadField<T>` / `ReadFieldPointer`, with
  presence guards so missing descriptor entries degrade instead of crashing
- Contracts implemented: **GC, Loader, ExecutionManager**

That is §6.2 steps 1–4 — attach, module discovery, remote export resolution, descriptor parse —
independently implemented and permissively licensed. **This is the single biggest saving in the
plan**, and it also confirms our §4.3/§5 reconstruction was correct, since it was arrived at
independently.

**Caveats — do not overstate it:**

- The author frames it as an **exploration/proof-of-concept**, not a production library, and the
  repo is very young (2 commits, 2 stars at time of writing). **Vendor and adapt it; do not take
  a dependency on it.** MIT makes that entirely legitimate.
- Its contracts target **runtime internals** (heaps, segments, code managers). Our need —
  `Module` → ECMA-335 → application object graph → Godot bridge — is *above* that layer and is
  not provided.
- The presence-guard pattern (`HasType`/`HasField` before use) is worth copying wholesale; it is
  the right answer to §5.5's "the .NET 9 descriptor doesn't publish everything".

### 8.4 Novelty, narrowed honestly

External cDAC reading is **not** novel. Two independent public precedents:

- **RuntimeDataContract** (§8.3) — remote `ReadProcessMemory` + PE export walk + descriptor parse.
- **[OpenTelemetry eBPF Profiler](https://github.com/open-telemetry/opentelemetry-ebpf-profiler)**
  — a production, explicitly non-intrusive whole-system profiler that loads nothing into target
  processes, with .NET 9/10 work involving `DotNetRuntimeContractDescriptor`.

Nor is the *pattern* new: HotSpot's **Serviceability Agent** has done runtime-publishes-its-own-
layout → external semantic reader for decades (via `VMStructs`), though it halts the target.

And the lineage is explicit: **UnitySpy / HearthMirror** established
*external process → `ReadProcessMemory` → managed runtime internals → classes/fields → known
static root → live game state → companion overlay*. This design is best described as **a modern
CoreCLR/Godot/cDAC descendant of that architecture** — which is a more credible framing than
claiming novelty wholesale.

What still has no public counterexample is the **combination**: no injected DLL, no mod, no hooks,
no suspension, no matched DAC, no hardcoded CLR-version table — while producing semantic C#
objects *and* native Godot SceneTree geometry from a live, unmodified game.

**Claim to make:** "no public fully out-of-process, non-injected, continuously-live Godot + CoreCLR
semantic reader." **Claim to avoid:** "nobody has built anything like this."

### 8.5 A cheaper input plane: logs and saves

[thequantumfalcon/spirescope](https://github.com/thequantumfalcon/spirescope) (**MIT**) is a live
STS2 tracker that **requires no mod and reads no memory** — it tails the game's `godot.log` and
reads save trees (`STS2_LOG_FILE`, `STS2_SAVE_DIR`), serving state over SSE with an OBS overlay.

Verified boundary: it exposes **run-level** state — deck, relics, potions, HP, floor history,
encounters, events — and **does not** expose in-combat data: no enemy HP/block, no intents, no
powers, no turn/round.

That boundary is almost exactly the split between what is cheap and what needs memory:

```
godot.log + saves  ──►  run-level state      (stable, no pointers, no GC, no tearing)
memory reader      ──►  combat state + UI geometry
                        (round/side, allies, enemies, block, powers,
                         Monster.NextMove.StateId, Control rects)
```

**Worth doing before assuming every field must come from memory.** Every field sourced from a log
line is one fewer moving GC pointer and one fewer intrusive-list walk exposed to §12.4e's tearing
window. Investigate what `godot.log` actually emits during combat before committing.

---

## 8.6 If we package this as a library

### Buy vs build, by layer

| Layer | Decision | Why |
| --- | --- | --- |
| Process memory read (`IMemoryReader`) | **Vendor** — RuntimeDataContract (MIT) | Written, three backends, right abstraction |
| Remote PE export walk | **Vendor** — same (`PeImage.FindExport`) | Written; matches §4.3 exactly |
| cDAC descriptor + `Target` | **Vendor + extend** — same | Written, incl. the presence guards §5.5 demands |
| ECMA-335 metadata | **Use** — `System.Reflection.Metadata` (BCL) | 5 MB format, Microsoft ships the reader |
| Cold root bootstrap | **Optional** — ClrMD | Only if the object-upward route (§5.5) proves awkward |
| Run-level state (deck, relics, HP, floor) | **Consider not reading memory at all** — §8.5 | `godot.log` gives it without pointers or GC |
| **App object graph** (module→type→static→fields→collections) | **Build** | Nothing public exists above runtime internals |
| **Godot native layer** | **Build** | Only Zolt-Dump, which is GPL + injected |
| **Offset calibration** (§12.5) | **Build** | Novel; what makes generality honest |
| **Snapshot consistency** | **Build** | §6.4 — the differentiator, and nothing has it |
| IPC to Electron | **Build** (trivial) | stdio/JSON |

Roughly **half the stack is already written under permissive licences.** What is genuinely ours
is the layer above the runtime and the layer beside it.

### Package structure

Three artifacts, two of them publishable:

```
DotNetLiveReader                       ← publishable, game-agnostic
  Memory/     IMemoryReader, LiveProcessMemoryReader        [vendored, MIT]
  Clr/        DescriptorLocator, Target, globals/types      [vendored + extended]
  Metadata/   ECMA-335 via System.Reflection.Metadata       [BCL]
  Objects/    ClrType, ClrObject, List<T>/array/string      ← NEW: the app object graph
  Snapshot/   page cache, agree-twice, retry, error shapes  ← NEW: consistency

GodotLiveReader                        ← publishable, engine-specific
  Bridge/     managed GodotObject → NativePtr               (depends on the above)
  Nodes/      Node, Control, Label, RichTextLabel
  Values/     StringName, CowData<char32_t>
  Layout/     offset table (fast path) + Calibrator (§12.5) ← NEW: the honesty layer

spectra-overlay                        ← stays private, not a library
  Sts2/       RunState, Player, Creature, Monster models
  Host/       sidecar, stdio/JSON, poll policy
```

The split matters: **`DotNetLiveReader` has no Godot in it and no game in it.** It is "read a
live, unsuspended .NET 9+ process's object graph by name" — useful far beyond this project, and
the piece with the strongest claim to being new. `GodotLiveReader` is where the fragile,
build-specific knowledge is quarantined.

### API shape

Follow RemoteNET's surface, not its machinery (§8):

```csharp
using var session = LiveSession.Attach(pid);

using (var snap = session.Snapshot())          // page cache + structural validation
{
    var rm     = snap.Clr.Type("MegaCrit.Sts2.Core.Runs.RunManager").Static("Instance");
    var state  = rm.Get("RunState");
    var player = state.Get("_players").AsList()[0];
    int hp     = player.Get("Creature").Get<int>("_currentHp");

    var node = snap.Godot.FromManaged(player.Get("Node"));   // NativePtr bridge
    var rect = node.AsControl().Rect;                        // calibrated offsets
}
```

Three design rules that fall straight out of the findings:

1. **`Snapshot` is the unit of work, not the accessor.** §6.4's torn walk means consistency has
   to be structural. A snapshot owns the page cache, re-resolves managed roots (§7b.1), and
   validates traversals; outside a snapshot there is no read API. This makes the correct thing
   the only thing.
2. **Managed handles never outlive a snapshot.** §7b.1 showed managed addresses move. Native
   Godot pointers may be cached across snapshots within a scene; the type system should make that
   distinction impossible to get wrong (`ClrObject` snapshot-scoped, `GodotNode` session-scoped).
3. **Calibrate, then verify against the table.** §12.5 derives offsets at connect; §4.6's table
   becomes a seed and a cross-check. Disagreement is a loud warning, not a silent fallback.

### What would make it dishonest to publish

- Shipping §4.6's table **without** the calibrator — that is the one-cell compat matrix problem.
- Claiming Godot support generally when only 4.5.1 release-template is measured. Scope the README
  to what has been *run*, list the rest as untested.
- Omitting §6.4. A reader that can silently return a short list, undocumented, is worse than no
  library.

### Licence consequence

`DotNetLiveReader` wants **MIT/Apache** — it is infrastructure, and permissive licensing is what
makes it adoptable (and it is what let us vendor RuntimeDataContract in the first place).
Choosing GPL v3 for it would foreclose the same reuse we benefited from, and cannot happen while
`vendor/untapped-scry` is still shipped (§9). `GodotLiveReader` could go either way — GPL there
would let it borrow from Zolt-Dump (§8.2), at the cost of the same adoption ceiling.

## 8.7 Framing it as a bridge

The STS2 ecosystem already has a name for this category. STS2MCP, HermesBridge and BoberInSpire
all do the same thing — *expose live game state to an external consumer* — and all of them do it
with **code running inside the game**. "Bridge" is the vocabulary those users already speak.

That suggests defining the product by its **contract** rather than its mechanism:

```
                    ┌──────────────────────────────┐
   providers  ──►   │   Bridge contract (schema)    │  ──►  consumers
                    └──────────────────────────────┘
  memory reader          run / combat / UI state          overlay
  godot.log tailer       versioned, provider-agnostic     OBS
  mod bridge (opt-in)                                     agent / MCP
  replay / fixture                                        tests
```

**Why this framing is better than "a memory reader":**

- **It makes the hybrid natural.** §8.5's log plane stops being a shortcut and becomes a second
  provider behind one contract, with an explicit merge policy (logs for run-level, memory for
  combat and geometry). Provider capability becomes data — `Capabilities { RunState: true,
  CombatState: false }` — so consumers degrade instead of breaking.
- **It states the differentiator precisely.** We are not claiming to invent bridging; the
  ecosystem is full of bridges. The claim is *a bridge that requires no code in the game*. That
  is narrow, true, and easy to verify — much stronger than an architecture-novelty claim (§8.4).
- **It future-proofs the rejected option.** §7 rejected the mod for changing the product. Under a
  provider model a mod can exist later as an **opt-in provider** for users who want it, without
  the default install touching the game. The rejection becomes a default, not a dead end.
- **It makes fixtures possible.** A replay provider that serves recorded snapshots is what lets
  the overlay be tested without launching StS2 — worth more than it sounds given §12's reliance
  on a live game.

**The structural caveat: a bridge is a *third* layer, not a rename.**

```
spectra-bridge         ← game-specific schema + provider selection   [STS2-shaped]
   ├── provider: memory   → GodotLiveReader + DotNetLiveReader
   ├── provider: log      → godot.log tailer
   └── provider: mod      → optional, opt-in
GodotLiveReader        ← engine-specific mechanism                    [game-agnostic]
DotNetLiveReader       ← runtime-specific mechanism                   [engine-agnostic]
```

Collapsing these loses exactly what made §8.6's split worth having: `DotNetLiveReader` is
infrastructure with no game in it. A bridge is inherently game-shaped. Keep them separate or the
reusable half stops being reusable.

**Two real risks, worth naming before adopting the frame:**

1. **A schema is a commitment, on a moving target.** StS2 is Early Access, and its modding
   documentation already warns that loader contracts and signatures shift between updates. A
   published bridge schema means versioning, deprecation and breakage reports on top of a reader
   that is itself chasing game internals. **Mitigation: define the schema internally, ship the
   overlay on it, publish only after it survives a few game patches.**
2. **Two audiences, two cadences.** The reader's audience is people building tools for
   .NET/Godot games; the bridge's audience is STS2 tool authors. Different release rhythms and
   different support expectations. Do not let bridge requests drive reader design.

**One assumption to test rather than assume:** the differentiator only matters to users who
*won't* install a mod. Every full-fidelity STS2 bridge today assumes users will. Whether the
no-mod segment is large is unmeasured — and it determines whether the bridge framing is a
product or a principle.

## 8.8 Final architecture (supersedes the §8.6 sketch)

One reusable CLR core, one deliberately narrow engine adapter, all game semantics private.

```
spectra-reader.exe                      PRIVATE sidecar (stdio/JSON → readerProcess.ts)
├── Spectra.Sts2                        PRIVATE — MegaCrit.Sts2.Core.* lives ONLY here
├── Godot.External                      PRIVATE until cross-version (§8.6 honesty rules)
└── LiveClr                             PUBLISH FIRST — MIT
      Memory/   IMemoryReader, WindowsProcessMemory, PageCache
      Cdac/     RuntimeDescriptor, RuntimeContractTarget, Layouts
      Metadata/ ModuleMetadata, TypeResolver        [System.Reflection.Metadata]
      Runtime/  ClrType, ClrField, ClrObject, ClrArray, ClrString
      Snapshots/LiveSnapshot, SnapshotValidator
      Calibration/ StructuralProbe        (engine-agnostic half of §12.5)
      Fixtures/ RecordedMemory            (serialize/replay page cache → CI without a game)

tests/
├── LiveClr.Tests                        unit, on recorded fixtures
├── LiveClr.IntegrationTests             LiveValidated vs PSS diff — the tearing oracle
├── Godot.External.Tests                 profile vs calibrator agreement
└── Spectra.Sts2.Tests                   model mapping on fixtures

tools/
└── godot-abi-grid/                      §8.9 — the publish gate for Godot.External
    ├── project/                         authored ground truth
    ├── build.ps1                        export across version × template × precision × binding
    ├── calibrate.mjs                    attach, calibrate, diff vs expected
    └── REPORT.md                        generated coverage matrix (committed)

vendor/reference/RuntimeDataContract/    NOT compiled — licence + adapt by hand
```

**Hard name boundary.** `MegaCrit.Sts2`, `RunManager`, `CombatManager`, `Monster`, card/intent
semantics, `godot.log`, save parsing and overlay DTOs must never appear in either reusable
library. §12.4b's paths (`RunManager.Instance → RunState`,
`CombatManager.Instance → StateTracker → _state`) are already clean enough to make this practical.

### Dependencies — final

| Piece | Decision |
| --- | --- |
| Win32 memory primitives | **Write it.** `OpenProcess`/`ReadProcessMemory`/`VirtualQueryEx`/`EnumProcessModules`/`GetModuleInformation` — five calls (§2). No dependency justifies this. |
| cDAC bootstrap | **Adapt, don't compile.** Keep RuntimeDataContract in `vendor/reference/` with its licence, port the small pieces behind our own `IRuntimeContractTarget`. It is a 2-commit repo with no releases — resembling Microsoft's `Target` model gives a clean migration path if the official NuGet ever ships. |
| ECMA-335 | **`System.Reflection.Metadata`.** Never hand-roll. |
| ClrMD | **Dev/test only** — correctness oracle, unknown-type inspection, cold bootstrap if needed. Never in the polling loop. |
| Zolt-Dump | **Reference only** (GPL, §8.2). |

### Lifetimes — corrected

An earlier draft said native Godot pointers are *session*-scoped. **That was wrong.** The CLR GC
does not move them, but **Godot can free a node and reuse the allocation** — so a stale native
pointer can address a different, entirely plausible-looking node. Silent, like §12.4e.

| Tier | Holds |
| --- | --- |
| **Process** | module info, cDAC descriptor, ECMA-335 blob + parsed tables, `MethodTable → ClrType`, field metadata |
| **Scene epoch** | Godot native `Node*`, validated names/type identity |
| **Snapshot** | managed addresses, static-root results, page cache, array/list contents, values |

Encode it: `ClrObject` cannot outlive a `Snapshot`; `GodotNode` cannot outlive a `SceneEpoch`.
This turns §7b.1 and §12.4e from documentation into type errors.

### Snapshot modes

```csharp
enum SnapshotMode { LiveValidated, ProcessSnapshot }
```

- **`LiveValidated`** — page cache + re-resolved roots + bounded traversal + agree-twice. No
  suspension. The product mode as currently understood.
- **`ProcessSnapshot`** — `PssCreateSnapshot`, which is what ClrMD itself recommends over
  unsuspended inspection.

**Its first job is as a correctness oracle**: diff `LiveValidated` against a PSS-coherent read to
build a randomized test for exactly the §12.4e tearing class — the one bug we found that is
otherwise silent.

**But benchmark it as a *product* mode before assuming it is too expensive.** PSS is
copy-on-write; if it is cheap enough at 4 Hz it *eliminates* the tearing class rather than
detecting it, which would be strictly better than agree-twice. That measurement has not been
taken, and it should be taken early — it could simplify the entire consistency layer.

### API invariant

```csharp
using var process  = LiveClr.Attach(pid);
using var snapshot = process.BeginSnapshot();

var run   = snapshot.Type("MyGame.RunManager").Static("Instance").AsObject();
int floor = run.Field("RunState").Field("ActFloor").ReadInt32();
```

**There is no semantic read API outside a snapshot.** No `process.ReadObject(addr)`, no
`process.GetField(...)`. Surface kept small on purpose: object, primitive, string, array,
`List<T>`, statics, inheritance, named instance fields — §12.4b showed that reaches full game
state without a reflection framework.

**Error model — do not leave this implicit.** `Validate()` must be *inspectable*, not throwing: an
overlay's correct response to a suspect snapshot is "reuse the last good one," which is impossible
if validation throws. Preserve §4.8's error shapes so `isTransientRead`/`READ_ATTEMPTS`
(`scryObject.ts:29`) port unchanged, and add a distinct *structural* failure signal for §6.4.

### Two additions

1. **A recorded-fixture provider.** Serialize a snapshot's page cache and replay it. Everything in
   §12 required a live game; without fixtures, `LiveClr.Tests` and `Spectra.Sts2.Tests` cannot run
   in CI at all. Cheap to build, and it is what makes the other tests possible.
2. **Split calibration.** §12.5 used two distinct techniques: *structural* (find the offset holding
   a known pointer — engine-agnostic, belongs in `LiveClr` or a shared utility) and *semantic*
   (size == design viewport — Godot-specific, belongs in `Godot.External/Abi`). Keeping them
   together buries a reusable trick inside the engine adapter.

### `godot.log` — deferred, but leave the seam

Reversing §8.5's ordering: **make the memory path complete and boring first.** A hybrid built too
early means every bug is ambiguous between memory, log latency, log parsing, and reconciliation
while the base architecture is still unproven.

But define the provider seam from day one (§8.7) even with a single implementation, so adding
`LogStateProvider` later is a new class rather than a refactor.

### Publishing order

1. **`LiveClr` — publish, MIT.** Not "another ClrMD": *semantic, read-only inspection of a
   continuously running .NET 9+ process via cDAC, with snapshot-scoped handles and no suspension.*
2. **`Godot.External` — later, conditional** on 2–3 materially different layouts or calibration
   maturing enough that the profile is a fallback.
3. **`Spectra.Sts2` — never.**

No separate `MemoryReader` / `CdacReader` / `MetadataReader` packages — plumbing, and Microsoft's
cDAC is heading toward owning that space.

## 8.9 Making `Godot.External` publishable — manufacture the compat matrix

The blocker on publishing (§8.6) is that we have measured **one cell**: Godot 4.5.1, release
template, single precision, one modified engine. Waiting to encounter more real games is a slow
and passive way to fix that.

**We can generate the matrix instead.** Godot ships official export templates for every version.
A minimal test project — a scene with Controls of *known* sizes, nested nodes with *known* names,
a Label with *known* text — exported across the axes gives ground truth we control completely:

| Axis | Values to cover |
| --- | --- |
| Engine version | 4.2, 4.3, 4.4, 4.5, 4.6 (whatever brackets our target) |
| Template | **release** and **debug** — the variant flag in §4.6 is exactly this |
| Precision | single and double (`real_t` width changes every float offset) |
| Binding | GDScript-only and **.NET/C#** (only the latter has the managed bridge) |

That converts the compat matrix from a liability into a **CI fixture**. Each build is a target the
calibrator must solve unaided; success across the grid is the evidence that justifies publishing.
It also directly tests the §4.6 debug column, which we deliberately left unresolved.

### Patterns worth taking from Zolt-Dump

Techniques and architecture are not copyrightable; **implementation is**. Take these from its
README, compat table and architecture description — not from reading its source (§8.2):

1. **Explicit ABI profiles per version/build**, rather than one global offset set. We already have
   `GodotAbiProfile`; Zolt shipping the same shape is independent confirmation it is the right
   decomposition.
2. **Calibration as a first-class step, not a fallback.** Zolt calibrates per target even with its
   offset knowledge. That we arrived at the same conclusion independently (§12.5) is corroboration.
3. **Publish measured coverage, not a binary "supported."** Zolt's table reports property-walk
   success *rates* per version and compiler. A README that says "4.5.1 release: 112/112 checks;
   4.3 debug: calibrated, 9/11 accessors" is honest in a way "supports Godot 4.x" never is.
4. **Its compat table tells us which axes actually matter** — it flags GCC vs MSVC differences,
   which is a fifth axis we would otherwise not have thought to test.

### Honest limit

Stock export templates are **not** the same as a modified engine — StS2 runs a customised 4.5.1,
and any real game may. So the grid validates **the calibrator**, not a lookup table. That is the
correct thing to validate: the claim becomes *"the calibrator solves layouts it has never seen,"*
which is testable, rather than *"we know every Godot layout,"* which is not.

Publish when the calibrator solves the grid unaided and the hardcoded profile has become a
cross-check rather than a dependency.

### The harness — concrete spec

```
tools/godot-abi-grid/
├── project/                     minimal Godot project, authored ground truth
│   ├── project.godot
│   ├── Main.tscn
│   └── Probe.cs                 forces a .NET build; exposes a static root
├── build.ps1                    export across the grid → out/<ver>-<tmpl>-<prec>-<bind>/
├── calibrate.mjs                attach to each build, run calibration, diff vs expected
└── REPORT.md                    generated coverage matrix (committed)
```

**Scene design — these details are load-bearing, learned from §12.5 and §4.6:**

- **Non-round, mutually distinct sizes.** Probe 15 got four candidate offsets for a `200×50`
  control because round numbers recur throughout memory. Use values like `613×227`, `409×151`,
  `887×313` — a single scan should then be near-unique, and two-control intersection certainly is.
- **≥ 3 sized Controls** so intersection has margin, plus one deliberately duplicated size to
  confirm the calibrator does not collapse distinct nodes.
- **Deep, uneven nesting** (≥ 6 levels, varying sibling counts) to exercise the intrusive
  child-list walk and `parent` in both directions.
- **Distinct ASCII node names**, and **one Label with non-ASCII text** — §4.6 found scry truncates
  `char32_t` → byte, which is silently lossy. Our decoder must not, and the harness should fail if
  it does.
- **Known visible/invisible pair** for `isVisible`, and non-default `scale` / anchor `offset`
  values so those accessors are exercised rather than reading zeros.
- **A `RichTextLabel`** — §4.6 gave it a separate text offset from `Label`.

**What `calibrate.mjs` asserts per build:**

1. structural offsets (child head, parent) derived by pointer identity alone
2. semantic offsets (size, position, scale, offset, visible) derived by known-value intersection
3. names and text decoded exactly, non-ASCII included
4. derived values agree with the §4.6 profile **where one exists** — disagreement is a loud
   failure, never a silent fallback
5. full-tree walk count matches the authored node count

`REPORT.md` emits the measured-coverage table §8.9 argues for, so the published README quotes
generated numbers rather than claims.

**Order of work:** build the grid against **4.5.1 release** first. That cell is already known good
(111/112), so it validates the harness itself before the harness is used to judge anything else.

---

## 9. A note on sourcing

Scry is `"license": "UNLICENSED"` and `"private": true`. The §4.5 table is recorded here
because it is *data about Microsoft's open-source runtime* — factual struct offsets, not
HearthSim's expression — and it is useful as a cross-check.

It should not end up in shipping code, for an engineering reason rather than a legal one:
those constants are valid only for one runtime version and build configuration (§4.5), whereas
§5 obtains the same values from the runtime itself, correct by construction, for every version.
Copying the table buys a maintenance burden we do not need.

---

## 10. Reproducing this

Ghidra 12.1.2 at `C:\Users\Brandon\ghidra\ghidra_12.1.2_PUBLIC`, JDK 21 at
`C:\Program Files\Microsoft\jdk-21.0.12.8-hotspot`. Scripts and the saved project live in the
session scratchpad. Extracted descriptor JSON: `scry_decomp/sts2_contract_descriptor.json`.

**Technique: follow references to anchor strings.** Byte-level scanning fails because the
interesting strings are built inline as SSO `std::string`s rather than referenced from `.rdata`
(§4.4). Ghidra's reference analysis, chasing one level of data-pointer indirection, finds them.
Where a reference lands outside any defined function (catch funclets, cold-split blocks), fall
back to the nearest preceding function — that is how the Godot and field-access paths were
located. Useful anchors: `g_dacTable`, `4.5.1`, `-debug`, `withPageCache`, `getSize`,
`getClassName`, `No such property`, `memory-access-exception`.

Import the `.node` renamed to `.dll` so the PE loader is unambiguous. PGO fragments **hot**
paths, but bootstrap and metadata code runs once at connect, sits in cold sections, and
decompiles nearly intact.

**The runtime is more informative than the binary.** The single highest-value step in this
whole analysis was not decompilation — it was reading `coreclr.dll`'s export table and parsing
40 bytes of static data.

---

## 11. Open questions — closed

Every question this investigation raised has been answered. Closed items, with where:

| Question | Answer | Where |
| --- | --- | --- |
| Is the `0xb8` constant runtime drift? | **No.** Only IDs `0x23`/`0x25`/`0x27` are used; `0x25` → `0x150` matches `Module.TypeDefToMethodTableMap` exactly. `0xb8` is an unpublished field between `Path` and `Base`. | §4.6b |
| Which Godot variant is release? | **Uniform across all 12 accessors** — release is always the second constant. The debug-column overlap is a real inconsistency in scry's own untested debug path. | §4.6 |
| Do the offsets hold on combat visuals? | **Yes — 60/60.** | §12.4c |
| Is `getGlobalPosition` cached or computed? | **Cached** — two `readFloat`s, no arithmetic. Hence the stale `[0,0]`. Keep `computeGlobalPosition`. | §4.6 |
| Can we resolve type/field names without scry or ClrMD? | **Yes** — descriptor offsets → `Module.Base` → ECMA-335 `BSJB` metadata → `#Strings`. | §12.4d |
| Does our child walk match scry's? | **100/100 identical, 0 errors**; ~184k pointer chases without a failure. | §12.4e |
| Is combat state readable? | **Fully** — creatures, HP, block, powers, deck, encounter, intent-as-string, RNG seed. | §12.4b |

| Does the child walk survive structural mutation? | **Mostly — but not always.** 23/24 mutating samples agreed with scry; one returned 10 nodes short, **silently**. Read-level retry cannot catch it. | §12.4e |

**The last question was also the most useful one.** Everything else confirmed the design; the
mutation test *changed* it. Torn traversals are silent, so §6.4's read-retry is necessary but
**not sufficient** — the reader needs a structural check (agree-twice, bounded walk, or snapshot
page-caching per §4.7) before it can be trusted during live combat.

Deliberately not pursued (superseded, not unknown): Mono and IL2CPP backends (unused), and
scry's own seven-layer field-resolution cache (§12.4d proves a simpler route).

**Assessment: the investigation is complete for its purpose.** The mechanism is understood end
to end; the Godot layer is recovered *and* live-validated at **111/112** across menu and combat
nodes (the single miss corrected a wrong assumption, §12.3b); and the .NET layer has a better answer, also
live-validated with zero hardcoded offsets. What remains is implementation, not discovery.

---

## 12. Live validation (2026-08-16)

Run against Slay the Spire 2 pid 146688, at the main menu, **read-only** throughout —
`OpenProcess` with `VM_READ | QUERY_INFORMATION`, no writes, no injection, game unsuspended.

### 12.1 Remote export + descriptor (§4.2, §4.3, §5.1–5.3)

```
coreclr.dll base      0x7FFE30DF0000          (ASLR'd; static image base is 0x180000000)
PE parse              machine=0x8664  optMagic=0x20B (PE32+)
export walk           12 names -> DotNetRuntimeContractDescriptor @ RVA 0x461D30
descriptor header     magic='DNCCDAC'  flags=0x1 (64-bit)  descriptor_size=3201
                      descriptor=0x7FFE311DC2A0  pointer_data_count=14
JSON blob             3201 bytes — BYTE-IDENTICAL to the static extraction
pointer_data[1]       -> &AppDomain = 0x7FFE31252780 -> AppDomain = 0x1A96EC71B30
```

Every RVA matched the static extraction exactly, and relocation was handled correctly.

### 12.2 CLR type walk with **zero hardcoded offsets** (§5.2)

Offsets taken *only* from the live descriptor (`MethodTable.Module=24`, `Module.Base=192`,
`MethodTable.ParentMethodTable=16`, `BaseSize=4`):

| Global | MethodTable | BaseSize | Parent | Module.Base → |
| --- | --- | --- | --- | --- |
| ObjectMethodTable | `0x7FFDD1234730` | **24** | `0x0` | `System.Private.CoreLib.dll` ✔ |
| StringMethodTable | `0x7FFDD134BF40` | **22** | ObjectMT ✔ | `System.Private.CoreLib.dll` ✔ |
| ExceptionMethodTable | `0x7FFDD134E260` | 120 | ObjectMT ✔ | `System.Private.CoreLib.dll` ✔ |
| ObjectArrayMethodTable | `0x7FFDD12F2170` | 24 | (Array) | `System.Private.CoreLib.dll` ✔ |

Four independent correctness signals: `Object.BaseSize = 24` and `String.BaseSize = 22` are the
known-correct x64 CoreCLR values; `Object.Parent = 0` because `Object` is the root of the
hierarchy; `String.Parent` resolves to exactly the `ObjectMethodTable` address; and every
`Module.Base` is a valid `MZ`/`PE\0\0` image whose address matches the loaded-module table entry
for `System.Private.CoreLib.dll`.

**This is §6.2 proven end to end.** The hot path needs no hardcoded CLR offsets and no DAC dll.

### 12.3 Godot offsets — 30/30

Scene tree traversal worked live (`getName`, `getChildren`, the `NativePtr` bridge). Five
Controls on the main menu, six checks each, comparing scry's own accessors against raw reads at
the §4.6 release offsets:

| Control | size | position | offset[4] |
| --- | --- | --- | --- |
| MainMenu | `[1920,1080]` | `[0,0]` | `[0,0,0,0]` |
| MainMenuBg | `[1920,1080]` | `[0,0]` | `[0,0,0,0]` |
| BgContainer | `[2560,1200]` | `[0,24]` | `[-960,-516,1600,684]` |
| MainMenuTextButtons | `[269,450]` | `[642,609]` | `[-318,69,-49,519]` |
| ContinueButton | `[200,50]` | `[34,50]` | `[34,50,234,100]` |

**30 match, 0 differ**, covering `size`, `position`, `scale`, `globalPosition`, `offset[4]`, and
`visible`.

### 12.3b Node-level and Label offsets — 21/21

A second pass (probe 05) covered what the Control pass did not:

| Offset under test | Result |
| --- | --- |
| `Node.getName` `0x1c0` → StringName `+8` → UTF-32 | **8/8** — `FmodBankLoader`, `AudioManager`, `Proxy`, … |
| `Node.getChildren` `0x148`, next@`+0`, payload@`+0x18` | **4/4** — exact child address *sequences* matched |
| `Node.getParent` `0x128` | **4/4** — parents resolved to the root `NativePtr` as expected |
| `Label.getText` `0x800`, CowData length at `ptr-8` | **5/5** — `"Controller Detected"`, `"Connection Interrupted"`, `"[v0.107.1] (2026.06.18)"` |

The 22nd check — `getDotNetCoreObject` at `0x68` — **failed, and that failure was the useful
part**: it exposed the `ScriptInstance` → GCHandle chain documented in §4.6. The table entry has
been corrected accordingly. Everything else in §4.6 is confirmed.

Incidental: the live `Label` read recovered the game's own build string,
**`[v0.107.1] (2026.06.18)`** — worth recording, since every offset here is valid *for that
build*.

### 12.4 In-run gameplay read (Act 1, Floor 4, MerchantRoom)

Validated against an actual run, not the menu. Full snapshot read live, read-only:

```
character    Necrobinder          hp  61/66      gold 130     energy 3
act / floor  1 / 4                ascension 0    room MerchantRoom
in combat    false
deck (19)    4x DEFEND_NECROBINDER   4x STRIKE_NECROBINDER   1x AFTERLIFE
             1x BODYGUARD  1x DEATH_MARCH  1x DIRGE  1x ENFEEBLING_TOUCH
             1x EQUILIBRIUM  1x HANG  1x MASTER_OF_STRATEGY
             1x SLEIGHT_OF_FLESH  1x SOUL_STORM  1x UNLEASH
```

**Entry points** (managed statics in `sts2.dll`):

| Static | Gives |
| --- | --- |
| `MegaCrit.Sts2.Core.Runs.RunManager.Instance` | → `RunState` (found by scanning its fields for that class) |
| `MegaCrit.Sts2.Core.Combat.CombatManager.Instance` | `IsInProgress`, `IsPaused`, `StateTracker`, `History` (31 fields) |
| `MegaCrit.Sts2.Core.Nodes.NGame.Instance` | `RootSceneContainer._currentScene` → e.g. `NRun` |
| `MegaCrit.Sts2.Core.Context.LocalContext.NetId` | local player id |

**Shape of the data:**

- `RunState` — `ActFloor`, `AscensionLevel`, `GameMode`, `_currentActIndex`, plus `_players`,
  `_allCards`, `_currentRooms`, `Map`, `Acts`, `_visitedMapCoords`, `Rng`, `Odds`
- `Player` — `_gold`, `MaxEnergy`, `NetId`, `Character` (e.g. `Necrobinder`), `Creature`
- `Player.Creature` — `_currentHp`, `_maxHp`
- `_currentRooms[0]` class name *is* the room type (`MerchantRoom`)

**Four API facts that matter for the build:**

1. **`getFieldNames()` is on the CLASS, not the object.** Objects expose only `get`,
   `getBaseAddress`, `getClassName`. To enumerate an instance, take its `getClassName()`, look
   the class up via `module.getClass(name)`, and read field names from there. Cache per class —
   this is the single biggest cost in a naive traversal.
2. **`.NET List<T>` walks as `_items` (backing array) + `_size`.** `_items.length` is capacity,
   not count; using it over-reads into stale entries.
3. **Model identity is free.** Every model object carries `Id`, a `ModelId` with string fields
   `{ Category, Entry }` — `{"CARD", "STRIKE_NECROBINDER"}`. **No numeric-id mapping table is
   needed**; `EntrySortingId` is an internal sort key, not the identity. Card objects also carry
   `_canonicalInstance`, `_owner`, `_pool`, `_currentUpgradeLevel`, `CanonicalEnergyCost`,
   `Rarity`, `Type`.
4. `enumerateProperties: true/false` made no difference to field enumeration in these tests.

This is the combat/run-scene coverage §11 listed as unverified. The same accessors work; nothing
new was needed.

**Polling stability.** A watcher (probe 07) polled `CombatManager.IsInProgress` every 3s for
100s — **35 consecutive reads, zero errors, zero torn reads**, against a live unsuspended
process while the player was active. First direct evidence that the unsuspended hot-loop design
(§6.2) behaves.

### 12.4b Live combat — everything the overlay needs is readable

Caught an active fight (Act 1, Floor 5, `NibbitsWeak` encounter). Read live, read-only:

```
CombatState   round=1  currentSide=1 (player)
badges        CCC_COMBO_MODEL (_cardsPlayedThisTurn=0), DEBUFFER_MODEL
_allCards     11  — the in-combat deck (3x STRIKE_NECROBINDER, 4x DEFEND_NECROBINDER,
                    BODYGUARD, UNLEASH, HANG, ENFEEBLING_TOUCH)
_allies       2   — player Creature CombatId=0 hp 61/66 block 0 Side=1
                    summon      CombatId=2 hp 1/1  _powers: DIE_FOR_YOU_POWER=1
_enemies      1   — Creature CombatId=1 hp 43/43 block 0 Side=2
                    MonsterMaxHpBeforeModification=43
```

**Path to combat state:** `CombatManager.Instance` → `StateTracker` → `_state` (a `CombatState`)
→ `_allies` / `_enemies` / `_allCards` / `_encounter` / `BadgeModels`. The room also exposes it
as `CombatRoom.CombatState`.

**Creature** — `CombatId`, `Side` (1 = player, 2 = enemy), `_currentHp`, `_maxHp`, `_block`,
`_powers` (list of models, `POWER_ID=amount`), and `Monster` for enemies.

**Enemy identity and intent — both readable strings:**

```
Creature.Monster                     Id = { MONSTER, NIBBIT }
  .NextMove        <MoveState>       StateId = "BUTT_MOVE"
     .FollowUpState <MoveState>      StateId = "SLICE_MOVE"
  ._moveStateMachine._currentState   StateId = "BUTT_MOVE"
  ._moveStateMachine._initialState   ConditionalBranchState BranchId = "INIT_MOVE"
  ._isAlone / ._isFront / ._isPerformingMove / ._spawnedThisTurn
```

**Intent is `Monster.NextMove.StateId`** — a string, with the follow-up move also visible. No
sprite reading, no icon matching, no numeric lookup table.

**RNG and seed** are exposed too: `Monster._rng` `{Counter, Seed}` and `_runRng`
`{Seed: 3403250353, StringSeed: "Z8EWEAWBHT"}` — the run's seed string.

**One probe bug worth recording:** `System.Collections.Generic.List\`1` *has* a class name, so
"has a class name → treat as object, else treat as list" silently reports every collection as
empty. Check for the `List` prefix explicitly. This cost two wasted reads and would be an easy
bug to ship.

This closes the last item §11 listed as unverified. Every piece of state the overlay needs —
run, deck, player vitals, allies, enemies, powers, intents, seed — is readable out of process,
unsuspended, with readable string identifiers throughout.

### 12.4c Combat-scene Godot nodes — 60/60

The §12.3 pass covered menu Controls. A second pass (probe 11) targeted **combat UI nodes** in a
live fight — `HpBarContainer` `[210,16]` and `[294,16]`, `HpBarHitbox` `[258,26]`, `Intents`
`[1000,40]` and `[1000,64]`, `Intent` `[64,64]`:

**60 checks across 13 nodes, 0 differ.** The release offsets hold on combat visuals exactly as
they do on menu Controls.

Incidental confirmation: `engine.getControl()` on non-Controls (e.g. an `AudioStreamPlayer`)
returns denormal garbage such as `2.6e-38` — but scry and our raw reads produce *the same*
garbage, which is itself evidence we are reading identical bytes. It also underlines §12.5:
there is no type check, so validate by plausibility.

### 12.4d Type/field names without scry or ClrMD — proven

Probe 13 closes the field-name-resolution question. Using **only** offsets published by the
runtime's own descriptor (`Object.m_pMethTab=0`, `ObjectToMethodTableUnmask=0x7`,
`MethodTable.Module=24`, `Module.Base=192`):

```
managed object  0x1a974c6c240  (MegaCrit.Sts2.Core.Nodes.NGame)
  -> MethodTable 0x7ffdd1808c70
  -> Module      0x7ffdd15029c8
  -> Module.Base 0x1a902200000     'MZ' / PE\0\0   VALID
  -> CLI header  rva 0x2000 (cb=72)
  -> metadata    'BSJB'  version "v4.0.30319"   5 streams
       #~ 3,031,628   #Strings 577,064   #US 621,000   #GUID 16   #Blob 738,108
```

Real identifiers were then read straight out of the `#Strings` heap. **Type and field names are
reachable with no scry and no ClrMD** — just the descriptor plus the documented ECMA-335 layout.

This means the *entire* pipeline (§6.2) has a dependency-free path: descriptor for CLR struct
offsets, ECMA-335 metadata for names, raw reads for values.

**A trap worth recording:** JavaScript bitwise operators truncate to 32-bit **signed**, so
`ptr & ~0x7` corrupts any 64-bit pointer. Use arithmetic (`p - (p % 8)`) or `BigInt`. This
produced a nonsense `MethodTable 0x-2e7f7390` before it was caught.

### 12.4e Walk robustness

Probe 12 compared our raw-offset child walk against scry's, over the whole tree, repeatedly:

- **100 paired traversals, ours vs scry: identical every time, 0 mismatches, 0 errors**
- a separate 4 Hz sampler traversed **2,308 nodes × 80 iterations ≈ 184,000 pointer chases in
  20 s with zero failed reads**, against a live unsuspended process

**Under structural mutation — a real defect, observed.** Once active play resumed, the tree
began mutating heavily (`+33/-0`, `+0/-33`, `+12/-52`, `+24/-3` …). Across 24 observed mutations:

```
t14: nodes=2341 ourWalk=2341 IDENTICAL  MUTATED +33/-0
t20: nodes=2301 ourWalk=2301 IDENTICAL  MUTATED +12/-52
t21: nodes=2306 ourWalk=2296 MISMATCH   MUTATED +10/-5    <-- torn walk
```

**23 of 24 mutating samples agreed exactly. One did not:** our walk returned **2296 nodes where
scry returned 2306** — ten nodes short — while the tree was being spliced.

This is the intrusive-list tearing failure mode, and it matters more than it looks:

- **It is silent.** No exception, no failed read, no `memory-access-exception`. The walk simply
  terminates early when a `next` pointer is sampled mid-splice.
- **`isTransientRead` (§4.8) will not catch it.** That path keys off *read failures*; here every
  read succeeded and returned a plausible pointer. Read-level retry is not sufficient.
- Final tally over the full run: **299 samples, 26 mutations, 1 mismatch, 0 read errors.** Roughly **4% of mutating
  samples tore, and 0% of the ~45 static ones** — so the risk is concentrated exactly where the
  overlay is busiest.

**Design consequence:** the reader needs a *structural* sanity check on top of read-level retry —
e.g. walk twice and accept only when two consecutive traversals agree, bound the walk by a
`children`-count field where one exists, or treat a shrink beyond some threshold as suspect and
re-sample. Snapshot page-caching (§4.7) would also close most of this window by making one
traversal read a consistent memory image.

This was the last open question, and it is the one that changed the design.

### 12.5 Godot offsets can be DERIVED, not hardcoded

The strongest objection to generalising the Godot layer was the compat matrix: version × build
template × precision × engine fork, of which we had validated one cell. Probe 15 tests whether
the offsets can instead be *discovered at connect* from independently-known ground truth.

Method — no prior knowledge of any offset, only structural and semantic anchors:

| Offset | Anchor used | Derived | Expected | |
| --- | --- | --- | --- | --- |
| child-list head | the only pointer `p` where `*(p+0x18)` is a known child | `0x148` | `0x148` | **MATCH** |
| parent | the only slot in a child equal to the parent's own pointer | `0x128` | `0x128` | **MATCH** |
| size | scan for the design viewport `1920×1080` as an adjacent float pair | `0x4c0` | `0x4c0` | **FOUND** |

The naive size scan on a *second* control (200×50) returned four candidates
(`0x4c0`, `0x4c8`, `0x4d4`, `0x4f4`) — but intersecting the candidate sets across two controls of
different sizes leaves exactly one:

```
INTERSECTION (offset valid for BOTH): 0x4c0
=> size offset UNIQUELY derived as 0x4c0 with zero prior knowledge.
```

**Implication.** A general reader does not need a per-build offset table; it needs a *calibration
pass* — two or three objects with independently-known values, intersected. The hardcoded table in
§4.6 becomes a fast path and a self-check rather than a dependency, which is exactly what turns a
one-cell compat matrix into something honestly general.

Not yet tested: calibration against a *different* Godot version or a debug template. The method is
version-agnostic by construction, but that is an argument, not a measurement.

### 12.6 Practical notes

- scry returns vectors as **array-likes** (`{0:…,1:…}`), not true `Array`s — `Array.isArray()`
  is false. Use `Object.values()`.
- `raw.readFloat()` takes a **Number**, not a BigInt.
- `engine.getControl(addr)` succeeds on non-Controls and returns garbage; there is no type
  check. Validate by plausibility or by class name.
- N-API is ABI-stable, so `untapped-scry.node` loads in plain Node.js (v24 tested) with no
  Electron and no rebuild — which is what made this validation cheap.

Re-run after any game update: the probes are in
[`docs/reference/probes/`](reference/probes/).
