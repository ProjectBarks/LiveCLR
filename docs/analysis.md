# untapped-scry — how it works, and how to build our own

Analysis dates: 2026-08-16 – 2026-08-17. Subject: `vendor/untapped-scry` 6.12.6 and
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

> **Sharper than "version-keyed": scry has no version table at all.** The parser stores
> `{u16 major, u16 minor, u16 patch, …, u8 isDebug}` — and **major/minor/patch are never read by
> anything.** Every accessor tests exactly one byte, `*(char*)(engine + 0x3c)`. There is no
> 4.3-vs-4.5 branch anywhere in the binary.
>
> That is a significant limitation, not a simplification: scry's Godot offsets are correct for the
> one engine version they were measured against and silently wrong on any other. §12.7's measured
> table shows how far apart 4.3 and 4.5 actually are (`control.offset` moves `0x68`). Calibration
> is not a nicety here — it is the difference between supporting one build and supporting the
> engine.

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

### `CanvasItem::visible` and its thirteen decoys

`visible` is **one full byte, no mask** — and it sits in a run of booleans that are exactly what a
value-scanning calibrator loses to. Layout verified from `scene/main/canvas_item.h`, **identical in
4.3 and 4.5** with no `#ifdef`s. With `V` = offset of `visible`:

| Offset | Field | Runtime behaviour |
| --- | --- | --- |
| `V−12` / `V−11` | `z_relative`, `y_sort_enabled` | static |
| **`V−8`** | **`Window *window`** | **a pointer — the key discriminator** |
| **`V+0`** | **`visible`** | the stored property |
| `V+1` | `parent_visible_in_tree` | true iff all ancestors visible — decoy |
| `V+2` | `pending_update` | **flips every frame** |
| `V+3`…`V+7` | `top_level`, `drawing`, `block_transform_notify`, `behind`, `use_parent_material` | mixed |
| `V+8` | `notify_local_transform` | static, usually 0 — decoy |
| `V+9`…`V+10` | `notify_transform`, `hide_clip_children` | static |
| `V+12` | `clip_children_mode` (u32) | ∈ {0,1,2} |

Note `is_visible_in_tree()` is **computed**, never stored — so there is no cached tree-visibility
byte to confuse with the property.

**Two structural discriminators that need no timing:**

1. **`visible` is always ≡ 0 (mod 8).** `CanvasItem`'s prefix through `window` is exactly `0x80`
   bytes and `sizeof(Node)` is 8-aligned. That single rule eliminates **11 of the 13** boolean
   decoys; only `visible` and `notify_local_transform` survive.
2. **Read the qword at `V−8`.** For real `visible` that is `Window *window` — zero or a canonical
   heap pointer. For `notify_local_transform` the same qword spans eight bools, so it is non-zero
   with every byte ≤ 1. Reject on that pattern and the last decoy is gone.

> **A temporal stability test discriminates against the correct answer here.** In a live UI
> `visible` genuinely toggles between two readings — cards, tooltips, panels animating — so
> "the byte must be identical across two reads" rejects the *real* field while the stable decoys
> are eliminated by the differs-between-pair test, leaving nothing. That is precisely the
> "never wrong, always absent" failure §12.7 measured at 11 of 24 runs. Structure beats sampling.

**Also: the calibration pair must differ in the node's *own* flag.** If a node is invisible because
an *ancestor* is hidden, `visible` is identical on both and the byte that differs is
`parent_visible_in_tree` at `V+1`.

**Independent corroboration.** Godot's
[`scene/gui/control.h`](https://github.com/godotengine/godot/blob/master/scene/gui/control.h)
declares `Control::Data` in the order `real_t offset[4]` → `real_t anchor[4]` → focus/grow
enums → `real_t rotation` → `Vector2 scale` → … with `pos_cache` / `size_cache` later. The
release column reproduces exactly that shape:

```
0x370  CanvasItem visible
0x3f8  (cached origin — see attribution note below; NOT a Control::Data member)
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

**Attribution correction for `0x3f8`.** It is listed inside the `Control::Data` mapping above, but
upstream `Control::Data` has no such member and `0x3f8` sits well *below* `offset[4]` at `0x470`.
It is far more likely a `CanvasItem`/transform-level cached origin. The **offset is not in doubt** —
it is validated 30/30 as "what `getGlobalPosition` returns" — only the attribution. That matters,
because it explains why this field's staleness is *structural* rather than incidental: it is a
cache maintained by a different layer than the one whose coordinates callers expect.

**Branch direction — settled for every accessor.** All twelve emit the identical pattern:

```c
lVar = <debug constant>;
if (*(char *)(engine[1] + 0x3c) == '\0') { lVar = <release constant>; }
```

So the **release value is uniformly the second constant**, with no exceptions. The `pattern`
rows in the table above are therefore as reliable as the `branch` rows.

That also settles the debug-column oddity: `getOffset` really does read `0x500..0x50c` while
`getPosition` reads `0x508/0x50c` on the debug path — a genuine **overlap in scry's own debug
constants**, confirmed in the disassembly, not a misreading on our part.

**There is a second debug-column defect**, found while encoding the table: debug `scale` (`0x4f8`)
sits *below* debug `offset` (`0x500`), **inverting the field order** that the release column and
upstream `control.h` both agree on (`offset[4]` → `anchor[4]` → … → `scale`).

> ### The debug column is now MEASURED, and it was wrong — replace it
>
> The ABI grid exported real stock Godot templates and derived the offsets independently
> (§12.7). **8 of 13 debug values here are contradicted.** The measured column is self-consistent
> (`offset < scale < position < size`, matching release); this one was not. Use the measured table
> in §12.7. The only entry this column got right is `node.scriptInstance` at `0x70`.
>
> The recovered pattern is much simpler than either guess: **debug = release + `0x8`, uniformly,
> for every field in both 4.3 and 4.5.** The debug template is
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
Node*  +0x68 -> ScriptInstance*        (0x70 on the debug template)
                  +0x00   vtable pointer (inside the game exe's .text)
                  +0x08   back-reference to the owning Node*
                  +0x20   GCHandle  ->  *(handle) == managed C# object
```

For `NGame`: `native=0x1a9204c5580` → `scriptInstance=0x1a90351dd30` → `+0x20 = 0x1a96f941360`
→ dereference → `0x1a974c6c240`, exactly the managed object address scry reports. The `+0x08`
back-reference is a cheap self-check that you followed the right pointer.

This is the route from a scene-tree node to the C# object holding game state, so it matters.

**Caveat on the inner two hops.** `NodeScriptInstance` has both a release and a debug value
(`0x68` / `0x70`), but `+0x08` and `+0x20` were **only ever observed on the release template** and
are presented above without a column — which makes them look universal. If the debug template pads
`Node`, it may pad `ScriptInstance` too. Untested in either direction; treat them as
release-measured, not build-independent.

**Do not mask the GCHandle's low bits.** Some CLR handle encodings tag them, and the live capture
happened to be aligned. Masking would silently repair precisely the wrong-pointer case the `+0x08`
self-check exists to catch — a misaligned slot should be reported as suspect, not quietly fixed.

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

**There is a third header word, and it is the one that makes validation possible.** `CowData`'s
layout is `REF_COUNT_OFFSET = 0`, `SIZE_OFFSET = 8`, `DATA_OFFSET = 16` — identical in 4.3 and 4.5,
with `USize = uint64_t`. So for a `_ptr` **P**: `size` is at `P−8` and **`refcount` at `P−16`**.

That second header word is an *independent* constraint a random qword will not satisfy, and
together with `P % 16 == 0` and the NUL terminator at `P + (size−1)*4` it is what distinguishes a
real Godot `String` from arbitrary pointer-shaped bytes.

**Scry performs none of these checks.** Its entire validation is a single `ptr == 0` early-out — a
wrong offset either throws or silently returns garbage. Copying its trust model is how a calibrator
ends up decoding a different wrong address on every run.

**Two traps in that recipe, found while implementing it:**

- **The stored count includes the trailing NUL.** A literal implementation of steps 1–4 appends
  `U+0000` to every string. Stop at the first NUL — correct under either convention.
- **`- 8` is `sizeof(USize)`, not a universal constant.** It is the x64 case; derive it from
  pointer width rather than hardcoding, or a 32-bit target reads the refcount as the length.

`getName` instead walks code units one remote read at a time — noticeably worse, and both paths
then truncate each `char32_t` to a byte when building the JS string. **Fine for ASCII, lossy for
anything else.** Our implementation should decode UTF-32 properly and always use the bulk read.

Vtable slots observed across the Godot layer: `+0x00` bool/byte, `+0x10` readBytes (bulk),
`+0x28` float, `+0x40` pointer, `+0x60` uint32, `+0x68` uint64/size.

### 4.6b — Scry's Godot layer is 18 hardcoded immediates, and nothing else

Re-derived exhaustively from the binary with a capstone harness (PE + `.pdata`, all 2,488 functions
disassembled) rather than by sampling. **This negative result is load-bearing** — it is the
justification for building a calibrator at all, so it is recorded as measurement, not impression.

Every native read in scry's Godot layer goes through one code shape, and there are exactly 18 sites:

```
mov  edx, <debug const>
mov  r9d, <release const>
cmp  byte ptr [rax + 0x3c], 0    ; rax = engine[1], +0x3c = isDebug
cmove edx, r9d
add  rdx, [engine]
call <vtable read primitive>
```

`cmp byte ptr [reg+0x3c]` occurs 19 times binary-wide; 18 are these, 1 is unrelated. Counting the
accessors independently — CanvasItem 3, Control 9, Node 4, Label 1, RichTextLabel 1 — also gives 18.
**The enumeration is complete; there is no other mechanism anywhere in the binary.**

**Scry uses no Godot reflection of any kind.** Zero occurrences of `ClassDB`, `ObjectDB`,
`get_property_list`, `StringName`, `Variant`, `SceneTree`, `MethodBind`, `bbcode`, `xl_text`,
`visible` or `godot` — searched as ASCII, as UTF-16, and as the 8-byte immediate fragments MSVC emits
for stack-built SSO strings. **Scry never locates the Godot module at all**: the only module-name
comparison in the binary targets `coreclr.dll`, and there is no PE export walk against the game
executable. The entire Godot API surface is six class names and thirteen methods in one `.rdata`
cluster, with no `getClassName` and no type check on the native side.

**One binary across Godot versions? It does not do that.** The version string is parsed into
`{major, minor, patch, …, isDebug}` and stored at engine `+0x30..+0x3d` — but scanning every memory
operand in the binary shows **major, minor and patch are never read by anything**. The only field
consumed is the `isDebug` byte, set by `strstr` against the literal `"-debug"`. Scry's offsets are
correct for the single build someone measured and silently wrong on every other, which §12.7 confirms
directly: 4.3 moves `visible` by `0xa8` and the whole `Control` block by `0x60`, and scry has no way
to express that.

So the calibrator is not solving a problem scry solved more cleverly. **It is solving a problem scry
never attempted.**

One consequence for the harness: because scry truncates each `char32_t` to its low byte (above), it
**cannot serve as an oracle for the non-ASCII grid fixtures** — against `ρich ✦ テキスト 𝄞` it will
disagree with a correct decoder and the correct decoder will be the one that is right.

**Scry's `Label.text` offset may be `xl_text`, not `text`.** Godot declares `String text` immediately
followed by `String xl_text`, and `Label.getText`'s debug−release delta is `0x48` — one `String` slot
short of the `0x50` that most of the table shows — which would be consistent with its release
constant pointing at the translated copy and its debug constant at the original.

> **The delta argument is weaker than this section originally claimed, and does not stand on its
> own.** An exhaustive re-derivation from the binary (capstone over all 2,488 functions) measured the
> deltas directly: **9 of 13 are `0x50`, not "every other constant".** The exceptions are
> `scriptInstance` (`0x8`), `Label.text` (`0x48`), `Control.offset` (`0x90`) and
> `RichTextLabel.text` (`0xa0`) — four, not one. `Label.text` is therefore not an anomaly against a
> uniform background; it is one irregular value among several. And since §12.7 established that
> scry's debug column is contradicted 8 of 13 times by measurement, the deltas are computed from
> numbers already known to be junk. Treat this paragraph as *consistent with* the `xl_text` reading,
> never as evidence for it. It never mattered to scry because `set_text` does `xl_text = atr(text)`, and the
non-translating path returns by value — so `CowData::_ref()` shares the allocation and
**`xl_text._ptr == text._ptr` exactly, with refcount ≥ 2.** The two only diverge when a translation
actually resolves, at which point their contents legitimately differ.

Practical rule: accept either slot of the pair and prefer the lower.

> **§4.6's `Label.text` release value is wrong.** The ABI grid's calibrator, knowing none of the
> above, derived **`0x7f8`** from target memory alone, and its set is internally consistent
> (`debug = release + 8`): 4.5-rel `0x7f8`, 4.5-dbg `0x800`, 4.3-rel `0x8f0`, 4.3-dbg `0x8f8`.
> Repeated across nine grid series with zero deviation. So **`0x800` is `xl_text` and `text` is
> `0x7f8`.**
>
> This was originally written up as *two* independent routes agreeing — a decompiled delta anomaly
> and a live derivation. **It is one route.** The delta anomaly does not survive measurement (see the
> correction above): `0x48` is one of four irregular deltas, not a lone outlier against a uniform
> `0x50`, and it is computed from a debug column that §12.7 contradicts 8 of 13 times. The live
> derivation is the sole support for `0x7f8`. That support is strong on its own — but the corroboration
> claimed here never existed, and a conclusion believed for two reasons when only one is real is
> exactly the kind of thing this document is supposed to catch.
>
> The table below still records `0x800`, which is what scry uses and what §12.3b validated *as a
> readable string* — it just happens to be the translated copy, which is why nobody noticed. Prefer
> `0x7f8` for `text`. This is also the first time a text offset has ever been cross-checked in this
> project, and it failed on the first attempt, which is the harness doing its job.

**`RichTextLabel` has no `xl_text` member at all** — `_apply_translation()` uses a local. It has
exactly one stored `String`, holding the **raw BBCode source**, so any expected-text comparison
against *rendered* text will never match on a bbcode-enabled node.

**Composing global position has a type trap.** `Control.position` is a `Control` field, but the
scene tree contains non-`Control` ancestors. Walking up and reading that offset off, say, an
`AudioStreamPlayer` returns garbage rather than failing — the same denormal `2.6e-38` behaviour
§12.4c observed from `engine.getControl()` on a non-Control. The value layer has no type
information, so composition must take an "is this ancestor a Control?" gate supplied by the scene
layer. Also note composition is **translation-only**: a scaled or rotated ancestor is unhandled,
as in scry's own `computeGlobalPosition`.

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

**Block size, measured — and 4 KiB is the wrong default for a scene walk.** Benchmarked against the
live game, a 4 Hz subtree poll fell from **105,740 syscalls / 71 ms to 5,980 / 11 ms** with a page
cache. But the winning block was **512 bytes**, not 4 KiB: a Godot `Control` is ~1.3 KB, so only
**1.76 nodes land in a 4 KiB page** and such blocks read **43.8 bytes for every byte a walk actually
consumes**.

Measured cross-node locality on the live game: **1.76 nodes per 4 KiB page**, with only 6.7% of
BFS-consecutive node pairs sharing one. Poor, but not absent.

| Workload | Variant | Syscalls | Amplification |
| --- | --- | ---: | ---: |
| tree walk | uncached | 15,616 | 1.00× |
| tree walk | **page-512** | 3,887 | 13.17× |
| tree walk | page-4k *(LiveClr default)* | 1,618 | **43.84×** |
| tree walk | span (object-granular) | 4,453 | 16.45× |
| geometry | page-16k | 3,400 | **314.64×** |
| 4 Hz poll | **page-128** | 8,320 | **1.24×** |
| 4 Hz poll | page-512 | 5,980 | 3.55× |

The design expected to win — object-granular, fetching a whole node struct on first touch — **lost**,
and was *strictly dominated* by `page-512` on the tree walk: fewer syscalls, fewer bytes, faster.

The reason is that the fields this reader touches **cluster**: a walk reads `0x148` and `0x1c0`,
120 bytes apart; geometry reads `0x370` and `0x470–0x4c8`. A small aligned block fetches only the
clusters a given workload uses, while a ~1,224-byte object span always fetches all of them. That
held even on a synthetic heap with deliberately scattered allocation.

> **Amplification, not hit rate, is the metric that exposes this.** A cache can report a healthy hit
> rate while reading two orders of magnitude more bytes than the caller uses. Measure
> bytes-read-per-useful-byte, or a page cache will look like a success while being the bottleneck.

**Caching must also be opt-in and scoped.** A cache that never invalidates has now silently defeated
a temporal check three times in this project (§6.4's agree-twice, the calibrator's two-readings
check, and `visible` derivation). The resolution that works: the source **announces** coherence and
the weaker check steps aside *visibly*, with a counter recording the substitution — rather than
being cancelled by accident.

### 4.8 Error surface

`ScryMemoryAccessException` → JS `type: 'memory-access-exception'`. Read failures format as
`Failed to read <N> bytes from remote address <ADDR>:` (`FUN_180051620`). Both are load-bearing
in `scryObject.ts:23` — `isTransientRead` keys off the exception type and the
`remote address 0+:` pattern. **Our implementation must preserve this contract** or that retry
logic silently stops working.

**The trailing colon is a separator, not punctuation — and the whole contract is stricter than it
looks.** The classifier is:

```js
if (/remote address 0+:/.test(m)) return false                       // null deref: never retry
return m.includes('Invalid access to memory location')
    || m.includes('Only part of a Read')                             // otherwise: retry
```

So a message ending at the address matches **neither** arm and `isTransientRead` returns false for
everything — retry silently never fires. The colon terminates the address for the `0+:` test *and*
introduces the appended Win32 error text that the second arm actually matches. Full shape:
`Failed to read {N} bytes from remote address {ADDR:X}: {win32 message}`.

**Measured caveat:** `ReadProcessMemory` returns `ERROR_PARTIAL_COPY` (299) for a **wholly
unmapped** address as well as a straddling one — the Win32 error does *not* distinguish a torn
read from a bad pointer. Both are retryable so behaviour is unaffected, but nothing should be
built on "299 means torn". Only pre-syscall rejections (`ERROR_NOACCESS`, 998) can be labelled
precisely.

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
"Array":       { "m_NumComponents": 8, "!": 16 }        // "!" = TYPE SIZE (see below)
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

**Correction on `"!"`.** An earlier revision annotated it as "element base", inferred from `Array`
where element data does start at 16. That generalises wrongly: `"!"` is the type's **total size**.
`GCHandle` carries `{"!": 8}` with no fields at all, and `MethodDescChunk` carries `{"!": 24}`
alongside five real fields — neither is an element base. Both readings coincide for `Array` only
because an array's header size *is* where its elements begin.

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
`pointer_data`**, which holds the *address of* the global.

**There are two legal spellings and only one appears in our fixture.** Per the official cDAC
`data_descriptor.md`, the compact form is unambiguous by *outer array length*:

| Spelling | Meaning |
| --- | --- |
| `"G": [[12], "pointer"]` | indirect — `pointer_data[12]` holds the address of `G` (what .NET 9 emits) |
| `"G": [12]` | **also indirect** — one-element array is unambiguously an indirect value |
| `"G": [12, "uint32"]` | literal — two elements are "value and type" |

The bare `[12]` form is easy to misread as a typeless literal, which silently turns a
`pointer_data` **index** into the global's **value** — a small, plausible integer, the §6.4 failure
class exactly. The .NET 9 descriptor always publishes types, so a fixture-driven test will not
catch it; a .NET 10+ or non-CoreCLR descriptor using the terse form would corrupt every indirect
global.

Verified against the shipped DLL:

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
the first segment).

> **None of `Count`, `Next` or `SupportedFlagsMask` is published by the .NET 9 descriptor** (§5.5).
> So this documented algorithm cannot be implemented as written: bound the walk by the metadata row
> count instead of a segment `Count`, and **derive** the flag mask rather than reading it — the
> field-offset calibration in §8.8 exists partly for this reason. What follows describes the
> contract, not what .NET 9 lets you do.

Enumeration starts at index 1.

### 5.5 The honest gap

The .NET 9 descriptor's 29 types **do not include `AppDomain`, `Assembly`, or `ArrayListBase`**
(`baseline: "empty"` means nothing is inherited). So the descriptor gives us everything from a
*module or object pointer downward*, but not the layout needed to walk the assembly list from
the AppDomain root.

**The full gap list, as found by implementing against it** — this section originally named only the
first row:

| Missing from the descriptor | Consequence |
| --- | --- |
| `AppDomain`, `Assembly`, `ArrayListBase` | cannot walk the assembly list from the root |
| `FieldDesc`, `EEClass.FieldDescList`, MT token field | instance offsets must be **calibrated**, not read (§8.8) |
| `DomainLocalModule`, MT auxiliary data | **static** addresses have no route *and no calibration anchor* — ClrMD required |
| `ModuleLookupMap.Count` / `.Next` / `SupportedFlagsMask` | §5.4's segment-chaining walk cannot be implemented as written — bound the walk by the metadata row count instead |
| `EEClassOrCanonMT` union tag | try both readings, accept whichever closes the `EEClass.MethodTable` back-pointer loop |
| `MTFlags` bit meanings | component size must be *checked* against `StringMethodTable` (must report 2) and `ObjectArrayMethodTable` (must report a pointer), never assumed |

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

> **Correction — these two are not complementary, they cancel.** An earlier revision listed
> agree-twice and the page cache as stacking mitigations. Inside one snapshot they do not: the page
> cache serves the second traversal **the identical frozen bytes**, so agree-twice is a guaranteed
> no-op and detects nothing. The two are alternatives at different scopes:
>
> | Scope | What actually helps |
> | --- | --- |
> | Within one snapshot | the page cache (or PSS) — agree-twice is dead weight here |
> | Across snapshots | agree-twice — the only way to notice the world moved between them |
>
> Pick per scope. Running both inside a snapshot buys nothing and reads like defence in depth.

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
knowledge of the offsets.

**Measurements are in §12.5** — do not duplicate them here.

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

**Correction — this cannot be a compile error, and claiming it could was wrong.** The only C#
construct expressing "cannot outlive" statically is `readonly ref struct`, and ref structs cannot
go into a `List<T>` — which a 2,300-node tree walk requires. What is actually achievable, and what
was built:

- **inert address types** — a `NativePtr`/`ManagedPtr` distinction so passing a managed address to
  a native accessor does not compile, and the address types have no method that reads memory
- **handles obtainable only from a live scope**, as classes with no accessible constructor (so no
  `default` with a null owner)
- **a runtime failure at point of use** — every read re-enters the owning scope, which throws once
  expired

That is a strong runtime guarantee plus a genuine compile-time guarantee about *pointer kind*. It
is not "documentation becomes type errors", and the design should not be sold as if it were.

### Snapshot modes

```csharp
enum SnapshotMode { LiveValidated, ProcessSnapshot }
```

- **`LiveValidated`** — page cache + re-resolved roots + bounded traversal + agree-twice. No
  suspension. The product mode as currently understood.
- **`ProcessSnapshot`** — `PssCaptureSnapshot`, which is what ClrMD itself recommends over
  unsuspended inspection.

> **Measured, and it settles the open question: PSS is NOT a viable product mode.** An early
> benchmark on a small test host gave ~1 ms and this section speculated it might replace the whole
> consistency layer. Against the **real game** (316 MB working set) the median capture is
> **193 ms** (188–196). At 4 Hz that is a fifth of every second spent capturing, with a 193 ms
> stall each time — unusable for an overlay. Cost scales with the target's VA size, exactly as the
> caveat warned.
>
> PSS remains valuable as a **correctness oracle** in tests, which is where it now belongs. The
> page cache stays the product mechanism.

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

> **The `.Static("Instance")` step in that example is not achievable on .NET 9 alone.** Building it
> exposed a gap §5.5 anticipates in general but this section presented without caveat. The
> descriptor publishes **no** `DomainLocalModule`, no `MethodTable` auxiliary data, no `FieldDesc`,
> and no managed static whose address is already known — so unlike instance fields there is not
> even a **calibration anchor** to derive one from. Static roots need ClrMD (cold, suspended, once
> at connect) exactly as §5.5 prescribes; the address is process-tier cacheable and the value is
> re-read per snapshot (§7b.1).
>
> **Instance** fields *are* derivable: the descriptor publishes eight of `System.Exception`'s
> managed field offsets plus `ExceptionMethodTable`, giving eight independently-known answers to
> calibrate the `FieldDesc` encoding against — §12.5's technique applied to the runtime itself.
> Convergence on all eight is the safety property: a wrong guess fails to converge rather than
> producing a plausible offset.

**Error model — do not leave this implicit.** `Validate()` must be *inspectable*, not throwing: an
overlay's correct response to a suspect snapshot is "reuse the last good one," which is impossible
if validation throws. Preserve §4.8's error shapes so `isTransientRead`/`READ_ATTEMPTS`
(`scryObject.ts:29`) port unchanged, and add a distinct *structural* failure signal for §6.4.

### Two additions

1. **A recorded-fixture provider.** Serialize a snapshot's page cache and replay it. Everything in
   §12 required a live game; without fixtures, `LiveClr.Tests` and `Spectra.Sts2.Tests` cannot run
   in CI at all. Cheap to build, and it is what makes the other tests possible.

   **But a fixture is a snapshot, not a history — it cannot be the §12.4e tearing oracle.** An
   earlier revision of this section conflated the two. A coalesced single image *by construction*
   cannot reproduce a torn walk: the tearing signal is **two reads of the same address disagreeing
   across time**, and coalescing collapses exactly that. The two artifacts are distinct:

   | Artifact | Gives you |
   | --- | --- |
   | Recorded fixture (one image) | deterministic CI for parsing, layout, decoding |
   | **PSS diff against live** | the tearing oracle — a coherent reference to compare against |
   | Fixture *sequence*, or per-read sequencing in the container | a replayable tearing regression |

   Build the container versioned with a flags word so per-read sequencing is an additive v2, and
   do not assume fixture replay already covers §12.4e. **PSS is the oracle that works today** —
   measured at ~0.7–1.0 ms per capture, well inside a 4 Hz budget.
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

## 8.8b One implementation of each parser — a finding from building it

The PE header walk is needed twice: to find `DotNetRuntimeContractDescriptor` in the export table
(§4.3), and to reach ECMA-335 via data directory 14 (§12.4d). Written independently, the two copies
**drifted within a single build session**, and the weaker one silently lacked three bounds checks:

| Check | Export copy | Metadata copy |
| --- | --- | --- |
| `e_lfanew` upper bound | `0x1000` | `0x1000_0000` — chases a bad base 256 MB into other memory |
| `NumberOfRvaAndSizes` | capped at 16 | unbounded (only `<= 14` tested) |
| `SizeOfImage` / RVA bounds | enforced | **absent entirely** |

The third is the dangerous one. Pages adjacent to a loaded module are routinely mapped, so a stale
`Module.Base` could read a plausible-looking COR20 header out of a neighbouring allocation — the
§6.4 wrong-but-plausible failure, occurring inside the parser whose job is to prevent it.

**Rule: one implementation of each format parser, taking the _union_ of hardening.** Where copies
disagree the stricter wins — unless the difference is genuinely scope-specific and documented (the
machine-type filter belongs only to the export path, which dereferences pointers out of the image;
applying it to the metadata path would make ARM64 modules unreadable for no safety gain).

## 8.9 Making `Godot.External` publishable — manufacture the compat matrix

The blocker on publishing (§8.6) is that we have measured **one cell**: Godot 4.5.1, release
template, single precision, one modified engine. Waiting to encounter more real games is a slow
and passive way to fix that.

**We can generate most of the matrix instead.** Godot ships official export templates for every version.

> **Correction — the precision axis cannot be downloaded.** Official templates are
> **single-precision only**. `precision=double` requires building the engine from source
> (`scons … precision=double`), so those 8 cells cannot be filled by installing anything. This is
> the most expensive gap in the plan, because `real_t` width changes **every float offset** — it
> is precisely the axis most likely to break a calibrator, and the one we can least cheaply test.
> Budget for a source build, or scope the published claim to single precision and say so.
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
- **At least one Control with NON-ZERO anchors.** `Control::Data` places `anchor[4]` immediately
  after `offset[4]`, so with all-zero anchors a calibrator that locks onto the *wrong one of the
  two* still looks correct. This is the tie-breaker for that pair, and it is invisible without it.
- **Non-ASCII must include an astral character** (e.g. U+1D11E `𝄞`) — one `char32_t`, two UTF-16
  units. BMP-only samples miss surrogate-pair handling, and Latin-1 misses the truncation bug
  entirely: U+00E9 truncated to `0xE9` and re-widened is `é` again, so `café` round-trips *through*
  a lossy decoder and proves nothing.
- Record in `expected.json` what a **truncating** decoder would emit, so a failure names the §4.6
  bug rather than printing a generic mismatch.

**Build-script trap:** PowerShell 5.1's `Get-Content`/`Set-Content` default to ANSI and will
silently destroy the non-ASCII fixtures — producing a "the calibrator is lossy" verdict actually
caused by the build script. Do all file I/O through explicit UTF-8-no-BOM .NET calls.

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

## 10b. Live validation of the reimplementation

The C# rewrite was run against the real game for the first time — pid 418440, CoreCLR
9.0.725.31616, the exact build §5.2's descriptor was extracted from.

| Step | Result |
| --- | --- |
| Attach + module discovery | **PASS** — 198 modules, `coreclr.dll` @ `0x7FFD41C20000`, 1.0 ms |
| Remote PE export walk | **PASS** — descriptor found at `coreclr+0x461D30`, 3.5 ms |
| Descriptor header + JSON | **PASS** — `DNCCDAC\0`, 3201 B |
| **Byte-exact vs static extraction** | **PASS** — identical char-for-char; 0 diffs across 29 types / 95 offsets / 22 globals |
| ECMA-335 for `sts2.dll` | **PASS** — 9410 typedefs, 40038 fielddefs, real names resolved |
| Field values vs independent reader | **PASS** — 11/11 objects, **90/90 field values agreed** |
| Snapshot lifetime / `Validate()` | **PASS** — bad pointer counted not crashed; disposed → not usable, no throw |

**The descriptor route is confirmed end to end against a live runtime.** That was the central
architectural bet and it holds.

### 10b.1 The calibration converged — on the wrong width

`FieldDescCalibration` derived `m_dwOffset` as bits `[0,28)` at `+12`. CoreCLR's actual layout is
`m_dwOffset : 27` then `m_type : 5`. **One bit too wide**, swallowing the low bit of `m_type`.

Measured cost: **7,234 of 23,235 instance fields (31.1%) unreadable** — every non-enum struct
field, every `double`, every unsigned integer. Any field with an odd `m_type` has bit 27 set, so
the decode returns `offset + 0x8000000`.

**Why the search did not catch it is the real lesson.** All eight published `System.Exception`
anchors have *even* `m_type` (CLASS=18, I4=8), so bit 27 is zero in every sample and widths 27 and
28 reproduce all eight identically. **The anchor set cannot distinguish them.**

> **An anchor set can be insufficient in a way that is invisible from the anchors themselves.**
> Convergence on a unique candidate proved only that the samples could not tell the difference —
> not that the answer was right. A bit that is zero across every sample is *absence of evidence*,
> not evidence the bit belongs to the field, and claiming it is the unsafe direction.

**The root defect** was that the width search kept the *last* matching width per position and
emitted a single tuple, so 27 and 28 were never two candidates to refuse between — they were
silently merged into "28". The ambiguity rule had nothing to fire on.

**"Prefer the narrowest" is the wrong fix, and would have been worse than the bug.** An earlier
revision of this section recommended it. The anchors span offsets 0..100, so the *narrowest*
matching width is **7 bits** — every field past offset 127 would decode to `real & 0x7F`: a small,
plausible number comfortably inside `BaseSize`, which the guard cannot catch. That trades a loud
31% loss for silent corruption of every large object. **Neither direction is derivable from eight
even-`m_type` samples.**

The fix that works is a **second constraint from real target data**: walk a corpus of real
`FieldDesc` rows from a module's own type map and count `BaseSize` violations. Take the widest
width with zero violations — which guards the narrow end, since a truncating width would otherwise
win — and accept it only if the next bit up is *demonstrably* not ours (excluded by an anchor,
overflowing `BaseSize` in the corpus, or past the word edge). If neither anchors nor real data can
separate the two, refuse. **The boundary is observed, never assumed**, and the constant `27`
appears nowhere in the implementation.

Measured after the fix: **31.1% unreadable → 0%.**

### 10b.2 What held

**The failure was fail-safe.** `RuntimeFieldLayoutSource`'s `BaseSize` guard caught 8/8 broken
fields, and `offset >= 0x8000000` guarantees it always will. Fields went *missing*; none came back
**wrong**. That is the property §6.4 was designed around, tested against a real defect rather than
a hypothetical one.

**And the end-to-end comparison got lucky.** 90/90 agreement was real, but the reference reader
only surfaces *scalar* fields — so no struct field was ever in the comparison set. The bug was
found by an independent audit walking every `FieldDesc`, not by the agreement test. A passing
comparison bounded by the weaker tool's coverage is not the reassurance it appears to be.

---

## 12.7 The ABI grid ran — measured offsets across two engine versions

§8.9 proposed manufacturing the compat matrix from stock export templates, and §8.6 made publishing
`Godot.External` conditional on the calibrator solving a layout it had never seen. Both were run
for real against Godot 4.5-stable and 4.3-stable.

### The gate is met

`4.3-release-single-gdscript` and `4.3-debug-single-gdscript` each scored **12/15 on the first
attempt**, with `calibration.unaided` green and **no 4.3 profile in existence**. Every derived
offset was verified against the authored scene — sizes, positions, scales, anchor offsets,
visibility, all 20 `StringName`s, child order, parent round-trip.

**The calibrator derives layouts it has never seen.** That is the claim §8.9 said was worth
publishing, demonstrated rather than argued.

### Measured offsets

Derived independently by both bindings, which agreed exactly:

| Field | 4.5 release | 4.3 release | 4.5 debug | 4.3 debug |
| --- | --- | --- | --- | --- |
| `node.parent` | `0x128` | `0x128` | `0x130` | `0x130` |
| `node.childListHead` | `0x148` | `0x150` | `0x150` | `0x158` |
| `node.name` | `0x1c0` | `0x1d0` | `0x1c8` | `0x1d8` |
| `canvasItem.visible` | `0x370` | `0x418` | `0x378` | `0x420` |
| `control.offset` | `0x470` | `0x4d8` | `0x478` | `0x4e0` |
| `control.scale` | `0x4a8` | `0x508` | `0x4b0` | `0x510` |
| `control.position` | `0x4b8` | `0x518` | `0x4c0` | `0x520` |
| `control.size` | `0x4c0` | `0x520` | `0x4c8` | `0x528` |
| `childList.next` / `.node` | `0x0` / `0x18` | `0x0` / `0x18` | `0x0` / `0x18` | `0x0` / `0x18` |

Two structural facts fall out:

- **Debug is release + `0x8`, uniformly** — every field, both versions. The §4.6 debug column's
  irregularity was error, not engine behaviour.
- **4.3 → 4.5 is not a uniform shift.** `node.parent` unchanged, child-list head `−8`, name
  `−0x10`, and the whole `Control` block `−0x60` (`visible` `−0xa8`, `offset` `−0x68`). A
  per-version table is unavoidable; calibration is what makes that survivable.

### Two cross-checks worth more than the table

**§4.6's release column is confirmed 10/10 — and the "modified engine" caveat is retired.** The
grid derived those offsets from scratch on a **stock** 4.5 template, and they match the values
recovered from the shipped game. Every prior section warning that StS2 runs a *modified* Godot and
so upstream layouts may not apply was right to be cautious, but for the `Control` block the fork's
layout **is** the stock layout.

**§4.6's debug column is contradicted 8/13**, exactly as it suspected of itself — see the
correction there. A later run gave a **third** independent confirmation: the harness's
`profile.agreement` check fails on both 4.5-debug cells, and the derived values preserve the
release field ordering while the shipped debug column does not.

### Reproducibility

The grid was then re-run **three times at one attempt per cell** — 24 cell-runs — after fixing a
nondeterminism in the calibrator's root location. Results:

- **Zero offset disagreements** across 40 result files spanning six full grid runs. All 32 table
  entries confirmed on every cell, every run, with zero run-to-run drift. The measured offsets are
  reproducible, not a lucky sample — which is the claim that matters, since a calibrator that
  derives a *different* answer each run would be useless regardless of whether any single answer
  was right.
- `4.5-release-single-dotnet` reached **17/17 on three consecutive runs** — the first cell to score
  full marks reproducibly.
- **But 5 of 8 cells still flip between runs**, so the matrix as a whole is not yet evidence. One
  cell scored 16/16 in a single run out of three; that number is not quotable and was not quoted.
  The remaining instability is concentrated in two derivations (`canvasItem.visible`, and text
  offsets that are found per-node rather than per-class) rather than being spread across the ABI
  work.
- A new binding-dependent fact fell out: `scriptInstance.ownerBackref` is `0x8` on .NET cells and
  `0x10` on GDScript cells, stable across all runs. It appears in no profile yet. This is a
  *per-binding* fact, not a per-version one — a GDScript instance and a C# instance are different
  C++ classes implementing `ScriptInstance`, so the owner pointer need not sit in the same place.

**Two traps in reading the matrix, both worth knowing before quoting a number:**

- **Score stability is not check stability.** One cell held a constant 14/15 across three runs while
  the *failing check changed* underneath it — `semantic.visible` in one run, `strings.text.rich` in
  the next two. A stable score can hide two alternating defects.
- **`profile.agreement` can be passed by deriving *less*.** One cell passed "9/9 offsets match" in
  two runs and failed "1/11 disagree" in the third — the only difference being that the third run
  managed to derive two *more* offsets. The compared-count varies per run, so a green
  `profile.agreement` is weaker evidence than it reads, and a cell that derives nothing passes it
  trivially.
- **Zero root-location failures**, against a prior regime of roughly 2-in-5 success on one cell and
  14/14 failures on another. The harness's retry workaround was deleted as a result.
- The managed bridge (`Probe.Instance` → `NativePtr` → walk root, plus the reverse
  `ScriptInstance` → GCHandle chain) passes on **all four** .NET cells.

**A retry loop that hides nondeterminism is worse than a red cell.** The harness had grown one to
work around the defect, disclosed in every report row. Fixing the cause and deleting the workaround
is what makes the matrix mean anything — a green obtained on the sixth attempt is not the same
claim as a green obtained on the first.

### Harness defects found by running it

The harness had only ever driven a mock. Five real bugs surfaced, all fixed without weakening a
check:

1. **A .NET export silently produced a broken game.** Godot's exporter needs a `.sln`, which
   `--build-solutions` does not create headless. It logged ERROR, **exited 0**, and wrote a valid
   native `grid.exe` with no managed payload — which then died with `0xC0000005`. "The exe exists"
   is not success.
2. **The ground truth was wrong about the tree.** `RichTextLabel` adds an internal
   `@VScrollBar@2` child that `.tscn` parsing and `get_children()` both hide — but a memory walk
   cannot. Asserting 20 nodes while the walk found 21 did not merely fail the cell: it made the
   *correct* layout unacceptable, so the search settled on an unrelated `SelfList` chain that
   threads every node and crashed the driver.
3. **The scene could not separate the parent pointer.** Godot caches it three times
   (`Node::data.parent`, `CanvasItem::parent_item`, `Control::data.parent_control`), and in an
   all-`Control` tree all three are identical for every pair. Fixed by making one sibling a bare
   `Node`.
4. **net8.0 exports were unmeasurable by construction** — the bundled .NET 8 runtime exposes no
   readable `DotNetRuntimeContractDescriptor`, so the managed bridge could never be tested.
5. `build.ps1` must stay ASCII — PS 5.1 reads it as ANSI and an em dash is a parse error.

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

**Two validation gotchas found while implementing this:**

- **The stream sizes do not sum to the metadata size, and that is correct.** The five streams total
  4,967,816 against a stated 4,967,924 — a 108-byte gap, which is the metadata *root header*
  (signature, version block, stream header table) and belongs to no stream. Bound each stream
  against the blob independently; summing sizes as a consistency check will report a false error.
- **Validate the CLI header's own `cb` against the ECMA-335 floor of 72 bytes** (observed live:
  `cb=72`), not just the data-directory entry. A garbage `Module.Base` otherwise yields a
  plausible-looking RVA/size pair that survives naive checks.

This means the *entire* pipeline (§6.2) has a dependency-free path: descriptor for CLR struct
offsets, ECMA-335 metadata for names, raw reads for values.

**One step this section glosses over.** Going from a `MethodTable` to its TypeDef token — which is
what makes the metadata lookup possible at all — has no published field: the descriptor exposes no
token on `MethodTable`. The working route is to **invert `Module.TypeDefToMethodTableMap`** in one
bulk read per module. Cheap and process-tier cacheable, but it is a step, not a given.

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

| Offset | Anchor used | Derived | Expected | Samples needed |
| --- | --- | --- | --- | --- |
| child-list head | the only pointer `p` where `*(p+0x18)` is a known child | `0x148` | `0x148` | **1 — unique** |
| parent | the only slot in a child equal to the parent's own pointer | `0x128` | `0x128` | **1 — unique** |
| size | scan for an adjacent float pair matching a known Control size | `0x4c0` | `0x4c0` | **2 — AMBIGUOUS on one** |

**Read that last row carefully — it is the design lesson, not a footnote.** The structural probes
are uniquely determined by a single sample because pointer identity is a strong constraint.
Semantic probes are **not**: a scan of a `200×50` control alone yields four candidates
(`0x4c0`, `0x4c8`, `0x4d4`, `0x4f4`). Only intersecting across controls of *different* sizes
collapses it to one. An API that lets a caller derive a semantic offset from one sample is wrong
by construction.

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

---

## 13. Resolving offsets by NAME — the getter-disassembly route

**Status: validated 3/3 against the shipped export templates. This is the most significant finding
in the project and it changes what the calibrator has to do.**

Everything up to here recovers struct layout by archaeology: scan for candidates, eliminate by
structural rules, publish when exactly one survives. §4.6b established that scry never attempted
this. What follows establishes that we may not have to either — for most fields.

### 13.1 ClassDB does not store offsets. But the getter does.

`ClassDB::ClassInfo` (`class_db.h:102-151`) carries `property_list`, `property_map` and
`property_setget`. `PropertySetGet` (`class_db.h:93-100`) is
`{int index; StringName setter; StringName getter; MethodBind *_setptr; MethodBind *_getptr;
Variant::Type type;}` — **no offset field anywhere**, and `ClassDB::add_property`
(`class_db.cpp:1458-1512`) never computes one. GDExtension's registration is likewise name-based.
`ClassDB::native_structs` does carry real field layouts, but only for a handful of POD structs
(`AudioFrame` and similar), never for `Object` descendants. So the obvious hope — *ask the engine
where `text` lives* — is genuinely unavailable, and §8.2's caveat was right.

Two properties rescue it, both verified unguarded by `#ifdef` and therefore **present in release
export templates**:

- `property_list` / `property_map` / `property_setget` sit outside the `DEBUG_ENABLED` block
  (`class_db.h:122-130`).
- `_getptr` is cached **eagerly at registration** (`class_db.cpp:1506-1507`), so a `MethodBind*` is
  reachable with no name lookup.

And on Windows the `MethodBind` holds a **plain code address**: `platform/windows/detect.py:363`
defines `TYPED_METHOD_BIND`, so `MethodBindTRC<T,R,P...>` (`method_bind.h:569-570`) stores a
pointer-to-member typed on the real class — and because Godot's `Object` hierarchy is
single-inheritance with no virtual bases, that is laid out as 8 bytes of function pointer. A scan
of the 4.5 release `.text` found **zero vcall thunks**: no property getter is dispatched virtually.

> **Correction — the official templates are MinGW-GCC, not MSVC.**
> `godot-build-scripts/build-windows/build.sh` builds the official x86_64/x86_32 templates with
> `use_mingw=yes` (arm64 with llvm-mingw), and `build-containers/Dockerfile.windows` installs
> `mingw64-gcc-c++`. **No MSVC anywhere in the official pipeline.** The decoding results in §13.2 were
> validated empirically against the real shipped templates and are unaffected — but any reasoning
> here that appealed to *MSVC's* pointer-to-member layout was appealing to the wrong toolchain.
> The load-bearing facts survive independently: the single-inheritance hierarchy makes the
> pointer-to-member a plain code address under either ABI, and the zero-vcall-thunk scan is a
> measurement of the actual binary. The consequence that does change is RTTI — see §13.9, where the
> right ABI is **Itanium**, not MSVC `RTTICompleteObjectLocator`.

So: the engine tells us where the getter is, and the getter's first instruction tells us the offset.

### 13.2 Measured, on the real binaries

| Getter | RVA | Decoded | Ground truth | Name attribution |
| --- | --- | --- | --- | --- |
| `CanvasItem::is_visible` (release) | `0x139f520` | `0x370` | `0x370` OK | **proven** — `"is_visible"` |
| `Label::get_text` | `0x1483bb0` | `0x800` | `0x800` OK | *unproven* — see below |
| `RichTextLabel::get_text` | `0x1663590` | `0xa78` | `0xa78` OK | *unproven* — see below |

The `visible` stub is eight bytes: `movzx eax, byte ptr [rcx+0x370]; ret`. Its one address-taken
reference sits at RVA `0x13aaa90`, inside the `_bind_methods` block that materialises the string
`"is_visible"` — so this row is confirmed **by name**, not merely by matching a number we already
believed.

Two codegen shapes appear and both decode:

```
Label::get_text          push rbx / sub rsp,0x20 / mov qword[rcx],0 / mov rbx,rcx
                         mov rcx, qword ptr [rdx + 0x800]     <- hidden sret ptr, this in RDX
RichTextLabel::get_text  mov rax, qword ptr [rdx + 0xa78]     <- instruction #1
```

Decoder rule: *the memory operand based on the `this` register (RCX for by-value returns, RDX when
the return needs a hidden sret pointer) with displacement ≥ 0x20, requiring exactly **one distinct
`(register, displacement)` pair** before the first `call`/`ret`.*

> **Three corrections found while implementing this — the first draft of §13 was wrong.**
>
> **1. "Exactly one this-relative memory operand" refuses one of the 3/3.**
> `RichTextLabel::get_text` loads `[rdx+0xa78]` **twice** — once at instruction #1 and again after a
> `cmpxchg` loop. The literal rule rejects it. The rule that works counts **distinct
> `(register, displacement)` pairs**, which preserves the ambiguity guarantee while accepting
> repeated loads of the same field.
>
> **2. The `0x3c0` debug row was a coincidence and has been deleted.** It is real —
> `movzx eax, byte [rcx+0x3c0]; ret` at RVA `0x18181a0` — but its address-taken reference sits in a
> `_bind_methods` block materialising **`"get_debug_use_custom"`**, an unrelated class. It is not
> `CanvasItem::visible`. And `movzx eax, byte [rcx+0x378]; ret` does not exist in the debug template
> at all, so the getter route **abstains** on debug `visible` rather than supporting either value.
> The lesson is the whole argument for §13.4's `ClassDB` walk: **an offset without a name attached to
> it is not evidence.** Matching a number we already believed is confirmation bias with extra steps.
>
> **3. `Label::get_text` and `RichTextLabel::get_text` are attributed by offset, not by name.**
> RVA `0x1483bb0` is *a* `String` getter at `+0x800`, but its `_bind_methods` neighbourhood shows
> `"is_shortcut_feedback"` / `"get_shortcut"`, so the class attribution is not provable offline.
> Both rows agree with §4.6's recorded values, which is worth something — but they are not proof
> about `Label` specifically until the `ClassDB` walk runs live.
>
> **Register liveness matters too**, and the prototype lacked it: a body that does
> `mov rcx, [rcx+0x178]` before `[rcx+0x918]` is reading a displacement into a *different object*.
> The shipped decoder retires RCX/RDX on any write, with sub-register writes normalised.

Run over a whole `.text` (1.09M candidate positions, 4.5 release), the shipped decoder decodes 1.1%
and refuses 98.9% — 81.3% `NoReturnInWindow`, 11.6% `NoThisRelativeAccess`, 4.5% `UndecodableBody`,
0.6% `AmbiguousAccesses`. That refusal rate is the design working, not a shortfall.

**Optimization does not erase these.** The getter's address is taken and stored in the `MethodBind`,
so the out-of-line body must be emitted. Census of the release template: 1,072 `bool` getter stubs,
1,704 `int32`, 770 `float`, 459 pointer, 227 COW/String — and the **debug** template's counts are
nearly identical (1,057 / 1,602 / 764 / 433 / 220). Optimization level is not the variable.
`/OPT:ICF` folding is harmless: folded getters share an offset by definition.

### 13.3 Coverage — and the 15% that must be refused

Classifying all 3,951 `ADD_PROPERTY` sites in the 4.5 source by getter body:

| Shape | Share | Decodable |
| --- | --- | --- |
| `return field;` / `return (T)field;` / `return field.sub;` | ~84.5% | yes |
| computed / multi-statement (`Engine::get_time_scale`, `InputEvent::is_pressed`) | 11.2% | **refuse** |
| delegating (`return f(...)`) | 4.4% | **refuse** |

(669 header-inline getters were not locatable by the parser; those skew *more* trivial, so 84.5% is
a floor.) The refusal rule preserves the project's discipline: require a `ret` within ~0x40 bytes and
**exactly one distinct `(register, displacement)` pair** among this-relative accesses before the
first `call`/`ret`. Anything else publishes nothing. (Distinct *pairs*, not distinct *accesses* — see
correction 1 above.)

Because the hierarchy is single-inheritance with no virtual bases, `this` for `CanvasItem` equals
`this` for `Label`, so a decoded displacement is directly usable from the `Object*`.

### 13.4 What still needs archaeology — two anchors, not every field

- **`ObjectDB::object_slots`** (`ObjectSlot` = 16 bytes, `{validator:39, next_free:24, is_ref:1,
  Object*}`): from one known `Object*` and its `_instance_id` (low 24 bits = slot index), the array
  base is `&slot - index*16`. Exact and self-validating — no scanning heuristic — and it removes the
  need to walk the scene tree from a root.
- **`ClassDB::classes`**, a static `HashMap` in `.bss`. The useful property: `HashMapElement` is a
  **doubly-linked list** (`hash_map.h`), so finding *one* element enumerates every class without ever
  locating the map root. Chain: known `Object` -> `_class_name_ptr` (`object.h:648`) -> static
  `StringName` -> interned `_Data*` -> the element whose key holds that pointer -> walk `next`/`prev`.

> **The `ClassDB` chain is inferred from verified layouts, not yet run against a live process.**
> The getter decoding in §13.2 *is* measured. Do not conflate the two.

### 13.5 GDScript needs no disassembly at all

`Object::script_instance` (`object.h:644`) -> `GDScriptInstance::script` -> `GDScript::member_indices`
(`gdscript.h:100`, `HashMap<StringName, MemberInfo>`, `MemberInfo.index` first) ->
`GDScriptInstance::members` (`Vector<Variant>`, stride 24 on a float build). Unguarded by any
`#ifdef`, and confirmed as the actual runtime resolution path (`gdscript.cpp:1755-1765` for `get`,
`1682-1702` for `set`). The derived class's map already contains base-class members in one flat index
space, so no base walk is needed. Caveat, checkable from data: if `MemberInfo::getter` is non-empty,
`members[index]` is a backing slot that may be stale.

C# fields are **not** covered — that needs CoreCLR metadata walking, which is §5's problem, not this
one.

### 13.6 Why this matters most as a cross-check

The calibrator currently publishes when exactly one candidate survives bracketing. **Two unrelated
derivations agreeing is a far stronger criterion**, and it is available essentially for free: the
bracket proposes, the getter disassembly confirms.

A concrete test of the idea's worth, and it survived implementation: §4.6's table records scry's
`Label.text` debug offset as `0x848`. In the 4.5 debug template there is **no `String`/sret-shaped
getter loading `[rdx+0x848]` — zero sites, any opcode.** The byte-for-byte structural twin of the
release `+0x800` getter sits at RVA `0x11bc100` and loads **`+0x808`**. And `0xb18` — §4.6's
`RichTextLabel` debug value — decodes from **nothing at all** anywhere in that template.

So the getter route contradicts §4.6's debug column and independently lands on §12.7's measured
*"debug is release + 8"*. Three unrelated methods now agree that the debug column is wrong: a live
grid derivation, a delta analysis, and static getter decoding.

Carry the §13.2 caveat with it, though: this corroborates the **uniform-shift rule**, not a claim
about `Label` specifically, because the class attribution of that getter is not provable offline.

The API reflects the discipline: `OffsetCrossCheck.Compare(getterBody, bracketedOffset)` carries a
value **only** on `Agree` — a disagreement publishes neither side rather than picking a winner.

### 13.7 Fragility — version gates, not assumptions

- **4.6/master already breaks this**: `ClassInfo::property_setget` becomes `AHashMap`. Different walker.
- `sizeof(MethodBind)` moves with `DEBUG_ENABLED` (`arg_names` is debug-only) — **probe the first few
  qwords for the one landing in the main module's `.text`** rather than hardcoding it. Self-validating.
- `HashMap` went 48 -> 40 bytes between 4.3 and 4.5.
- `StringName::_Data` dropped `cname`/`idx` in 4.5; a 4.3 reader must check `cname` first.
- **Windows-specific**, but *not* MSVC-specific — see the correction in §13.1. The official templates
  are MinGW-GCC, which still uses the Microsoft x64 calling convention (RCX/RDX), which is why the
  decoder works on them. **Linux** templates use the System V convention (RDI) and the Itanium
  `{ptr, adj}` pointer-to-member pair. Decodable, but a second decoder.

### 13.8 Prior art: nobody has published this

`Zolt-Dump` is an **injected** in-process dumper (proxy DLL -> named pipe -> external UI) and makes no
external claim at all; its own `ue-to-godot-mapping.md` rates property offsets *"Hard — Godot uses
getter/setter, not offsets"* and its `dev-log.md` calls them unsolved. Its offsets come from
empirical layout probing, not metadata. The one real external precedent is **GDDumper** (Cheat Engine
Lua) — genuine external name-to-offset, but **only** for GDScript `member_indices`, and only after a
human hand-derives the engine layout per build. Godot's own remote debugger is name-based and
external but requires a **debug** export template.

The `ClassDB` -> `MethodBind` -> disassemble-the-getter route appears to be unpublished.

*(Read only from public READMEs, docs and issues. Zolt-Dump is GPL-3.0 and archived; no source was
read — see §9.)*

### 13.9 Per-node class identity — the vtable, not `_class_name_ptr`

Knowing a node's real class turns out to be the load-bearing fact for reading text safely: a valid
Godot `String` at a plausible offset is indistinguishable from the *right* String unless you know
whether the node could be a `Label` at all (§13.6). The grid measured that directly — with class
gating, zero phantoms; without it, every phantom in the series.

**`Object::_class_name_ptr` is a dead end on 4.2, 4.3 and 4.4 — the field exists and is always null.**
This was measured before it was explained: 4.5 derived it 12/12 deterministically with zero wrong
class names, 4.3 failed 12/12, and a `cname` fallback, a relaxed threshold and a corroboration check
all produced *no observable change*. The source says why:

```cpp
// core/object/object.cpp:210-215, 4.3-stable
void Object::_postinitialize() {
    _class_name_ptr = _get_class_namev();
    _initialize_classv();
    _class_name_ptr = nullptr;   // destroyed on the next line
    notification(NOTIFICATION_POSTINITIALIZE);
}
```

`_predelete()` also writes null, and nothing else ever writes it, so the slot reads 0 for the entire
observable lifetime of every node. Fixed by [PR #105099](https://github.com/godotengine/godot/pull/105099)
(merged 2025-04-08), **milestone 4.5 only** — the reset was deleted and the logic moved to
`Object::_initialize()`. Verified **not** cherry-picked to 4.4.x against 4.4.1-stable.

| Version | Field present | Nulled after init | Live value |
| --- | --- | --- | --- |
| 4.2 / 4.3 / 4.4 / 4.4.1 | yes | yes | **always 0** |
| 4.5 | yes | **no** | populated |

> **Two corrections, both verified at the specific tags.** On **4.4** the nulling lives in
> `Object::_initialize()` (`object.cpp:243-246`), not `_postinitialize()` — 4.4 split the two
> functions, and the code block above is accurate for 4.3 (`object.cpp:211-213`) but mislabelled for
> 4.4. The effect is identical: the only other write is `_predelete()`, so the slot reads 0 for every
> node's observable lifetime. And the "not cherry-picked" claim is now **exhaustive rather than
> sampled** — the tag list contains exactly two 4.4.x tags, `4.4-stable` and `4.4.1-stable`, whose
> `object.cpp` files are byte-identical and both carry the reset.

So treat a zero on 4.2–4.4 as **structurally unavailable**, not as a calibration failure — and expect
4.4 cells to fail identically if the grid adds them. Nothing else in 4.3 carries per-instance class
identity: `get_class()` is a virtual returning a literal, `_get_class_namev()` returns a per-class
*static*, `is_class_ptr()` compares a static's address. All virtuals or statics, reachable only
through the vtable, never from instance bytes.

**The replacement works on every version, including 4.5, and needs no calibration at all:**

```
vptr      = u64[node + 0]        // Object has no base and is polymorphic -> vptr at offset 0
offs_top  = i64[vptr - 16]       // must be 0 for a primary-base object; use as a validity check
tinfo     = u64[vptr -  8]       // std::type_info*
name_ptr  = u64[tinfo + 8]       // libstdc++ type_info::__name
name      = cstring(name_ptr)    // "5Label" -> strip optional leading '*', read the decimal
                                 // length prefix, take that many chars
```

Every offset is an ABI constant. **Group by vptr first** — it partitions the scene into exact
class-equivalence sets for free — then resolve the name once per *distinct vptr* (a few dozen per
scene), not once per node. The grouping alone solves the single-instance problem: the subset rule
that guards text publication is vacuous when a class has exactly one instance, and exact equivalence
sets restore it without needing a name at all.

Inheritance shape verified in 4.3 source: `Object` has no bases and is polymorphic
(`virtual ~Object()`), then `Node : Object`, `CanvasItem : Node`, `Control : CanvasItem`,
`Label : Control`. Single inheritance throughout, no virtual bases. `GDCLASS` structurally forbids a
second base, and Godot's own `ObjectDB`/`void*` round-tripping depends on the `Object` subobject
sitting at offset 0.

**RTTI is enabled and the ABI is Itanium.** No `-fno-rtti` or `/GR-` anywhere in 4.3's `SConstruct`,
`methods.py`, `platform_methods.py` or `platform/windows/detect.py`; the MSVC path explicitly adds
`/GR` and the MinGW path leaves GCC's RTTI-on default. LTO (`production=yes`) does not merge vtables
of distinct classes, and stripping does not remove typeinfo — both non-issues.

Keep a one-time **ABI probe** so a custom MSVC-built template degrades instead of emitting garbage:
Itanium `vptr-8` points at a type_info whose first qword is a vtable in a read-only section, whereas
MSVC `vptr-8` points at a `RTTICompleteObjectLocator` whose first dword is 0 or 1. Detect, then either
decode `.?AVLabel@@` at `TypeDescriptor+0x10` or **withhold**.

Failure modes to gate rather than assume: a template built `-fno-rtti` (fall back to disassembling
`_get_class_namev` — `GDCLASS` at 4.3 `object.h:413-419` compiles to a `lea` on the per-class static
followed by a null test — but hold that in reserve, it is strictly more fragile); GDExtension nodes,
where RTTI reports the C++ wrapper rather than `_extension->class_name`; and namespaced classes
arriving as `N…E`, which Godot's global-namespace node classes avoid but which must be refused
explicitly rather than mis-parsed. Script-attached nodes correctly report their engine base class,
which is exactly what is wanted for telling a `Label` from a `Panel`.

**`ClassDB` cannot supply per-instance identity** and should not be pursued for it: it is keyed by
`StringName` and stores no vtable, no instance pointer and no per-instance handle. It remains useful
as a **validator** — the element walk of §13.4 yields the authoritative name set, and any
RTTI-derived name outside that set is a script, GDExtension or engine-internal case worth flagging.

> ### The fixture agreed with the hypothesis instead of with the target
>
> Worth recording as method, because it cost three rounds. The synthetic fixture for class-name
> calibration wrote a **live, populated `_class_name_ptr`** — so every unit test passed, and each
> successive relaxation (a `cname` fallback, a 75% threshold, name corroboration) was validated
> against behaviour the engine *never exhibits on 4.2–4.4*. The grid kept reporting 12/12 withheld
> and the fixture kept reporting green, and the contradiction read as "the derivation needs more
> tuning" rather than as "the fixture is lying".
>
> The tell was available the whole time and was misread: **three independent relaxations produced no
> observable change at all.** A mechanism that is merely over-constrained responds to relaxation.
> One that responds to nothing is not firing — and a fixture built from the same assumption as the
> code cannot reveal that, because it encodes the assumption twice and calls the agreement
> confirmation.
>
> Practical rule for this project: when a fixture and the grid disagree, **the grid is the target and
> the fixture is a hypothesis about the target.** Fix the fixture from measured bytes before tuning
> the code that reads them. This is the same lesson as §12.7's debug column — a number believed
> because two sources agreed, where one source was derived from the other.
>
> **It recurred immediately, which is what makes it a pattern rather than an incident.** A bracket
> clause was added requiring the dword at `Label::text+0x14` to be zero. Live memory says that dword
> is a member past `xl_text` holding `0x39`/`0x42`/`0x51`/`0x5a`/`0x79`/`0x61461120`/`0xff8700a2` —
> and *varying between the two Labels in a single process*. The unit fixture wrote **zero** there, so
> the tests confirmed the false clause, and the same edit deleted a clause that was **true**
> (`xl_text._ptr == text._ptr`, measured bit-identical on every Label under both bindings) on the
> strength of an inference about how .NET routes `set_text`. A guess replaced a fact, and the fixture
> ratified the swap.
>
> The generalisation worth keeping: **a fixture authored from a premise cannot falsify that premise.**
> Anywhere a test's input is written by the same reasoning as the code under test, the test measures
> self-consistency and nothing else. Fixture bytes for layout-sensitive code should be lifted from a
> real target, or deliberately randomised in the fields the code does *not* claim to depend on —
> which is exactly what caught this one when `0x5a` replaced the zero.
>
> Tally so far, all the same shape: the padding equalities that made `visible` undiscoverable
> (§13, three rounds), the always-null `_class_name_ptr` (three rounds), and this. **Every one was a
> clause asserting that some byte is zero.** C++ does not zero what you did not write.
>
> **And the same failure hit the verification method itself.** Every grid series pinned each cell's
> `grid.exe` SHA-256 to prove the targets had not been rebuilt between runs. That check was sound
> in form and empty in content: **`grid.exe` is a byte-identical copy of the stock Godot export
> template** — verified by hashing it against
> `%APPDATA%\Godot\export_templates\4.5.stable\windows_release_x86_64.exe` — because the scene ships
> in `grid.pck`, not in the executable. So the pin proved only that the *engine* was unchanged, which
> was never in doubt, and would have happily reported "targets not rebuilt" across an edited scene.
> Comparability is carried by **`grid.pck`** and `cell.json.sceneSha256`; pin those.
>
> Same lesson one level up: a check that never varies is not thereby passing. It may not be
> measuring anything.
>
> **The subtlest instance had no premise written into it at all.** A test for a read-retry change
> derived its expected attempt count *from the code, at runtime*, and then asserted the code matched
> it. That reads like rigour — no magic number, adapts to refactors — and is the exact opposite: it
> agrees with whatever the code does, including whatever the code does wrong. It passed with the
> retry removed. The fixed version pins the measured count (6) and separately asserts the strategy
> still makes exactly that many, so a change to the read path breaks loudly instead of silently
> re-calibrating.
>
> **The general tell across all four: the test never disagrees with anything.** A hardcoded premise
> at least fails when the premise is wrong; a self-derived one cannot fail at all. The only defence
> that has actually worked here is the crude one — revert the change and confirm the test goes red.
> Nothing else in this project has reliably caught a test that was measuring itself.

### 13.10 `ownerBackref` is per implementing class, not per binding

A small fact that was one edit away from being encoded wrongly, and the error would have been
invisible on this grid.

The grid measured `ScriptInstance`'s owner back-reference at `0x8` on every .NET cell and `0x10` on
every GDScript cell — 19 of 24 cell-runs, zero contradictions. The obvious reading is that the offset
is a property of the *build*, and the obvious fix is to split the profile table by binding.

**That model is false.** `CSharpInstance` and `GDScriptInstance` are unrelated C++ classes
implementing one interface; the back-reference is a member of whichever class actually instantiated,
not of the engine object. And a mono export template runs `.gd` scripts perfectly well — so **a
single process can hold nodes of both kinds at once**, and the correct offset differs *per node*.

The grid only makes it look build-shaped because each cell's probe script happens to match its cell
name. A table keyed on binding would have scored 24/24 here and been wrong on any real mixed game —
the worst possible combination, since the harness would have certified the mistake.

The correct key is the implementing class, read off the `ScriptInstance`'s own vtable by the same
RTTI as §13.9:

```json
"scriptInstance.ownerBackref": { "CSharpInstance": "0x8", "GDScriptInstance": "0x10" }
```

A key the table cannot express for a given target is **not compared** rather than scored, and says so
in the detail line, so the profile never reads as more complete than it is.

Worth generalising: *"the axis along which my samples happen to vary"* is not the same as *"the axis
the value actually depends on"*, and a fixture whose cells are stratified by build will make every
per-node fact look per-build. Cf. §12.7's debug column, where a real relationship
(`debug = release + 8`) was read out of a table that had no such rule in it.

### 13.11 Checks that cannot fail — the failure family that cost the most

Nearly every expensive mistake in this project was the same one, and it was never a wrong answer. It
was a **check that had no way to come out other than the way it came out.** Collected here because
the individual instances read as unrelated bugs and the pattern does not.

| # | The check | Why it could not fail | Cost |
| --- | --- | --- | --- |
| 1 | Unit fixture for `_class_name_ptr` calibration | Fixture wrote a *populated* pointer — a state Godot 4.2–4.4 never reaches, since `_postinitialize` nulls it on the next line | 3 rounds |
| 2 | Unit fixture for the `Label::text+0x14` bracket clause | Fixture wrote **zero** there; the live member holds `0x39`/`0x51`/`0x79`/… and varies between two Labels in one process | 3 rounds |
| 3 | Read-retry test | Derived its expected attempt count **from the code at runtime**, then asserted the code matched it. Passed with the retry removed | 1 round |
| 4 | `grid.exe` SHA pin, "targets not rebuilt" | `grid.exe` is a byte-identical copy of the stock export template; the scene ships in `grid.pck`. Would report "unchanged" across an edited scene | 8 series of false assurance |
| 5 | `profile.agreement` on `scriptInstance.ownerBackref` | `loadProfiles` ran `parseOffset` over the per-class map, flattening it to `null`. The comparison logic was correct and **unreachable** | reported as a real disagreement |
| 6 | Geometry checks on non-`CanvasItem` nodes | Filtered to `isControl` nodes, so the two bare `Node`s were never inspected | concealed a live defect through a **22/24 full-score** series |

Two of these deserve their own emphasis.

**#3 is the subtlest, because it looks like the good practice.** No magic number, survives refactors,
adapts to the implementation — and it agrees with whatever the code does, *including whatever the
code does wrong*. A hardcoded premise at least fails when the premise is wrong. A self-derived one
cannot fail at all. The fix was to pin the measured constant and separately assert the strategy still
produces it, so a change breaks loudly instead of silently re-calibrating.

**#6 is the one to remember, because plausibility could never have saved it.** The fabricated
readings were `size=[0,0] scale=[0,0] offset=[0,0,0,0]` — and **zeros pass every plausibility test
there is**. `visible=true` on an object with no `CanvasItem` base is not reachable from any amount of
value-checking. Only *identity* could reject it: the fix gates geometry on walking Itanium's
`__si_class_type_info` → `__base_type` chain to ask whether the object is a `CanvasItem` at all.
Note the shape of that too — the hierarchy is read **from the target**, not compared against a
hardcoded list of Godot class names, because "this node is a `Node`" only implies "it has no
`CanvasItem`" if you already assume Godot's hierarchy. That assumption would have been the same
species as the neighbour clauses in §13.10.

**The tell, in every case: the check never disagreed with anything.** Not "rarely" — never. A check
whose output is constant across every input it has ever seen is not passing; it may not be measuring.
Worth asking of any green check: *what input would make this red, and has anything like it ever been
run?*

**The only defence that has actually worked here is the crude one:** revert the change and confirm
the test goes red. Every fix in the later rounds was validated that way, and it caught #2 and #3
directly. Static reading of the test never did.

> **Writing the lesson down did not transfer it.** The strongest evidence for that claim is #6's
> sequel. `strings.text.absent` carries a comment in its own source recording exactly this bug and
> exactly how it was fixed — *"Hardcoding the authored count let a driver drop sixteen of seventeen
> text-less nodes and still be told 17/17."* Three rounds later `geometry.absent` was written, by the
> same author, with an `if (!got) continue;` that shrinks its denominator the same way: rename one
> bare node and it reports **"1/1 non-Control node(s) reported no geometry"** — full coverage over
> half the population.
>
> A documented lesson sitting beside the code did not prevent its immediate recurrence. What
> prevented it was a **fault that tries to exploit it** — `drop-bare-node` — which fails the moment
> the fix is reverted. The general form: *a lesson is only installed when something automated tries
> to violate it.* Prose is a reminder to whoever already remembers.
>
> The same blind spot also produced a wrong forecast twice: a predicted score drop that could not
> happen, because the reasoning was about the fix's effect on the **target** without checking the
> **check's denominator**. Predicting the effect of a change without asking what the measurement
> actually iterates is the same error as the six above, pointed at a forecast instead of at code.

A corollary that shaped a decision rather than a bug fix: the four 4.3 grid cells cap at 18/18 because
`profiles.json` ships no 4.3 column, leaving every 4.3 offset uncorroborated. Transcribing the
calibrator's own output into that column would raise the score to 19/19 and would be **anti-evidence**
— `profile.agreement` would then pass by construction forever, a check that cannot fail, installed
deliberately. The honest sources are the getter decoder (§13.2, independent of bracketing) or nothing.
**The cap is information; removing it by fiat would destroy the information and keep the number.**

---

## 14. Statics on .NET 9 — §5.5 was wrong, and scry's CLR layer is where it shows

**§5.5 records that static field addresses have "no route and no calibration anchor — ClrMD
required." That is wrong on both counts.** Scry has the route, and the anchor exists and closes a
loop on a value we already hold. This unblocks `.Static("Instance")` without `DomainLocalModule`
(which no longer exists on .NET 9) and without ClrMD.

Worth stating why this was missed: §4.6b's exhaustive Godot-layer enumeration concluded scry was
hand-measured with nothing to teach, and that negative result was load-bearing — it justified building
the calibrator. The mistake was generalising it. **The Godot layer and the CLR layer are not the same
quality of work**, and the CLR layer had never been enumerated.

### 14.1 The chain — `DotNetCoreFieldDesc::getStaticValue` (`FUN_180032730`)

`DotNetCoreClass.get(name)` is a static-field read, and it is already used in this project's
production path (`scryObject.ts:512,534`). Every read is `ReadProcessMemory` through scry's vtable.

```
isStatic = (u32(fd+8)  >> 24) & 1          FieldDesc m_isStatic  -> else empty
isRVA    = (u32(fd+8)  >> 26) & 1          FieldDesc m_isRVA
offset   =  u32(fd+0xC) & 0x07FFFFFF       FieldDesc m_dwOffset
type     =  u32(fd+0xC) >> 27              FieldDesc m_type
mt       =  ptr(fd+0)                      FieldDesc m_pMTOfEnclosingClass

isDynamicStatics = .NET>=9 : (u32(mt+8) >> 1) & 1     MethodTable m_wFlags2 & 0x0002
                   .NET<9  : (u32(mt+0) & 6) != 0     m_dwFlags & enum_flag_StaticsMask

aux  = ptr(mt + 0x20)                      MethodTable m_pAuxiliaryData
base = ptr(aux - 0x18) & ~1                GC statics      (type CLASS 0x12 / VALUETYPE 0x11)
base = ptr(aux - 0x10) & ~1                non-GC statics  (everything else)
addr = base + offset
```

**Verified against .NET 9 source, not guessed.** `release/9.0` `methodtable.h` defines
`struct DynamicStaticsInfo { TADDR m_pGCStatics; TADDR m_pNonGCStatics; PTR_MethodTable m_pMethodTable; }`
with `GetDynamicStaticsInfo(aux) = aux - sizeof(DynamicStaticsInfo)` and
`STATICSPOINTERMASK = ~ISCLASSNOTINITED`, `ISCLASSNOTINITED = 1`. Scry's `aux-0x18` / `aux-0x10` /
`& ~1` is that verbatim, and its version gate is `MethodTable::IsDynamicStatics()` on both branches —
a faithful port of `FieldDesc::GetBase()`'s dispatch, not a measured constant.

### 14.0 VERIFIED LIVE — and three corrections to what follows

Measured against a running .NET 9 process (SlayTheSpire2, CoreCLR 9.0.x, read-only
`ReadProcessMemory`): **12,283 validated MethodTables across 25 managed assemblies, 27,732 static
FieldDescs.** Steps 1–5 of the chain hold as written. Nothing here needs retracting. Ground truth,
checkable outside the process:

- `System.Environment.s_processId` → **418440**, the target's actual OS PID.
- `MegaCrit.Sts2.Core.Debug.ReleaseInfoManager._instance` → every field matching `release_info.json`
  on disk (commit `59260271`, version `v0.107.1`, `MainAssemblyHash -1555940892`, date ticks
  converting to the file's timestamp).
- Control: reading **the identical fields from the wrong base** yields **0 valid objects out of 529**.
  The test therefore has full discriminating power, so 0 garbage across 17,982 dispatched fields is a
  result rather than a tautology.
- 200,000 addresses drawn near real MethodTables: 24,819 passed the flags gate, 37 passed gate *and*
  anchor, and all 37 independently validate as real MethodTables under an unrelated test (generic
  instantiations absent from the corpus). **Genuine false positives: zero.**

**Correction 1 — slot 40 aliases the anchor. Derive the slot once and freeze it; never sweep per
lookup.** §14.3 says to sweep the slots between `Module = 24` and `EEClassOrCanonMT = 40`. That is
safe only if "between" is *exclusive*: there is then exactly **one** 8-aligned candidate, `0x20`, and
the "three or four candidate slots" phrasing below is wrong. Measured:

| slot | anchor holds, gate set | gate clear |
| --- | --- | --- |
| **32 (`0x20`)** | **3033 / 3033 (100%)** | 0 / 4000 |
| 40 (`EEClassOrCanonMT`) | 4 / 3032 | 16 / 4000 |
| every other slot 0…72 | 0 | 0 |

26 types satisfy `ptr(ptr(mt+40)-8) == mt` by coincidence, so a **per-type inclusive sweep picks the
wrong slot for four of them** (`EpochModel`, `MonsterModel`, `OrbModel`, `PowerModel`). Derive by
unanimity over ≥100 gate-set types once at connect, then use the frozen value.

**Correction 2 — thread statics are not handled and will produce a confident wrong address.**
`FieldDesc` bit **25** marks a thread-local static (28 in the corpus, e.g. `Thread.t_currentThread`).
They pass the gate *and* the anchor, but the aux GC/non-GC bases **do not apply to them**. §14.1
decodes `m_isStatic` (bit 24) and `m_isRVA` (bit 26) and silently skips bit 25. **Check it and
refuse.** Likewise §14.3's recommended design drops `isRVA` entirely, which §14.1 does decode — 243
RVA statics need their own path.

**Correction 3 — open generic type definitions have no statics storage.** 3,385 GC-dispatched
statics read `gcRaw == nonGcRaw == 1` (`ArrayPool\`1.s_shared`, `EmptyArray\`1.Value`). The
instantiation's MethodTable is required. The chain refuses correctly, so this is a *capability* limit
rather than a correctness bug — but a caller resolving by TypeDef name simply gets nothing, and
per-instantiation `GenericsStaticsInfo` was not tested.

Two smaller notes. The gate is **exact and fails safe**: zero of 12,283 types with statics had it
clear, so there are no false refusals; the 8 gate-set-without-statics are all
`<PrivateImplementationDetails>` carrying RVA statics only. And the constant `0x0002` is **not
descriptor-published** — it is measured here to mean precisely "a `DynamicStaticsInfo` precedes the
auxiliary data", so on a future runtime it should be *derived* (pick the `MTFlags2` bit that
perfectly predicts the anchor) rather than hardcoded.

`ISCLASSNOTINITED` is also confirmed as meaningful rather than incidental: `Boolean.TrueString` reads
null because `Boolean`'s raw GC base is `0x1A2FB020CE1` — low bit set, class never initialized in
this process. Types whose base has bit 0 clear return live values. So the `& ~1` masking is measured,
and "null" and "class not initialized" are distinct states that should not be collapsed.

Scope: one runtime, one build. Nothing here speaks to .NET 10.

### 14.2 The calibration anchor §5.5 says does not exist

`DynamicStaticsInfo`'s third member is a **back-pointer to the MethodTable**:

```
aux = ptr(MethodTable + 0x20)
assert ptr(aux - 0x08) == MethodTable      <-- closes the loop on a value already held
```

That is structurally identical to the `EEClass.MethodTable` trick §5.5 already uses to resolve the
`EEClassOrCanonMT` union tag. So **`MT+0x20` need not be trusted — it can be searched and confirmed**,
sweeping the three or four candidate slots between the descriptor-published `Module = 24` and
`EEClassOrCanonMT = 40` until the back-pointer matches. One derived offset instead of a table.

Guard with `MTFlags2 & 0x0002`. If that bit is clear on .NET 9 the type has no statics at all, so the
guard produces a **correct refusal rather than a garbage read** — which is the property the whole
project is built on.

### 14.3 Recommended design — descriptor-anchored at both ends, calibrated in the middle

```
object -> m_pMethTab & ~ObjectToMethodTableUnmask     (descriptor-published)
       -> MTFlags2 & 0x0002 gate                      (published offset, contract-documented flag)
       -> DERIVE m_pAuxiliaryData: sweep slots between Module=24 and EEClassOrCanonMT=40
          for the one whose -8 back-pointer equals the MethodTable
       -> ptr(aux-0x18) & ~1  /  ptr(aux-0x10) & ~1
```

Plus the `Object`/`String` MethodTable sanity checks §5.5 already mandates. Keep the cDAC descriptor
as the anchor; this adds statics with **one calibrated offset**, and it fails closed.

### 14.4 Corrections to the doc

**"Scry has no version handling" is true of the Godot layer and false of the CLR layer.** There are
**21 `major >= 9` gates across 14 functions** in the CLR layer, against 18 `isDebug` gates in the
Godot layer. Minor and patch are stored (ModuleImpl `+0x42`/`+0x44`) and, as in the Godot layer,
**never read** — writes only, binary-wide. So the CLR layer is version-aware, at exactly one
boundary: .NET 9.

**The `g_dacTable` table indexes four structures, not one.** §4.5 sketched it as a `Module` offset
table. `FUN_180039930` is a 44-entry jump table (IDs `0x00`–`0x2b`) whose entries index `DacGlobals`
slot byte-offsets, `AppDomain`, assembly-list entries, and `Module`. **Only 9 IDs are reachable** —
13 call sites across 8 functions, every one passing an immediate, no dynamic ID anywhere. **35 of 44
entries are dead code.**

**Slot 21 is proven, not inferred.** `g_dacTable` is exported from the shipped `coreclr.dll` at RVA
`0x3dde50`, lives in `.rdata`, and is statically relocated:

```
g_dacTable + 0xa8  =  slot 21  =  0x180462780  ==  pointer_data[1]  ==  descriptor global "AppDomain"
```

Twelve slots cross-match the descriptor's `pointer_data` exactly (16 ThreadStore, 17 FinalizerThread,
18 GCThread, 21 AppDomain, 30 ArrayBoundsZero, 44 ObjectMethodTable, 47 StringMethodTable,
51 ExceptionMethodTable, 58 FreeObjectMethodTable, 84 SyncTableEntries, 95/96 MiniMetaData). Slot 46
— scry's `<9` constant — is a different address on this build, which is precisely why the gate exists.

### 14.5 Native → managed is simpler than assumed

```
scriptInstance = ptr(node + (isDebug ? 0x70 : 0x68))
handle         = ptr(scriptInstance + 0x20)
managedObject  = ptr(handle)
```

A CoreCLR `OBJECTHANDLE` is an `Object**`, so a strong GCHandle is **one dereference**. No
handle-table walk, no handle-type decoding, no object-header or SyncBlock work, and — searched across
all 2,488 functions — **no `& ~7` mask on `Object.m_pMethTab` anywhere in the CLR layer.**

### 14.6 Scry never touches the cDAC descriptor

Stated plainly, because the negative is load-bearing: zero hits for `DotNetRuntimeContractDescriptor`,
`cdac`, `DacGlobals` or `g_CLREngineMetrics` as ASCII, as UTF-16, or as the 8-byte stack-built
fragments MSVC emits — the method that *does* find `"g_dacTable"` itself. Scry is purely `g_dacTable`
with hardcoded slot ordinals, which is the fragility §4.5 describes. **The project's descriptor route
is strictly better and this confirms it.**

### 14.7 What is not worth taking

The `g_dacTable` bootstrap (the descriptor is better and already proven live). The metadata reader —
scry reaches ECMA-335 rows through the runtime's private `CMiniMd` internals with ~8 hardcoded
offsets, where §12.4d already proved the cleaner route of reading the module's own metadata blob;
notably there is **no `BSJB`, no `#~`, no `#Strings`** anywhere in the binary, so scry never parses a
metadata blob itself. The 35 dead table entries. And one outright defect: on the
`!isDynamicStatics` primitive path scry sets `base = fd` — the FieldDesc's own address as a static
base, which is not a valid address. It is a stub. It never fires on .NET 9, where any type with
statics carries `DynamicStatics`, which is why nobody noticed.

`EEClass + 0x18 = m_pFieldDescList`, `sizeof(FieldDesc) = 0x10`, and the FieldDesc bitfields are
worth taking as **calibration hypotheses to test first**, not as hardcodes — `EEClass+0x18` sits
immediately after the descriptor-published `EEClass.MethodTable = 16`.

---

## 15. Cross-version: 4.4 is nearly free, 4.6 is easy, 4.7 is the real work

Source verification at tags `4.3-stable`, `4.4-stable`, `4.4.1-stable`, `4.5-stable`, `4.6-stable`,
`4.7-stable` and `master`. No binaries were decoded — Godot ships templates only as ~1 GB `.tpz`
bundles, so there is no cheap per-binary download. **Everything here is source-only.**

Both §13 predictions were confirmed on their headline. One sub-premise was refuted, and it matters
less than expected. Three things were not predicted at all, and one of them would have caused silent
wrong answers.

### 15.1 The prediction that held, and the trap underneath it

`_class_name_ptr` is nulled on 4.2/4.3/4.4/4.4.1 and populated from 4.5 — confirmed exhaustively
(see the correction in §13.9). The RTTI replacement's premises all hold at 4.4: `Object` polymorphic
with no bases (`object.h:1004`), the full single-inheritance chain to `Label` intact, `GDCLASS`
forbidding a second base, `/GR` on the MSVC path with no `-fno-rtti` anywhere, `TYPED_METHOD_BIND`
defined.

**But 4.4's offsets are not 4.3's offsets, and nothing predicted that.** Verified layout-changing
edits between `4.3-stable` and `4.4-stable`, all sitting *above* the fields this project reads:

- `Object` gains `StringName _translation_domain` (`4.4 object.h:680`) — **+8 bytes, shifting every
  `Node`/`CanvasItem`/`Control` field below it.**
- `Node::Data` gains three bitfield bools plus two translation-domain flags.
- `CanvasItem` gains two `HashMap` members (`4.4 canvas_item.h:118`) — *after* `visible` (line 98),
  so `visible`'s intra-class offset survives but **the whole `Control` block below moves ~96 bytes.**
- `Control::Data` gains `tooltip_auto_translate_mode`.
- `Label` is restructured: per-paragraph state moves into a nested `struct Paragraph`.

`Label::text`/`xl_text` survive as adjacent inline `String` members at the head of the private block
on **every** tag 4.3 → master, as does `RichTextLabel::text`. So the *fields* are stable and only
their addresses move — harmless for a calibrator that derives, **silently wrong for any 4.3-derived
table reused on 4.4.** That is the one mistake available here and it is an easy one to make.

### 15.2 The refuted sub-premise — `AHashMap` is not doubly-linked, and that is fine

`property_setget` becomes `AHashMap` at `4.6-stable class_db.h:157` (confirmed, also at 4.7 and
master). But §13.7's implied worry was wrong: `AHashMap` is not a linked structure **at all** —
`a_hash_map.h:82-103` is a dense `_elements` array plus an open-addressing `_metadata` index, with no
`next`, no `prev`, no head. The §13.4 property — *find one element and enumerate the map without
locating the root* — is simply gone for it.

**It was never load-bearing there.** That property mattered only for `ClassDB::classes`, which the
walker cannot address directly. `property_setget` lives *inside* a `ClassInfo` the walker already
holds, so its root is free. And **`ClassDB::classes` remains `HashMap` at every tag through master**,
so the anchor chain keeps its linked-list property. Net: the 4.6 walker is a 24-byte header read plus
a dense scan of `_size` entries — **simpler than the 4.5 walker, not harder.**

### 15.3 Corrections to §13.7's version table

- **`HashMap` 48→40 happens at 4.4→4.5, not 4.3→4.5.** Cause pinned: 4.3/4.4 declare
  `Allocator element_alloc;` as the first member; 4.5+ use `class HashMap : private Allocator`
  (`4.5 hash_map.h:68`) and empty-base-optimization erases it. Consequence beyond size:
  **`head_element` sits at `+0x18` on 4.3/4.4 and `+0x10` on 4.5+.** (The EBO reasoning is inference;
  the source change is verified and agrees with the project's independently measured 48→40.)
- **`StringName::_Data` keeps `cname`/`idx` on 4.4** as well as 4.3, dropped at 4.5, unchanged
  through master. So 4.4 uses the 4.3 reader.
- **`MethodBind` is unchanged 4.3 → master** — identical member list at every tag; only the guard
  macro was renamed (`DEBUG_METHODS_ENABLED` → `DEBUG_ENABLED` at 4.5). `arg_names` is still the only
  debug-conditional member, so the "probe the first few qwords" heuristic stays valid everywhere.
  `MethodBindTRC` still stores `method` as the first member after the base under `TYPED_METHOD_BIND`
  on master (moved to `method_bind_common.h:317-318`), and `TYPED_METHOD_BIND` is still defined on
  Windows at 4.6, 4.7 and master. **The getter decoder's premise survives to master.**
- **`ObjectDB::ObjectSlot` unchanged 4.3 → master** — same 39/24/1 bitfields. The §13.4 anchor needs
  no work at any version.

### 15.4 Unpredicted: 4.6 gives back something better than RTTI

`_class_name_ptr` is replaced by `mutable const GDType *_gdtype_ptr` (`4.6 object.h:672`), set in
`_initialize()` and — crucially — **never reset**; only `_predelete()` nulls it. `GDType`
(`core/object/gdtype.h`) is `{ const GDType *super_type; StringName name; Vector<StringName>
name_hierarchy; }`, so **one pointer chase yields the class name *and* the entire inheritance chain**,
`Object` last. Strictly more than the RTTI route gives, and it fixes the GDExtension case §13.9
flagged (`object.cpp:1437` assigns `_extension->gdtype`).

4.6 also adds a **free ancestry test**: `Object::_ancestry` is a 15-bit field (`object.h:653`) over
`enum class AncestralClass` with `NODE = 1<<1`, `CANVAS_ITEM = 1<<4`, `CONTROL = 1<<5`. The
CanvasItem gate of §13.11 becomes **one masked dword read**, no name resolution and no `__base_type`
walk.

4.6 moves offsets again, hard: `Object` *shrinks* (`Variant script` removed, five bools collapsed
into bitfields), `CanvasItem` replaces `List<CanvasItem*> children_items` + `Element *C` with a
`LocalVector` plus `index_in_parent`, and `Control::Data` gains `pivot_offset_ratio`. New profile
required — but that is a calibration run, not a code change.

### 15.5 Unpredicted: 4.7 is a different problem, and the doc collapsed three ABIs

`ClassInfo` at `4.7 class_db.h:120-157` **loses `StringName inherits` and `StringName name`
entirely**, along with `constant_map`, `enum_map` and `signal_map` — all folded into `GDType`. Any
walker reading a class name out of `ClassInfo` breaks at 4.7 and must go through
`ClassInfo::gdtype->name`. 4.6 is the transitional tag carrying both.

And **4.6 and 4.7 are shipped stable tags now** (`4.6-stable`…`4.6.3-stable`,
`4.7-stable`…`4.7.2-stable`), not branches. §13.7's "4.6/master" framing collapses three now-distinct
ABIs and should not be quoted as one.

### 15.6 What the calibrator needs, ranked

| Version | Work | Why |
| --- | --- | --- |
| **4.4** | **A version-gate entry + one calibration run** | RTTI already covers identity, and every version-sensitive reader 4.4 needs *already exists for 4.3* — the `cname`-bearing `StringName::_Data`, the 48-byte `HashMap` with `head_element` at `+0x18`, the `HashMap` walker, unchanged `MethodBind` and `ObjectSlot`. **The matrix widens to 4.2–4.5 for the cost of a table entry.** The one thing that would fail is treating 4.4 as an alias for 4.3's *offsets*. |
| **4.6** | One `AHashMap` walker + a profile | Simpler than the walk it replaces. Everything else carries over from 4.5. Optionally swap class identity to `_gdtype_ptr` for a better answer. |
| **4.7 / master** | Re-plumb §13.4 through `GDType` | The class-metadata layer, not the ABI. Decide deliberately rather than extrapolating from 4.6. |
| **Nothing** | getter decoder, `ObjectDB` anchor | Both premises verified intact at master. |
