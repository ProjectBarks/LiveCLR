---
name: Wrong value returned
about: LiveClr returned data that was plausible but incorrect
title: ''
labels: 'wrong-value'
assignees: ''
---

<!--
This is the most important issue type in this repo. A confident wrong answer is treated
as more serious than a crash, because nothing errors and the caller has no way to tell.
-->

**What was read, and what did it return?**

**What was the correct value, and how do you know?**
<!-- Independent verification matters: a debugger, ClrMD, a known constant, source. -->

**Environment**
- Target runtime version (`dotnet --info` on the target, or the exact `coreclr.dll` version):
- LiveClr version / commit:
- Snapshot mode (`LiveValidated` / `ProcessSnapshot`):

**Did `Validate()` report anything?**
<!-- SnapshotHealth: FailedReads, StructuralAnomalies, Detail. If it said the snapshot was
     usable and the data was wrong, say so - that is a defect in the validator too. -->

**Reproduction**
<!-- A recorded fixture (Fixtures/RecordingMemoryReader -> Save) is worth far more than a
     description, and needs no live process to replay. -->
