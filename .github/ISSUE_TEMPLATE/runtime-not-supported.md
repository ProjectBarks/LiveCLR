---
name: Runtime or target not supported
about: LiveClr could not attach, bootstrap, or resolve types against a target
title: ''
labels: 'runtime-support'
assignees: ''
---

**Where did it stop?**
<!-- Tick the furthest step reached. -->
- [ ] attach / open process
- [ ] found the `coreclr` module
- [ ] located `DotNetRuntimeContractDescriptor`
- [ ] parsed the descriptor JSON
- [ ] resolved a module's ECMA-335 metadata
- [ ] calibrated instance field offsets
- [ ] read a field

**Target runtime version**
<!-- Exact version of coreclr.dll in the target. LiveClr requires .NET 9+; the descriptor
     does not exist before that. -->

**What the descriptor published**
<!-- If you got past step 4, the raw JSON is the single most useful thing you can attach.
     Different patch runtimes publish different type/global sets, and that is often the
     whole answer. -->

**Is the target self-contained or framework-dependent? Trimmed? NativeAOT?**
<!-- NativeAOT has no CoreCLR and is out of scope. -->

**Environment**
- Host OS / architecture:
- Same user as the target, or elevated?
