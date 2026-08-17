# Contributing

## Build and test

```bash
dotnet build -warnaserror
dotnet test
```

Windows and .NET 9 SDK. `-warnaserror` is not optional — see below.

The suite runs entirely on synthetic and recorded memory, so **no live process is needed**. If a
change requires one to test, that is usually a sign the seam is in the wrong place.

## The one principle

**A confident wrong answer is worse than a miss.**

This library reads another process's memory and interprets it. Every failure mode that matters
looks like success: a stale pointer that resolves to a different valid-looking object, a traversal
that ends early with every individual read succeeding, an offset derived from one ambiguous sample.
None of those raise an error.

So the bar for a change is not "does it work on my machine" but "how does it fail". Concretely:

- **Decline rather than guess.** If the runtime does not publish enough to be certain, return
  null/false and say why. There are several places where this library knowingly gives up; that is
  the design, not a gap to be filled with an assumption.
- **Fail closed.** A partial read is a failure, and must not leave plausible bytes in the caller's
  buffer.
- **Do not add a guard that cannot fire.** One was removed for exactly this reason: agree-twice
  checking inside a snapshot, where the page cache guarantees the second sample is identical. A
  guard callers trust but that never triggers is worse than no guard.

## Things that will be asked in review

- **Does the test fail against the old code?** Several bugs here were caught by tests that were
  written after the fix and would have passed before it. If a test cannot fail, it is documentation.
- **Would this test pass if the implementation were subtly wrong?** A real example from this
  repo: a "permuted" fixture whose permutation had fixed points at exactly the index under test, so
  the whole suite would have passed against an implementation that ignored the lookup entirely.
- **Is a validation being duplicated?** The PE header walk was written twice independently and the
  copies drifted within a single session, one silently losing all its bounds checks. One
  implementation per format parser, taking the union of hardening.

## Comments and docs

XML docs should explain **why**, not restate the signature. Where a constant or a check exists
because of a specific observed failure, say so — most of the non-obvious code here is non-obvious
because of something that was measured, and the measurement is the useful part.

## Native code

Any new P/Invoke goes in [`NativeMethods.cs`](src/LiveClr/Memory/NativeMethods.cs), so the total
native surface stays reviewable in one file. A PR adding a write, injection, suspension, or
thread-creation API will be declined regardless of intent — see [SECURITY.md](SECURITY.md).
