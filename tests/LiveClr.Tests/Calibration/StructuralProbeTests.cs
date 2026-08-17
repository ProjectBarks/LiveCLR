namespace LiveClr.Tests.Calibration;

using LiveClr.Calibration;
using LiveClr.Fixtures;
using LiveClr.Tests.Fixtures;

/// <summary>
/// Rebuilds analysis doc §12.5's experiment as a synthetic fixture: known layout, probe with
/// no prior knowledge, assert it rediscovers the offsets. Offsets below are the doc's real
/// derived values (0x128 parent, 0x148 child-list head, 0x4c0 size) so a regression here reads
/// against the recorded live result.
/// </summary>
public class StructuralProbeTests
{
    private const ulong Parent = 0x0000_01aa_1000_0000;
    private const ulong Child = 0x0000_01aa_1000_8000;
    private const ulong ListNode = 0x0000_01aa_1001_0000;

    private const int ParentOffset = 0x128;
    private const int ChildListOffset = 0x148;
    private const int SizeOffset = 0x4c0;

    // ---- Technique 1: a field holding a known pointer (STRUCTURAL) ---------

    [Fact]
    public void Rediscovers_the_parent_pointer_offset()
    {
        var child = new SyntheticObject(Child, 0x600, junkSeed: 21)
            .Put(ParentOffset, Parent);

        var probe = ProbeOver(child);
        var result = probe.FindPointerOffset(Child, Parent, scanBytes: 0x600);

        // Structural: a live address is unique in the process, so one sample may determine it.
        Assert.Equal(CalibrationTechnique.Structural, result.Technique);
        Assert.True(result.CompleteCoverage);
        Assert.True(result.IsDetermined);
        Assert.Equal(ParentOffset, result.Offset);
        Assert.True(result.TryGetOffset(out int offset));
        Assert.Equal(ParentOffset, offset);
    }

    [Fact]
    public void Pointer_scan_across_samples_removes_a_coincidental_match()
    {
        // Two children of the same parent. Each has a junk slot that happens to hold the
        // parent's address, but at different offsets — only the real field survives both.
        var a = new SyntheticObject(Child, 0x400, junkSeed: 22)
            .Put(ParentOffset, Parent)
            .Put(0x40, Parent);

        var b = new SyntheticObject(Child + 0x1000, 0x400, junkSeed: 23)
            .Put(ParentOffset, Parent)
            .Put(0x90, Parent);

        var probe = ProbeOver(a, b);

        Assert.Equal(2, probe.FindPointerOffset(Child, Parent, 0x400).Candidates.Count);

        var samples = new[]
        {
            new PointerSample(Child, Parent),
            new PointerSample(Child + 0x1000, Parent),
        };
        Assert.Equal(ParentOffset, probe.FindPointerOffsetAcross(samples, 0x400).Offset);
    }

    [Fact]
    public void Rediscovers_an_indirect_pointer_offset()
    {
        // §12.5's child-list head: container -> list node -> (+0x18) known child.
        var container = new SyntheticObject(Parent, 0x400, junkSeed: 24)
            .Put(ChildListOffset, ListNode)
            .Put(0x30, ListNode + 0x800);   // decoy pointer into a node whose +0x18 is junk

        var node = new SyntheticObject(ListNode, 0x1000, junkSeed: 25)
            .Put(0x18, Child);

        var probe = ProbeOver(container, node);
        var result = probe.FindIndirectPointerOffset(Parent, Child, indirectionOffset: 0x18, scanBytes: 0x400);

        Assert.True(result.IsUnique);
        Assert.Equal(ChildListOffset, result.Offset);
    }

    [Fact]
    public void Indirect_pointer_scan_intersects_across_containers()
    {
        var containerA = new SyntheticObject(Parent, 0x400, junkSeed: 26)
            .Put(ChildListOffset, ListNode)
            .Put(0x60, ListNode);              // coincidence unique to A

        var containerB = new SyntheticObject(Parent + 0x2000, 0x400, junkSeed: 27)
            .Put(ChildListOffset, ListNode + 0x2000);

        var nodeA = new SyntheticObject(ListNode, 0x100, junkSeed: 28).Put(0x18, Child);
        var nodeB = new SyntheticObject(ListNode + 0x2000, 0x100, junkSeed: 29).Put(0x18, Child + 0x2000);

        var probe = ProbeOver(containerA, containerB, nodeA, nodeB);

        var samples = new[]
        {
            new PointerSample(Parent, Child),
            new PointerSample(Parent + 0x2000, Child + 0x2000),
        };

        Assert.Equal(ChildListOffset, probe.FindIndirectPointerOffsetAcross(samples, 0x18, 0x400).Offset);
    }

    // ---- Technique 2: known values, and why one sample is not enough --------

    /// <summary>
    /// The core claim of §12.5. A single 200x50 control produced four candidate size offsets
    /// (0x4c0, 0x4c8, 0x4d4, 0x4f4); intersecting with a second control of a different size
    /// left exactly one. This test reproduces both halves — the ambiguity AND the collapse —
    /// because the ambiguity is the part an API is tempted to hide.
    /// </summary>
    [Fact]
    public void One_sample_is_ambiguous_and_intersection_collapses_it_to_one()
    {
        // Control A is 200x50. Its size lives at 0x4c0, but three other slots happen to hold
        // the same pair — a cached minimum size, a layout scratch value, a stale copy.
        var small = new SyntheticObject(Child, 0x600, junkSeed: 31)
            .PutPair(SizeOffset, 200f, 50f)
            .PutPair(0x4c8, 200f, 50f)
            .PutPair(0x4d4, 200f, 50f)
            .PutPair(0x4f4, 200f, 50f);

        // Control B is full-screen: size is the design viewport. Its decoys sit elsewhere and
        // hold other values, so only the real field agrees with both samples.
        var fullScreen = new SyntheticObject(Child + 0x1000, 0x600, junkSeed: 32)
            .PutPair(SizeOffset, 1920f, 1080f)
            .PutPair(0x4c8, 640f, 480f)
            .PutPair(0x4d4, 0f, 0f)
            .PutPair(0x4f4, 1920f, 720f);

        var probe = ProbeOver(small, fullScreen);

        var single = probe.FindAdjacentPairOffset(Child, 200f, 50f, scanBytes: 0x600);
        Assert.True(single.IsAmbiguous);
        Assert.Equal(new[] { 0x4c0, 0x4c8, 0x4d4, 0x4f4 }, single.Candidates);

        // Asking a single ambiguous sample for "the" offset must fail loudly, not pick one.
        var ex = Assert.Throws<CalibrationException>(() => single.Offset);
        Assert.Contains("§12.5", ex.Message);
        Assert.Contains("DIFFERENT", ex.Message);

        var samples = new[]
        {
            new PairSample<float>(Child, 200f, 50f),
            new PairSample<float>(Child + 0x1000, 1920f, 1080f),
        };
        var intersected = probe.FindAdjacentPairOffsetAcross(samples, scanBytes: 0x600);

        Assert.True(intersected.IsUnique);
        Assert.Equal(SizeOffset, intersected.Offset);
        Assert.Equal(2, intersected.SampleCount);
    }

    /// <summary>
    /// The gate that documentation alone used to provide: a semantic scan that happens to yield
    /// exactly one candidate is STILL not an answer, because a lone match is indistinguishable
    /// from a lucky one. Contrast with <see cref="Rediscovers_the_parent_pointer_offset"/>,
    /// where one structural sample is legitimately enough (§12.5 derived parent 0x128 that way).
    /// </summary>
    [Fact]
    public void A_unique_single_sample_semantic_match_is_still_not_an_answer()
    {
        var control = new SyntheticObject(Child, 0x600, junkSeed: 51).PutPair(SizeOffset, 1920f, 1080f);
        var probe = ProbeOver(control);

        var result = probe.FindAdjacentPairOffset(Child, 1920f, 1080f, 0x600);

        Assert.True(result.IsUnique);                 // one candidate ...
        Assert.Equal(new[] { SizeOffset }, result.Candidates);
        Assert.Equal(1, result.SampleCount);
        Assert.Equal(CalibrationTechnique.Semantic, result.Technique);
        Assert.False(result.IsDetermined);            // ... but not an answer
        Assert.False(result.TryGetOffset(out _));

        var ex = Assert.Throws<CalibrationException>(() => result.Offset);
        Assert.Contains("ONE sample", ex.Message);
        Assert.Contains("§12.5", ex.Message);

        // Same for the scalar and tolerant forms.
        Assert.False(probe.FindValueOffset(Child, 1920f, 0x600).IsDetermined);
        Assert.False(probe.FindFloatOffset(Child, 1920f, 0.5f, 0x600).IsDetermined);
        Assert.False(probe.FindFloatPairOffset(Child, 1920f, 1080f, 0.5f, 0x600).IsDetermined);
    }

    [Fact]
    public void Intersecting_the_same_sample_twice_does_not_satisfy_the_gate()
    {
        // Otherwise the semantic gate is one Intersect() call away from being defeated.
        var control = new SyntheticObject(Child, 0x600, junkSeed: 52).PutPair(SizeOffset, 1920f, 1080f);
        var probe = ProbeOver(control);

        var once = probe.FindAdjacentPairOffset(Child, 1920f, 1080f, 0x600);
        var twice = once.Intersect(once);

        Assert.True(twice.IsUnique);
        Assert.Equal(1, twice.SampleCount);
        Assert.False(twice.IsDetermined);
        Assert.Throws<CalibrationException>(() => twice.Offset);
    }

    [Fact]
    public void Hand_intersecting_two_samples_with_the_same_value_does_not_satisfy_the_gate()
    {
        // The Across methods reject this outright; hand-intersection has to reject it too, or
        // the "different values" requirement is only enforced on one of two paths.
        var a = new SyntheticObject(Child, 0x600, junkSeed: 60).PutPair(SizeOffset, 200f, 50f);
        var b = new SyntheticObject(Child + 0x1000, 0x600, junkSeed: 61).PutPair(SizeOffset, 200f, 50f);
        var probe = ProbeOver(a, b);

        var merged = probe.FindAdjacentPairOffset(Child, 200f, 50f, 0x600)
            .Intersect(probe.FindAdjacentPairOffset(Child + 0x1000, 200f, 50f, 0x600));

        Assert.True(merged.IsUnique);
        Assert.Equal(2, merged.SampleCount);
        Assert.Equal(1, merged.DistinctExpectationCount);
        Assert.False(merged.IsDetermined);
        Assert.Contains("SAME value", Assert.Throws<CalibrationException>(() => merged.Offset).Message);
    }

    [Fact]
    public void Scalar_value_offsets_intersect_the_same_way()
    {
        var a = new SyntheticObject(Child, 0x200, junkSeed: 33)
            .Put(0x30, 7)
            .Put(0x80, 7);

        var b = new SyntheticObject(Child + 0x1000, 0x200, junkSeed: 34)
            .Put(0x30, 12)
            .Put(0x80, 99);

        var probe = ProbeOver(a, b);

        Assert.Equal(2, probe.FindValueOffset(Child, 7, 0x200).Candidates.Count);

        var samples = new[] { new ValueSample<int>(Child, 7), new ValueSample<int>(Child + 0x1000, 12) };
        Assert.Equal(0x30, probe.FindValueOffsetAcross(samples, 0x200).Offset);
    }

    [Fact]
    public void Tolerant_scalar_scan_intersects_across_samples()
    {
        // The most collision-prone probe of all: one component, plus slack. It needs the
        // Across form more than anything else does.
        var a = new SyntheticObject(Child, 0x200, junkSeed: 53).Put(0x30, 99.9997f).Put(0x50, 99.9997f);
        var b = new SyntheticObject(Child + 0x1000, 0x200, junkSeed: 54).Put(0x30, 250.0004f).Put(0x50, 12f);

        var probe = ProbeOver(a, b);

        Assert.True(probe.FindValueOffset(Child, 100f, 0x200).IsEmpty);          // exact scan finds nothing
        Assert.Equal(2, probe.FindFloatOffset(Child, 100f, 0.01f, 0x200).Candidates.Count);

        var samples = new[] { new ValueSample<float>(Child, 100f), new ValueSample<float>(Child + 0x1000, 250f) };
        Assert.Equal(0x30, probe.FindFloatOffsetAcross(samples, 0.01f, 0x200).Offset);
    }

    [Fact]
    public void Tolerant_float_pair_scan_matches_computed_values()
    {
        var a = new SyntheticObject(Child, 0x600, junkSeed: 39).PutPair(SizeOffset, 1919.9998f, 1080.0002f);
        var b = new SyntheticObject(Child + 0x1000, 0x600, junkSeed: 40).PutPair(SizeOffset, 200.0001f, 49.9999f);

        var probe = ProbeOver(a, b);

        Assert.True(probe.FindAdjacentPairOffset(Child, 1920f, 1080f, 0x600).IsEmpty);
        Assert.Equal(new[] { SizeOffset }, probe.FindFloatPairOffset(Child, 1920f, 1080f, 0.01f, 0x600).Candidates);

        var samples = new[]
        {
            new PairSample<float>(Child, 1920f, 1080f),
            new PairSample<float>(Child + 0x1000, 200f, 50f),
        };
        Assert.Equal(SizeOffset, probe.FindFloatPairOffsetAcross(samples, 0.01f, 0x600).Offset);
    }

    [Fact]
    public void NaN_matches_nothing_even_with_a_tolerance()
    {
        var obj = new SyntheticObject(Child, 0x100, junkSeed: 55).Put(0x20, float.NaN);
        var probe = ProbeOver(obj);

        Assert.True(probe.FindFloatOffset(Child, float.NaN, 0f, 0x100).IsEmpty);
        Assert.True(probe.FindFloatOffset(Child, float.NaN, 1000f, 0x100).IsEmpty);
    }

    // ---- Sample hygiene ----------------------------------------------------

    [Fact]
    public void Intersecting_probes_refuse_a_single_sample()
    {
        var probe = ProbeOver(new SyntheticObject(Child, 0x100, junkSeed: 35));

        var one = new[] { new ValueSample<int>(Child, 7) };
        var ex = Assert.Throws<ArgumentException>(() => probe.FindValueOffsetAcross(one, 0x100));
        Assert.Contains("at least two samples", ex.Message);
        Assert.Contains("§12.5", ex.Message);

        Assert.Throws<ArgumentException>(
            () => probe.FindPointerOffsetAcross(new[] { new PointerSample(Child, Parent) }, 0x100));
        Assert.Throws<ArgumentException>(
            () => probe.FindAdjacentPairOffsetAcross(new[] { new PairSample<float>(Child, 1f, 2f) }, 0x100));
    }

    [Fact]
    public void Intersecting_probes_refuse_useless_sample_sets()
    {
        var probe = ProbeOver(new SyntheticObject(Child, 0x100, junkSeed: 56));

        // Same object twice: the second scan returns the first's candidates, narrowing nothing.
        var duplicateAddress = new[] { new ValueSample<int>(Child, 7), new ValueSample<int>(Child, 9) };
        Assert.Contains("distinct objects",
            Assert.Throws<ArgumentException>(() => probe.FindValueOffsetAcross(duplicateAddress, 0x100)).Message);

        // Different objects, same expected value: cannot separate a co-varying neighbour.
        var sameValue = new[] { new ValueSample<int>(Child, 7), new ValueSample<int>(Child + 0x1000, 7) };
        Assert.Contains("DIFFERENT expected values",
            Assert.Throws<ArgumentException>(() => probe.FindValueOffsetAcross(sameValue, 0x100)).Message);

        // But a shared TARGET is legitimate for pointer samples: two children, one parent.
        var sharedParent = new[] { new PointerSample(Child, Parent), new PointerSample(Child + 0x1000, Parent) };
        probe.FindPointerOffsetAcross(sharedParent, 0x100);
    }

    [Fact]
    public void A_wrong_expectation_yields_nothing_and_says_why()
    {
        var obj = new SyntheticObject(Child, 0x100, junkSeed: 36).Put(0x20, 1234);
        var result = ProbeOver(obj).FindValueOffset(Child, 4321, 0x100);

        Assert.True(result.IsEmpty);
        Assert.False(result.TryGetOffset(out _));
        var ex = Assert.Throws<CalibrationException>(() => result.Offset);
        Assert.Contains("No offset satisfied", ex.Message);
    }

    // ---- Partial coverage: the confident-wrong-answer class ----------------

    /// <summary>
    /// The failure this design exists to prevent. Sample A's window runs into unmapped memory
    /// that contains the TRUE offset, so A's candidate set is missing it; a coincidental value
    /// that both objects happen to share survives instead. The intersection is unique and WRONG.
    /// It must not be reportable as an answer.
    /// </summary>
    [Fact]
    public void A_unique_candidate_from_an_incomplete_window_is_not_an_answer()
    {
        const int trueOffset = 0x140;
        const int coincidence = 0x40;

        // A is captured only up to 0x100, so the field at 0x140 is invisible in this sample.
        var a = new SyntheticObject(Child, 0x100, junkSeed: 57).Put(coincidence, 11);
        var b = new SyntheticObject(Child + 0x1000, 0x200, junkSeed: 58)
            .Put(trueOffset, 22)
            .Put(coincidence, 22);

        var probe = ProbeOver(a, b);

        var samples = new[] { new ValueSample<int>(Child, 11), new ValueSample<int>(Child + 0x1000, 22) };
        var result = probe.FindValueOffsetAcross(samples, scanBytes: 0x200);

        // Unique — and wrong. Coverage is what makes that detectable.
        Assert.True(result.IsUnique);
        Assert.Equal(coincidence, result.Candidates[0]);
        Assert.False(result.CompleteCoverage);
        Assert.False(result.IsDetermined);
        Assert.False(result.TryGetOffset(out _));

        var ex = Assert.Throws<CalibrationException>(() => result.Offset);
        Assert.Contains("UNREADABLE", ex.Message);
        Assert.Contains("AllowIncompleteCoverage", ex.Message);
    }

    [Fact]
    public void Partial_coverage_still_reports_what_it_found_and_can_be_accepted_explicitly()
    {
        // Two mapped chunks with a gap between them: the probe must still report candidates
        // from the readable parts rather than failing the whole window — while flagging that
        // the window was not whole.
        var first = new SyntheticObject(Child, 0x100, junkSeed: 40).Put(0x40, 4242);
        var second = new SyntheticObject(Child + 0x200, 0x100, junkSeed: 41).Put(0x40, 4242);

        var fixture = second.AddTo(first.AddTo(new RecordedMemoryBuilder())).Build();
        var probe = new StructuralProbe(fixture);

        var result = probe.FindValueOffset(Child, 4242, scanBytes: 0x300);
        Assert.Equal(new[] { 0x40, 0x240 }, result.Candidates);
        Assert.False(result.CompleteCoverage);

        // Opt-in is explicit and does not hand-wave the other gates: still ambiguous, still not
        // an answer.
        Assert.False(result.AllowIncompleteCoverage().IsDetermined);

        // A structural single-sample scan over a short window: refused by default because the
        // rest of the object was never read, accepted when the caller takes that risk on.
        var holed = ProbeOver(new SyntheticObject(Child, 0x100, junkSeed: 43).Put(0x20, Parent));
        var structural = holed.FindPointerOffset(Child, Parent, scanBytes: 0x300);

        Assert.True(structural.IsUnique);
        Assert.False(structural.CompleteCoverage);
        Assert.Throws<CalibrationException>(() => structural.Offset);
        Assert.Equal(0x20, structural.AllowIncompleteCoverage().Offset);
    }

    /// <summary>
    /// Readability is tracked by bisection, not by fixed-size chunks. A value sitting near the
    /// end of a captured region — inside it, but in the same chunk as the boundary — must still
    /// be found, or coarse chunking silently drops genuinely captured candidates.
    /// </summary>
    [Fact]
    public void Values_captured_near_a_region_boundary_are_still_found()
    {
        var fixture = new RecordedMemoryBuilder()
            .Add(Child, FakeTargetMemory.Junk(0x180, seed: 59))
            .Add<int>(Child + 0x150, 31337)
            .Build();

        var probe = new StructuralProbe(fixture);
        var result = probe.FindValueOffset(Child, 31337, scanBytes: 0x200);

        Assert.Equal(new[] { 0x150 }, result.Candidates);
        Assert.False(result.CompleteCoverage);   // 0x180..0x200 genuinely was not captured
    }

    // ---- Alignment, pointer width, argument validation ---------------------

    [Fact]
    public void Default_alignment_skips_unaligned_fields_and_alignment_one_finds_them()
    {
        var obj = new SyntheticObject(Child, 0x100, junkSeed: 37).Put(0x22, 0x1234_5678u);
        var probe = ProbeOver(obj);

        Assert.True(probe.FindValueOffset(Child, 0x1234_5678u, 0x100).IsEmpty);
        Assert.Equal(new[] { 0x22 }, probe.FindValueOffset(Child, 0x1234_5678u, 0x100, alignment: 1).Candidates);
    }

    [Fact]
    public void Pointer_scans_follow_the_targets_pointer_width()
    {
        var obj = new SyntheticObject(Child, 0x80, junkSeed: 38).Put(0x10, 0xdead_beefu);

        var fixture = obj.AddTo(new RecordedMemoryBuilder(is64Bit: false)).Build();
        var probe = new StructuralProbe(fixture);

        Assert.Equal(4, probe.PointerSize);
        Assert.Equal(0x10, probe.FindPointerOffset(Child, 0xdead_beef, 0x80).Offset);
    }

    [Fact]
    public void Rejects_a_nonsense_scan_window()
    {
        var probe = ProbeOver(new SyntheticObject(Child, 0x40, junkSeed: 42));

        Assert.Throws<ArgumentOutOfRangeException>(() => probe.FindValueOffset(Child, 1, 0));
        Assert.Throws<ArgumentOutOfRangeException>(() => probe.FindValueOffset(Child, 1, -8));
        Assert.Throws<ArgumentOutOfRangeException>(() => probe.FindValueOffset(Child, 1, 0x100, alignment: -1));
        Assert.Throws<ArgumentException>(() => probe.FindValueOffset(ulong.MaxValue - 4, 1, 0x100));
    }

    // ---- The two halves together -------------------------------------------

    /// <summary>
    /// The §8.8 payoff in one test: record from a "live" reader, persist, reload, calibrate.
    /// This is the shape a real CI regression takes — capture once against the game, then
    /// re-derive the offsets forever after with nothing running.
    /// </summary>
    [Fact]
    public void Calibrates_against_a_saved_and_reloaded_recording()
    {
        var image = FakeTargetMemory.Junk(0x600, seed: 50);
        Assert.True(BitConverter.TryWriteBytes(image.AsSpan(ParentOffset, 8), Parent));

        using var live = new FakeTargetMemory(Child, image);
        using var recorder = new RecordingMemoryReader(live, "synthetic capture");
        Assert.True(recorder.TryRead(Child, new byte[0x600]));

        using var stream = new MemoryStream();
        recorder.Save(stream);
        stream.Position = 0;

        var replay = RecordedMemory.Load(stream);
        Assert.Equal("synthetic capture", replay.Description);

        var result = new StructuralProbe(replay).FindPointerOffset(Child, Parent, 0x600);
        Assert.Equal(ParentOffset, result.Offset);
    }

    private static StructuralProbe ProbeOver(params SyntheticObject[] objects)
    {
        var builder = new RecordedMemoryBuilder(is64Bit: true, description: "synthetic");
        foreach (var o in objects) o.AddTo(builder);
        return new StructuralProbe(builder.Build());
    }
}
