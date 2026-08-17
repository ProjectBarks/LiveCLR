namespace LiveClr.Calibration;

/// <summary>
/// Which kind of ground truth produced a result. Determines how many samples are needed
/// before a single surviving candidate may be called an answer.
/// </summary>
/// <remarks>
/// Analysis doc §12.5 measured both kinds and they behave differently, so treating them the
/// same would either block a legitimate derivation or bless an unsafe one.
/// </remarks>
public enum CalibrationTechnique
{
    /// <summary>
    /// The expected value is an address that exists exactly once in the process — a parent
    /// pointer, a known child, a native handle. A specific 64-bit address appearing in a slot
    /// is strong evidence by itself; §12.5 derived parent <c>0x128</c> from one pair.
    /// </summary>
    Structural,

    /// <summary>
    /// The expected value is a semantic quantity — a size, a count, a coordinate. These
    /// collide constantly with cached copies, defaults and neighbouring fields: §12.5's single
    /// 200x50 control produced four candidate size offsets. One sample is never an answer.
    /// </summary>
    Semantic,
}

/// <summary>
/// The candidate offsets a probe found, plus everything needed to judge whether they are
/// trustworthy: how many distinct samples they survived, and whether the whole scan window
/// was actually readable.
/// </summary>
/// <remarks>
/// <para>This type exists to stop callers treating "the first candidate" as "the answer".
/// Analysis doc §12.5 measured the trap precisely: scanning one 200x50 control for its size
/// returned <b>four</b> candidates (0x4c0, 0x4c8, 0x4d4, 0x4f4), of which one was correct.
/// Nothing in a single-sample result distinguishes them. Intersecting with a second control
/// of a different size left exactly one.</para>
///
/// <para>So a bare <c>int</c> return would be a lie, and a <c>List&lt;int&gt;</c> return would
/// be silently ignorable. <see cref="Offset"/> throws unless the result is
/// <see cref="IsDetermined"/>, which requires all three of:</para>
/// <list type="number">
/// <item>exactly one surviving candidate;</item>
/// <item>full coverage of every scan window — see <see cref="CompleteCoverage"/>;</item>
/// <item>at least two distinct samples, for <see cref="CalibrationTechnique.Semantic"/> results.</item>
/// </list>
///
/// <para>Rule 2 is not defensive padding. If part of a window is unreadable, the true offset
/// can be dropped from one sample's candidate set while a coincidental co-varying value
/// survives in all of them — the intersection then reports a <i>unique</i> and <i>wrong</i>
/// offset. A confident wrong answer is worse than a miss, and it is the exact outcome this
/// whole calibration design exists to prevent.</para>
/// </remarks>
public sealed class CalibrationResult
{
    /// <summary>Identifies one scan: which object, and what was expected of it.</summary>
    internal readonly record struct SampleKey(ulong Address, string Expectation);

    private readonly HashSet<SampleKey> _sampleKeys;

    internal CalibrationResult(
        IReadOnlyList<int> candidates,
        CalibrationTechnique technique,
        HashSet<SampleKey> sampleKeys,
        bool completeCoverage,
        string description)
    {
        Candidates = candidates;
        Technique = technique;
        _sampleKeys = sampleKeys;
        CompleteCoverage = completeCoverage;
        Description = description;
    }

    /// <summary>Ascending, distinct byte offsets that satisfied every sample.</summary>
    public IReadOnlyList<int> Candidates { get; }

    /// <summary>Which gate applies before a single candidate counts as an answer.</summary>
    public CalibrationTechnique Technique { get; }

    /// <summary>
    /// How many <b>distinct objects</b> were scanned. Intersecting the same sample twice does
    /// not count twice — that would defeat the gate rather than satisfy it.
    /// </summary>
    public int SampleCount => _sampleKeys.Select(k => k.Address).Distinct().Count();

    /// <summary>
    /// How many distinct expected values the samples carried. Two objects that happen to share
    /// a value cannot separate the real field from a co-varying neighbour (§12.5's collapse
    /// worked only because the second control had a DIFFERENT size), so a semantic derivation
    /// needs this to be at least two as well.
    /// </summary>
    public int DistinctExpectationCount => _sampleKeys.Select(k => k.Expectation).Distinct().Count();

    /// <summary>
    /// True when every byte of every scan window was readable. False means candidates may have
    /// been silently dropped, so surviving candidates are a subset of the truth, not the truth.
    /// </summary>
    public bool CompleteCoverage { get; }

    /// <summary>What was being looked for. Used only to make failure messages actionable.</summary>
    public string Description { get; }

    /// <summary>Exactly one candidate survived. Necessary for an answer, not sufficient — see <see cref="IsDetermined"/>.</summary>
    public bool IsUnique => Candidates.Count == 1;

    /// <summary>More than one candidate survived. Add another sample with a DIFFERENT expected value.</summary>
    public bool IsAmbiguous => Candidates.Count > 1;

    /// <summary>Nothing matched. Either the layout is not what you think, or the window was too small/unreadable.</summary>
    public bool IsEmpty => Candidates.Count == 0;

    /// <summary>True when <see cref="Offset"/> will return rather than throw.</summary>
    public bool IsDetermined =>
        IsUnique && CompleteCoverage &&
        (Technique == CalibrationTechnique.Structural ||
         (SampleCount >= 2 && DistinctExpectationCount >= 2));

    /// <summary>The single derived offset.</summary>
    /// <exception cref="CalibrationException">
    /// The result is not determined: zero or several candidates, incomplete window coverage, or
    /// a semantic derivation from a single sample. The message says which.
    /// </exception>
    public int Offset => IsDetermined
        ? Candidates[0]
        : throw new CalibrationException(BuildFailureMessage());

    /// <summary>Non-throwing form of <see cref="Offset"/>. False whenever the result is not determined.</summary>
    public bool TryGetOffset(out int offset)
    {
        offset = IsDetermined ? Candidates[0] : 0;
        return IsDetermined;
    }

    /// <summary>
    /// Explicitly accept a result derived from a partially unreadable window, for the case where
    /// the caller knows the missing bytes cannot matter.
    /// </summary>
    /// <remarks>
    /// Deliberately a separate, named call: it is the point where a caller takes responsibility
    /// for the possibility that the true offset lay in the unreadable part. Prefer shrinking
    /// <c>scanBytes</c>, or sampling an object whose window is fully mapped.
    /// </remarks>
    public CalibrationResult AllowIncompleteCoverage() =>
        CompleteCoverage
            ? this
            : new CalibrationResult(
                Candidates, Technique, _sampleKeys, true, $"{Description} [partial coverage accepted]");

    /// <summary>Keep only offsets present in both results — the §12.5 collapse step.</summary>
    /// <remarks>
    /// Coverage is conjunctive: an intersection is only as trustworthy as its least complete
    /// input, because it is exactly the incomplete one that can have dropped the true offset.
    /// </remarks>
    public CalibrationResult Intersect(CalibrationResult other)
    {
        ArgumentNullException.ThrowIfNull(other);

        var keep = new HashSet<int>(other.Candidates);
        var merged = new List<int>();
        foreach (int c in Candidates)
            if (keep.Contains(c)) merged.Add(c);

        var keys = new HashSet<SampleKey>(_sampleKeys);
        keys.UnionWith(other._sampleKeys);

        // The stricter technique wins: a semantic input taints the whole derivation.
        var technique = Technique == CalibrationTechnique.Semantic || other.Technique == CalibrationTechnique.Semantic
            ? CalibrationTechnique.Semantic
            : CalibrationTechnique.Structural;

        string description = Description == other.Description
            ? Description
            : $"{Description} ∩ {other.Description}";

        return new CalibrationResult(
            merged, technique, keys, CompleteCoverage && other.CompleteCoverage, description);
    }

    /// <summary>Intersect a whole series of results. Empty input yields an empty, undetermined result.</summary>
    public static CalibrationResult Intersect(IEnumerable<CalibrationResult> results)
    {
        ArgumentNullException.ThrowIfNull(results);

        CalibrationResult? acc = null;
        foreach (var r in results)
            acc = acc is null ? r : acc.Intersect(r);

        return acc ?? new CalibrationResult(
            Array.Empty<int>(), CalibrationTechnique.Semantic, new HashSet<SampleKey>(), false, "empty intersection");
    }

    internal static CalibrationResult From(
        IEnumerable<int> candidates,
        CalibrationTechnique technique,
        SampleKey sampleKey,
        bool completeCoverage,
        string description)
    {
        var list = new List<int>();
        foreach (int c in candidates)
            if (list.Count == 0 || list[^1] != c) list.Add(c);

        return new CalibrationResult(
            list, technique, new HashSet<SampleKey> { sampleKey }, completeCoverage, description);
    }

    private string BuildFailureMessage()
    {
        string coverage = CompleteCoverage
            ? string.Empty
            : " Part of the scan window was UNREADABLE, so candidates may have been dropped — " +
              "including, possibly, the correct one. Shrink scanBytes, sample a fully-mapped " +
              "object, or call AllowIncompleteCoverage() to accept that risk explicitly.";

        if (IsEmpty)
        {
            return $"No offset satisfied {Description} across {SampleCount} sample(s). " +
                   "Either the expected value is wrong or the scan window is too small." + coverage;
        }

        string list = string.Join(", ", Candidates.Select(c => $"0x{c:x}"));

        if (IsAmbiguous)
        {
            return $"{Candidates.Count} candidate offsets ({list}) for {Description} after " +
                   $"{SampleCount} sample(s) — the offset is NOT determined. Add another sample of the " +
                   "same struct type with a DIFFERENT expected value and intersect; see analysis doc " +
                   "§12.5, where one control gave four candidates and a second collapsed them to one." +
                   coverage;
        }

        if (!CompleteCoverage)
            return $"Single candidate ({list}) for {Description}, but it is NOT trustworthy." + coverage;

        if (SampleCount >= 2 && DistinctExpectationCount < 2)
        {
            return $"Single candidate ({list}) for {Description} from {SampleCount} samples that all " +
                   "expected the SAME value. Objects sharing a value cannot separate the real field " +
                   "from a co-varying neighbour — §12.5's four candidates collapsed only because the " +
                   "second control had a different size.";
        }

        return $"Single candidate ({list}) for {Description} from ONE sample. A semantic value " +
               "(size, count, coordinate) collides with cached copies and neighbouring fields, so one " +
               "sample yields candidates, not an offset — analysis doc §12.5. Intersect a second sample " +
               "of the same struct type with a DIFFERENT expected value, or read Candidates directly if " +
               "you only meant to inspect.";
    }

    /// <inheritdoc />
    public override string ToString() =>
        $"{Description}: [{string.Join(", ", Candidates.Select(c => $"0x{c:x}"))}] from {SampleCount} sample(s)" +
        $", {Technique}{(CompleteCoverage ? string.Empty : ", INCOMPLETE COVERAGE")}";
}

/// <summary>Calibration produced no usable answer. Distinct from a read failure.</summary>
/// <remarks>
/// Separate from <see cref="LiveClr.Memory.MemoryAccessException"/> on purpose: §4.8's
/// <c>isTransientRead</c> retry must not treat "the layout is not what you assumed" as a
/// transient condition worth retrying.
/// </remarks>
public sealed class CalibrationException : Exception
{
    /// <summary>Creates the exception with an explanatory message.</summary>
    public CalibrationException(string message) : base(message) { }
}
