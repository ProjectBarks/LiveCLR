namespace LiveClr.Tests.Runtime;

using LiveClr.Memory;
using LiveClr.Runtime;

/// <summary>
/// Proves that the <c>FieldDesc</c> encoding is DERIVED from the runtime's own published
/// ground truth, not recognised from a table.
/// </summary>
/// <remarks>
/// The evidence standard is §12.5's: a derivation that only ever succeeds against one layout
/// is indistinguishable from a hardcode, so the same calibrator is run against two unrelated
/// encodings — different word, different bit position, absolute versus self-relative
/// back-pointer — and must find both. A third test corrupts the anchor and requires the
/// calibrator to report failure rather than produce a plausible answer, which is the property
/// §12.4e says actually matters.
/// </remarks>
public sealed class FieldDescCalibrationTests
{
    [Theory]
    [InlineData(FieldDescStyle.CoreClrLike, 12, 0)]
    [InlineData(FieldDescStyle.Alternate, 20, 5)]
    public void DerivesTheOffsetEncodingFromPublishedExceptionOffsets(FieldDescStyle style, int expectedWord, int expectedShift)
    {
        using SyntheticClrTarget target = SyntheticClrTarget.Build(style);
        using LiveProcess process = target.Attach();

        FieldDescCalibration calibration = process.FieldDescCalibration;

        Assert.True(calibration.IsCalibrated, calibration.Detail);
        Assert.Equal(1, calibration.CandidateCount);
        Assert.True(calibration.SampleCount >= 3, $"only {calibration.SampleCount} samples: {calibration.Detail}");

        FieldDescEncoding encoding = calibration.Encoding!.Value;
        Assert.Equal(expectedWord, encoding.OffsetByteOffset);
        Assert.Equal(expectedShift, encoding.OffsetBitShift);

        // 27 bits of offset, 5 of element type — the layout live validation measured on
        // CoreCLR 9.0.725.31616. Both fixture encodings pack it the same way, and neither
        // number is written down anywhere in the production code.
        Assert.Equal(27, encoding.OffsetBitWidth);
        Assert.Equal(0, calibration.CorpusViolations);
        Assert.True(calibration.CorpusFields >= 8, $"corpus too small: {calibration.Detail}");
    }

    [Fact]
    public void TheAnchorsAloneCannotChooseTheWidthSoTheCorpusDoes()
    {
        // The measured defect, pinned. Every offset the descriptor publishes for
        // System.Exception has an EVEN element type, so the bit above the offset field is zero
        // in all eight anchors and widths 27 AND 28 reproduce them identically. Nothing in the
        // anchors can separate the two; the earlier version resolved the tie by taking the wider
        // one and silently broke 31% of a real assembly's instance fields.
        using SyntheticClrTarget target = SyntheticClrTarget.Build();
        using LiveProcess process = target.Attach();

        FieldDescEncoding encoding = process.FieldDescCalibration.Encoding!.Value;

        // Confirm the ambiguity is real in this fixture: decoding an anchor at 28 bits gives the
        // same answer as at 27, so the anchor evidence genuinely does not distinguish them.
        const uint AnchorWord = 8u | (18u << 27);       // _message: offset 8, ELEMENT_TYPE_CLASS
        Assert.Equal(8u, FieldDescEncoding.Decode(AnchorWord, 0, 27));
        Assert.Equal(8u, FieldDescEncoding.Decode(AnchorWord, 0, 28));

        // And confirm the corpus can: an ODD element type sets bit 27, which 28 swallows.
        const uint OddWord = 8u | (17u << 27);          // a struct field, ELEMENT_TYPE_VALUETYPE
        Assert.Equal(8u, FieldDescEncoding.Decode(OddWord, 0, 27));
        Assert.Equal(8u + 0x800_0000u, FieldDescEncoding.Decode(OddWord, 0, 28));

        Assert.Equal(27, encoding.OffsetBitWidth);
        Assert.Contains("belongs to the neighbouring field", process.FieldDescCalibration.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public void FieldsWithAnOddElementTypeAreReadable()
    {
        // The 31% that a one-bit-too-wide window loses: every struct, double and unsigned field.
        // Position is ELEMENT_TYPE_VALUETYPE (17) and Numbers is SZARRAY (29) — both odd.
        using SyntheticClrTarget target = SyntheticClrTarget.Build();
        using LiveProcess process = target.Attach();
        using ISnapshot snapshot = process.BeginSnapshot();

        var derived = (ClrObject)snapshot.Object(target.DerivedAddress)!;

        Assert.True(derived.TryGetFieldLocation(nameof(FixtureDerived.Position), out ClrFieldLocation location));
        Assert.Equal(32, location.Offset);

        IClrValue position = derived.Field(nameof(FixtureDerived.Position))!;

        // An inline struct is not a reference, and must not be followed as one.
        Assert.Null(position.AsObject());

        FixturePoint value = position.Read<FixturePoint>();
        Assert.Equal(122, value.X);
        Assert.Equal(183, value.Y);

        Assert.Equal(3, snapshot.Object(target.HolderAddress)!.Field(nameof(FixtureHolder.Numbers))!.AsArray()!.Count);
    }

    [Fact]
    public void FindsTheBackPointerInWhicheverFormTheRuntimeUses()
    {
        using SyntheticClrTarget absolute = SyntheticClrTarget.Build(FieldDescStyle.CoreClrLike);
        using LiveProcess absoluteProcess = absolute.Attach();

        using SyntheticClrTarget relative = SyntheticClrTarget.Build(FieldDescStyle.Alternate);
        using LiveProcess relativeProcess = relative.Attach();

        FieldDescEncoding first = absoluteProcess.FieldDescCalibration.Encoding!.Value;
        FieldDescEncoding second = relativeProcess.FieldDescCalibration.Encoding!.Value;

        Assert.False(first.EnclosingIsRelative);
        Assert.Equal(0, first.EnclosingSlot);

        Assert.True(second.EnclosingIsRelative);
        Assert.Equal(8, second.EnclosingSlot);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(3)]
    [InlineData(7)]
    public void DerivesAnEntryMaskThatClearsWhateverFlagBitsTheFieldMapCarries(int flags)
    {
        // §5.4: real FieldDefToDescMap entries carry flag bits, and an unmasked entry is
        // therefore a misaligned pointer rather than a FieldDesc. This is the shipping path —
        // a fixture writing clean pointers exercises only the case where the mask cannot matter.
        using SyntheticClrTarget target = SyntheticClrTarget.Build(
            new SyntheticTargetOptions { FieldMapEntryFlags = flags });
        using LiveProcess process = target.Attach();

        // The entries really are dirty — otherwise every assertion below would hold vacuously.
        Assert.True(target.Memory.TryReadPointer(target.SampleFieldMapSlot, out ulong rawEntry));
        Assert.Equal((ulong)flags, rawEntry & 7);

        FieldDescCalibration calibration = process.FieldDescCalibration;
        Assert.True(calibration.IsCalibrated, calibration.Detail);

        FieldDescEncoding encoding = calibration.Encoding!.Value;
        Assert.Equal(0UL, (ulong)flags & encoding.EntryMask);

        // Derivation is not the point on its own; the masking has to survive into lookups.
        using ISnapshot snapshot = process.BeginSnapshot();
        IClrObject derived = snapshot.Object(target.DerivedAddress)!;

        Assert.Equal(61, derived.Field(nameof(FixtureBase.Hp))!.Read<int>());
        Assert.Equal(SyntheticClrTarget.ExpectedName, derived.Field(nameof(FixtureDerived.Name))!.AsString());
    }

    [Fact]
    public void PrefersTheMostRestrictiveMaskEvenWhenTheEntriesAreClean()
    {
        // The candidate order is the guard against §12.5's failure mode: on a flag-bearing
        // runtime the no-op mask asks whether a misaligned window happens to reproduce all eight
        // offsets, and a yes there is a confident wrong encoding with no second constraint to
        // catch it. ~7 is a no-op on an aligned pointer, so trying it first costs nothing here
        // and is the only candidate that is right in both worlds.
        using SyntheticClrTarget target = SyntheticClrTarget.Build();
        using LiveProcess process = target.Attach();

        Assert.Equal(~7UL, process.FieldDescCalibration.Encoding!.Value.EntryMask);
    }

    [Fact]
    public void UsesEveryExceptionFieldTheDescriptorPublishes()
    {
        using SyntheticClrTarget target = SyntheticClrTarget.Build();
        using LiveProcess process = target.Attach();

        // The fixture lays down one FieldDesc per published Exception field it finds in the
        // real CoreLib metadata; the calibrator must consume all of them, not just enough.
        Assert.Equal(target.PublishedExceptionFields, process.FieldDescCalibration.SampleCount);
    }

    [Fact]
    public void ReportsFailureRatherThanGuessingWhenCalibrationIsDisabled()
    {
        using SyntheticClrTarget target = SyntheticClrTarget.Build();
        using LiveProcess process = target.Attach(new LiveProcessOptions { CalibrateFieldOffsets = false });

        Assert.False(process.FieldDescCalibration.IsCalibrated);
        Assert.Contains("not attempted", process.FieldDescCalibration.Detail, StringComparison.OrdinalIgnoreCase);

        // And the whole field-reading surface degrades to null rather than inventing offsets.
        using ISnapshot snapshot = process.BeginSnapshot();
        IClrObject? holder = snapshot.Object(target.HolderAddress);

        Assert.NotNull(holder);
        Assert.Null(holder.Field("Items"));
    }

    [Fact]
    public void CallerSuppliedOffsetsFillTheGapWhenTheRuntimeCannotAnswer()
    {
        // §5.5's sanctioned hand-off: something else resolves the layout once at connect.
        var explicitLayout = new ExplicitFieldLayoutSource()
            .AddType(typeof(FixtureBase).FullName!, (nameof(FixtureBase.Hp), 8));

        using SyntheticClrTarget target = SyntheticClrTarget.Build();
        using LiveProcess process = target.Attach(new LiveProcessOptions
        {
            CalibrateFieldOffsets = false,
            FieldLayout = explicitLayout,
        });

        using ISnapshot snapshot = process.BeginSnapshot();
        IClrObject? derived = snapshot.Object(target.DerivedAddress);

        Assert.NotNull(derived);
        Assert.Equal(61, derived.Field("Hp")!.Read<int>());

        // Fields nobody supplied stay unavailable — no interpolation, no neighbouring guess.
        Assert.Null(derived.Field("Name"));
    }
}
