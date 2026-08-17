namespace LiveClr.Tests.Runtime;

using LiveClr.Runtime;

/// <summary>
/// What happens when an input the reader depends on is damaged.
/// </summary>
/// <remarks>
/// The doc's recurring finding is that plausible wrong data costs more than an error (§7b.1,
/// §12.4e, §12.5). These tests assert the reader degrades in the specific shape claimed —
/// partial rather than total, loud rather than silent, refusal rather than a confident guess —
/// for each input that can realistically be missing on a runtime nobody has measured.
/// </remarks>
public sealed class DegradationTests
{
    [Fact]
    public void AnUnreadableChunkOfTheTypeMapCostsThoseRidsOnlyNotTheWholeModule()
    {
        // §5.4: the map may be segmented and neither Count nor Next is published, so the walk
        // can run into unmapped memory. A single bulk read would then lose EVERY type in the
        // module, which is the silent-empty failure mode §12.4b warns about.
        using SyntheticClrTarget target = SyntheticClrTarget.Build(new SyntheticTargetOptions { PunchTypeMapHole = true });
        using LiveProcess process = target.Attach();
        using ISnapshot snapshot = process.BeginSnapshot();

        Assert.NotEqual(0UL, target.TypeMapHolePage);

        // Types outside the hole still resolve...
        IClrObject? derived = snapshot.Object(target.DerivedAddress);
        Assert.NotNull(derived);
        Assert.Equal(SyntheticClrTarget.ExpectedName, derived.Field(nameof(FixtureDerived.Name))!.AsString());

        // ...including the CoreLib types that make List<T> and strings work at all.
        Assert.Equal(SyntheticClrTarget.ListCount, snapshot.Object(target.HolderAddress)!
            .Field(nameof(FixtureHolder.Items))!.AsList()!.Count);

        // ...and the loss is reported rather than hidden.
        ClrModuleInfo coreLib = Assert.Single(process.TypeSystem.Modules, m => m.ModulePointer == target.CoreLibModulePointer);
        Assert.True(coreLib.TypeMapGaps > 0, "the unmapped page should have cost at least one chunk");
        Assert.True(coreLib.MappedTypeCount > 0, "the rest of the map must survive");
    }

    [Fact]
    public void AnUnverifiableElementStrideMakesArraysUnreadableAndSaysSo()
    {
        // MethodTable's component-size encoding is not published; it is checked against
        // System.String and object[]. A runtime that fails that check cannot have its arrays
        // indexed — and must not report a count it will then refuse to serve.
        using SyntheticClrTarget target = SyntheticClrTarget.Build(
            new SyntheticTargetOptions { BreakComponentSizeEncoding = true });
        using LiveProcess process = target.Attach();

        Assert.False(process.TypeSystem.ComponentSizeIsTrusted);

        using ISnapshot snapshot = process.BeginSnapshot();
        var numbers = (ClrArray)snapshot.Object(target.HolderAddress)!.Field(nameof(FixtureHolder.Numbers))!.AsArray()!;

        Assert.False(numbers.IsReadable);
        Assert.Equal(0, numbers.Count);
        Assert.Equal(3, numbers.ReportedCount);
        Assert.True(numbers[0].IsNull);

        // Loud, not silent: an empty-looking collection that is really unreadable is exactly
        // the §12.4b bug, so it condemns the snapshot.
        SnapshotHealth health = snapshot.Validate();
        Assert.False(health.IsUsable);
        Assert.Contains("stride could not be verified", health.Detail!, StringComparison.Ordinal);
    }

    [Fact]
    public void AListWhoseBackingArrayIsNullReportsNoElementsAndFlagsTheDisagreement()
    {
        using SyntheticClrTarget target = SyntheticClrTarget.Build(new SyntheticTargetOptions { NullBackingArray = true });
        using LiveProcess process = target.Attach();
        using ISnapshot snapshot = process.BeginSnapshot();

        var list = (ClrList)snapshot.Object(target.NullItemsHolderAddress)!
            .Field(nameof(FixtureHolder.Items))!.AsList()!;

        Assert.Equal(0, list.Count);
        Assert.Equal(0, list.Capacity);
        Assert.Equal(3, list.ReportedCount);
        Assert.True(list[0].IsNull);

        SnapshotHealth health = snapshot.Validate();
        Assert.False(health.IsUsable);
        Assert.Equal(1, health.StructuralAnomalies);
    }

    [Fact]
    public void AnEmptyListWithNoBackingArrayIsNotAnAnomaly()
    {
        // _size 0 and _items null is an ordinary freshly-constructed list, not a torn read.
        using SyntheticClrTarget target = SyntheticClrTarget.Build();
        using LiveProcess process = target.Attach();
        using ISnapshot snapshot = process.BeginSnapshot();

        IClrList list = snapshot.Object(target.NullItemsHolderAddress)!
            .Field(nameof(FixtureHolder.Items))!.AsList()!;

        Assert.Equal(0, list.Count);
        Assert.True(snapshot.Validate().IsUsable);
    }

    [Fact]
    public void ARuntimeThatOmitsAnEntryNothingReadsStillAttaches()
    {
        // EEClass.CorTypeAttr enriches ClrTypeInfo and is read by nothing else, so §5.5's
        // "coverage is a goal, not a guarantee" has to hold for it: refusing the whole target
        // over a field the walk never needs is the over-strict assumption, not caution.
        using SyntheticClrTarget target = SyntheticClrTarget.Build(new SyntheticTargetOptions
        {
            OmitDescriptorEntries = ["EEClass.CorTypeAttr"],
        });

        using LiveProcess process = target.Attach();
        Assert.False(process.Layouts.HasEEClassTypeAttributes);

        using ISnapshot snapshot = process.BeginSnapshot();
        IClrObject derived = snapshot.Object(target.DerivedAddress)!;

        Assert.Equal(typeof(FixtureDerived).FullName, derived.Type.Name);
        Assert.Equal(SyntheticClrTarget.ExpectedName, derived.Field(nameof(FixtureDerived.Name))!.AsString());

        // What is lost is exactly the one thing that entry fed, and it reads as unknown rather
        // than as a default.
        Assert.True(process.TypeSystem.TryGetType(process.Memory, target.DerivedMethodTable, out ClrTypeInfo? type));
        Assert.Null(type!.TypeAttributes);
    }

    [Fact]
    public void AnOmittedEntryTheWalkDependsOnFailsAttachAndNamesIt()
    {
        using SyntheticClrTarget target = SyntheticClrTarget.Build(new SyntheticTargetOptions
        {
            OmitDescriptorEntries = ["MethodTable.ParentMethodTable"],
        });

        ClrAttachException failure = Assert.Throws<ClrAttachException>(() => target.Attach());
        Assert.Contains("MethodTable.ParentMethodTable", failure.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("MethodTable.BaseSize")]
    [InlineData("MethodTable.ParentMethodTable")]
    [InlineData("EEClass.InternalCorElementType")]
    public void ATypeWhoseDefiningReadsFailIsNeitherBuiltNorRemembered(string field)
    {
        // A ClrTypeInfo is process-tier and never invalidated (§8.8), so accepting a failed read
        // here would cache a type with no base chain — and baseSize 0 quietly disables
        // RuntimeFieldLayoutSource's offset bound, which is §12.4e's shape exactly.
        using SyntheticClrTarget target = SyntheticClrTarget.Build();
        using LiveProcess process = target.Attach();

        ulong methodTable = target.DerivedMethodTable;
        Assert.True(process.TypeSystem.TryResolveEEClass(target.Memory, methodTable, out ulong eeClass, out _));

        // Offsets from the FIXTURE, not from process.Layouts. Asking production where it reads
        // and then unmapping exactly that address damages whatever offset production is using,
        // including a wrong one — the test then passes for any layout at all and proves only
        // that the reader is self-consistent (§13.11 species 3, and the doctrine
        // SyntheticClrTarget states at the top of its own constant block). These are the
        // addresses the fixture WROTE, so a layout that drifts fails here.
        (ulong address, int length) = field switch
        {
            "MethodTable.BaseSize" => (methodTable + SyntheticClrTarget.WrittenAt.MethodTableBaseSize, 4),
            "MethodTable.ParentMethodTable" => (methodTable + SyntheticClrTarget.WrittenAt.MethodTableParent, 8),
            "EEClass.InternalCorElementType" => (eeClass + SyntheticClrTarget.WrittenAt.EEClassInternalCorElementType, 1),
            _ => throw new InvalidOperationException(field),
        };

        // And the two agree today, so the change above is a change of SOURCE, not of address.
        Assert.Equal(SyntheticClrTarget.WrittenAt.MethodTableBaseSize, process.Layouts.MethodTableBaseSizeOffset);
        Assert.Equal(SyntheticClrTarget.WrittenAt.MethodTableParent, process.Layouts.MethodTableParentOffset);
        Assert.Equal(SyntheticClrTarget.WrittenAt.EEClassInternalCorElementType, process.Layouts.EEClassElementTypeOffset);

        var torn = new MutableMemoryOverlay(target.Memory);
        torn.Unreadable(address, length);

        Assert.False(process.TypeSystem.TryGetType(torn, methodTable, out ClrTypeInfo? type), field);
        Assert.Null(type);

        // Transient, so it must not be remembered: the same method table resolves once the read
        // works again, rather than staying invisible for the lifetime of the attach.
        Assert.True(process.TypeSystem.TryGetType(target.Memory, methodTable, out type));
        Assert.Equal(typeof(FixtureDerived).FullName, type!.Name);
        Assert.NotEqual(0u, type.BaseSize);
        Assert.NotEqual(0UL, type.ParentMethodTable);
    }

    /// <summary>
    /// An array header whose element count no allocation could hold is refused, not walked.
    /// </summary>
    /// <remarks>
    /// <c>m_NumComponents</c> is a decoded number and so is the field offset that reaches it, so
    /// a wrong FieldDesc width or a torn header produces an ENORMOUS count rather than an
    /// obviously invalid one. The only bound was <c>&gt; int.MaxValue</c>, which a billion passes
    /// comfortably — and a consumer that then walks the array spins instead of failing. §12.5's
    /// rule is that a bad decode must fail fast, and the evidence that it is bad is available
    /// for one read: the slot that many elements in is not mapped.
    /// </remarks>
    [Fact]
    public void AnArrayCountNoAllocationCouldHoldIsRefusedRatherThanWalked()
    {
        using SyntheticClrTarget target = SyntheticClrTarget.Build();

        ulong numbersAddress;
        using (LiveProcess clean = target.Attach())
        using (ISnapshot before = clean.BeginSnapshot())
        {
            var numbers = (ClrArray)before.Object(target.HolderAddress)!
                .Field(nameof(FixtureHolder.Numbers))!.AsArray()!;

            numbersAddress = numbers.Address;
            Assert.Equal(3, numbers.Count);
        }

        // The same array, with only its component count changed — every other byte, and every
        // offset used to reach it, is exactly as the passing case above.
        var torn = new MutableMemoryOverlay(target.Memory);
        torn.WriteI32(numbersAddress + 8, 1_000_000_000);

        using LiveProcess process = LiveProcess.Create(
            0, torn, ownsMemory: false, target.Modules, target.CoreClr);
        using ISnapshot snapshot = process.BeginSnapshot();

        var wild = (ClrArray)snapshot.Object(target.HolderAddress)!
            .Field(nameof(FixtureHolder.Numbers))!.AsArray()!;

        // The claim survives for diagnostics; nothing acts on it.
        Assert.Equal(1_000_000_000, wild.ReportedCount);
        Assert.Equal(0, wild.Count);
        Assert.True(wild[0].IsNull);

        SnapshotHealth health = snapshot.Validate();
        Assert.True(health.StructuralAnomalies > 0);
        Assert.Contains("bad decode", health.Detail, StringComparison.Ordinal);
    }

    /// <summary>
    /// §12.5's lesson, restated: the worst outcome is a single confident wrong answer. Each row
    /// damages the anchor differently, and each must land on "no encoding" FOR ITS OWN REASON.
    /// </summary>
    /// <remarks>
    /// The reason is asserted, not just the refusal. Three rows that all check
    /// <c>IsCalibrated == false</c> are three copies of one test, and the "too few samples" row
    /// was not even reaching the clause it names: <c>ExceptionFieldLimit</c> controls how many
    /// FieldDescs the FIXTURE lays down, while the sample count comes from how many offsets the
    /// DESCRIPTOR publishes — so the blob still published all eight and the refusal came from a
    /// later clause with a different message (§13.11). Starving the published blob with
    /// <c>OmitDescriptorEntries</c> is what actually reaches it.
    /// </remarks>
    [Theory]
    [InlineData("too few samples", 6, false, false, "needed to pin a bitfield position")]
    [InlineData("one offset disagrees", 0, true, false, "reproduces the published")]
    [InlineData("the anchor is not a method table", 0, false, true, "could not reach CoreLib's Module.Base")]
    public void ADegenerateCalibrationAnchorEndsInRefusalNotAConfidentGuess(
        string because, int omitCount, bool corruptOne, bool garbageAnchor, string expectedReason)
    {
        // The eight Exception fields §5.2 publishes, least-load-bearing first; omitting six of
        // them leaves two, below the three a bitfield position needs.
        string[] published =
        [
            "Exception._watsonBuckets", "Exception._stackTraceString", "Exception._remoteStackTraceString",
            "Exception._xcode", "Exception._HResult", "Exception._stackTrace",
            "Exception._innerException", "Exception._message",
        ];

        using SyntheticClrTarget target = SyntheticClrTarget.Build(new SyntheticTargetOptions
        {
            OmitDescriptorEntries = published[..omitCount],
            CorruptOneExceptionOffset = corruptOne,
            GarbageExceptionMethodTable = garbageAnchor,
        });

        using LiveProcess process = target.Attach();
        FieldDescCalibration calibration = process.FieldDescCalibration;

        Assert.False(calibration.IsCalibrated, $"{because}: {calibration.Detail}");
        Assert.Null(calibration.Encoding);
        Assert.NotEqual(1, calibration.CandidateCount);

        // Each row reaches the clause it is named after, rather than some other refusal that
        // happens to produce the same verdict.
        Assert.Contains(expectedReason, calibration.Detail, StringComparison.Ordinal);

        // And nothing downstream invents an offset to compensate.
        using ISnapshot snapshot = process.BeginSnapshot();
        IClrObject derived = snapshot.Object(target.DerivedAddress)!;

        Assert.Null(derived.Field(nameof(FixtureDerived.Name)));
        Assert.Null(derived.Field(nameof(FixtureBase.Hp)));

        // The parts that never depended on FieldDesc keep working, so the degradation is
        // confined rather than total.
        Assert.Equal(typeof(FixtureDerived).FullName, derived.Type.Name);
        Assert.Equal(typeof(FixtureBase).FullName, derived.Type.BaseType!.Name);
    }
}
