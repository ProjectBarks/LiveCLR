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

        (ulong address, int length) = field switch
        {
            "MethodTable.BaseSize" => (methodTable + (ulong)process.Layouts.MethodTableBaseSizeOffset, 4),
            "MethodTable.ParentMethodTable" => (methodTable + (ulong)process.Layouts.MethodTableParentOffset, 8),
            "EEClass.InternalCorElementType" => (eeClass + (ulong)process.Layouts.EEClassElementTypeOffset, 1),
            _ => throw new InvalidOperationException(field),
        };

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

    [Theory]
    [InlineData("too few samples", 2, false, false)]
    [InlineData("one offset disagrees", int.MaxValue, true, false)]
    [InlineData("the anchor is not a method table", int.MaxValue, false, true)]
    public void ADegenerateCalibrationAnchorEndsInRefusalNotAConfidentGuess(
        string because, int fieldLimit, bool corruptOne, bool garbageAnchor)
    {
        // §12.5's lesson, restated: the worst outcome is a single confident wrong answer. Each
        // of these damages the anchor differently, and all three must land on "no encoding".
        using SyntheticClrTarget target = SyntheticClrTarget.Build(new SyntheticTargetOptions
        {
            ExceptionFieldLimit = fieldLimit,
            CorruptOneExceptionOffset = corruptOne,
            GarbageExceptionMethodTable = garbageAnchor,
        });

        using LiveProcess process = target.Attach();
        FieldDescCalibration calibration = process.FieldDescCalibration;

        Assert.False(calibration.IsCalibrated, $"{because}: {calibration.Detail}");
        Assert.Null(calibration.Encoding);
        Assert.NotEqual(1, calibration.CandidateCount);

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
