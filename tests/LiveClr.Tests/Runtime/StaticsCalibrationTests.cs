namespace LiveClr.Tests.Runtime;

using LiveClr.Memory;
using LiveClr.Runtime;

/// <summary>
/// Proves the statics chain is DERIVED from the running target rather than recognised from
/// §14's numbers.
/// </summary>
/// <remarks>
/// <para>
/// The evidence standard is the one <c>FieldDescCalibrationTests</c> sets: a derivation that only
/// ever succeeds against one layout is indistinguishable from a hardcode. So every derived
/// quantity — the auxiliary slot, the <c>MTFlags2</c> gate bit, the thread-static marker bit, and
/// which <c>DynamicStaticsInfo</c> member is the GC base — is exercised against a target that
/// uses CoreCLR 9's value AND against one that does not.
/// </para>
/// <para>
/// <b>The slot-40 alias is present in every one of these fixtures.</b> §14.0's correction 1
/// records that 26 real types make <c>EEClassOrCanonMT</c> satisfy the back-pointer anchor by
/// coincidence, and that a per-type sweep therefore reads four types' statics out of an
/// <c>EEClass</c>. The fixture aliases it far more aggressively than reality does, so a derivation
/// that resolved the ambiguity by preference rather than by unanimity would be caught here.
/// </para>
/// </remarks>
public sealed class StaticsCalibrationTests
{
    private static SyntheticTargetOptions Statics(Action<SyntheticTargetOptions>? _ = null) =>
        new() { WithStatics = true };

    [Theory]
    [InlineData(32, 1)]
    [InlineData(64, 5)]
    public void DerivesTheAuxiliarySlotAndGateBitTogether(int slot, int bit)
    {
        using SyntheticClrTarget target = SyntheticClrTarget.Build(
            new SyntheticTargetOptions { WithStatics = true, AuxiliarySlot = slot, StaticsFlagBit = bit });
        using LiveProcess process = target.Attach();

        StaticsCalibration calibration = process.StaticsCalibration;

        Assert.True(calibration.IsCalibrated, calibration.Detail);
        Assert.Equal(1, calibration.SlotBitCandidates);

        StaticsEncoding encoding = calibration.Encoding!.Value;
        Assert.Equal(slot, encoding.AuxiliaryDataSlot);
        Assert.Equal(bit, encoding.StaticsFlagBit);

        // The floors §14.0 names: unanimity over at least 100 types with statics, and at least
        // that many without, so neither side can agree vacuously.
        Assert.True(calibration.GateSetTypes >= 100, calibration.Detail);
        Assert.True(calibration.CorpusTypes - calibration.GateSetTypes >= 100, calibration.Detail);
    }

    [Fact]
    public void TheAliasedEEClassSlotReallyDoesSatisfyTheAnchorAndIsStillNotChosen()
    {
        using SyntheticClrTarget target = SyntheticClrTarget.Build(Statics());
        using LiveProcess process = target.Attach();

        StaticsEncoding encoding = process.StaticsCalibration.Encoding!.Value;
        Assert.Equal(32, encoding.AuxiliaryDataSlot);

        // Confirm the decoy is real rather than assumed: on a statics-bearing type, slot 40's
        // target ALSO passes ptr(ptr(mt+40) - 8) == mt. A per-type sweep has no way to prefer 32.
        SyntheticClrTarget.StaticsFixtureType carrier = AnyCarrier(target);
        int eeClassSlot = process.Layouts.MethodTableEEClassOrCanonMtOffset;

        Assert.True(process.Memory.TryReadPointer(carrier.MethodTable + (ulong)eeClassSlot, out ulong eeClass));
        Assert.True(process.Memory.TryReadPointer(eeClass - 8, out ulong alias));
        Assert.Equal(carrier.MethodTable, alias);
        Assert.NotEqual(eeClassSlot, encoding.AuxiliaryDataSlot);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void DerivesWhichDynamicStaticsInfoMemberIsTheGcBase(bool gcSecond)
    {
        using SyntheticClrTarget target = SyntheticClrTarget.Build(
            new SyntheticTargetOptions { WithStatics = true, GcStaticsSecond = gcSecond });
        using LiveProcess process = target.Attach();

        StaticsCalibration calibration = process.StaticsCalibration;
        Assert.True(calibration.IsCalibrated, calibration.Detail);

        StaticsEncoding encoding = calibration.Encoding!.Value;
        Assert.Equal(!gcSecond, encoding.GcStaticsFirst);
        Assert.Equal(gcSecond ? -16 : -24, encoding.GcStaticsDisplacement);
        Assert.Equal(gcSecond ? -24 : -16, encoding.NonGcStaticsDisplacement);

        // The control §14.0 measured — 0 valid objects of 529 through the wrong base — is not a
        // separate experiment here. It is the evidence the ordering was chosen on, and the
        // calibration carries the number out.
        Assert.Equal(0, calibration.WrongBaseValidObjects);
        Assert.True(calibration.GcProbeFields >= 8, calibration.Detail);
    }

    [Theory]
    [InlineData(25)]
    [InlineData(17)]
    public void DerivesTheThreadStaticMarkerBitAgainstTheMetadataAttribute(int bit)
    {
        using SyntheticClrTarget target = SyntheticClrTarget.Build(
            new SyntheticTargetOptions { WithStatics = true, ThreadStaticBitIndex = bit });
        using LiveProcess process = target.Attach();

        StaticsCalibration calibration = process.StaticsCalibration;
        Assert.True(calibration.IsCalibrated, calibration.Detail);

        FieldDescFlagBit marker = calibration.Encoding!.Value.ThreadStaticBit;
        Assert.True(marker.IsDerived, calibration.Detail);
        Assert.Equal(bit, marker.BitIndex);
        Assert.Equal(8, marker.ByteOffset);
        Assert.True(calibration.ThreadStaticSamples > 0, calibration.Detail);
    }

    [Fact]
    public void RefusesWhenTheBackPointerAnchorCannotClose()
    {
        using SyntheticClrTarget target = SyntheticClrTarget.Build(
            new SyntheticTargetOptions { WithStatics = true, BreakStaticsAnchor = true });
        using LiveProcess process = target.Attach();

        Assert.False(process.StaticsCalibration.IsCalibrated, process.StaticsCalibration.Detail);
        Assert.Contains("no (auxiliary slot", process.StaticsCalibration.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public void RefusesRatherThanPickingWhenTwoSlotsAreGenuinelyIndistinguishable()
    {
        // Distinct from the slot-40 alias, which the corpus CAN separate because the alias does
        // not track the gate. Here two slots hold the same auxiliary pointer on exactly the same
        // types, so nothing in the target prefers one — and preferring one anyway is the
        // plausible-but-wrong outcome the whole derivation exists to avoid.
        using SyntheticClrTarget target = SyntheticClrTarget.Build(
            new SyntheticTargetOptions { WithStatics = true, DuplicateAuxiliarySlot = 72 });
        using LiveProcess process = target.Attach();

        StaticsCalibration calibration = process.StaticsCalibration;

        Assert.False(calibration.IsCalibrated, calibration.Detail);
        Assert.Equal(2, calibration.SlotBitCandidates);
        Assert.Contains("ambiguous", calibration.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public void RefusesOnATargetWithNoStaticsChainAtAll()
    {
        using SyntheticClrTarget target = SyntheticClrTarget.Build();
        using LiveProcess process = target.Attach();

        Assert.False(process.StaticsCalibration.IsCalibrated, process.StaticsCalibration.Detail);
        Assert.False(process.TypeSystem.StaticFields.IsUsable);
    }

    [Fact]
    public void RefusesWhenTheFieldDescEncodingDidNotConverge()
    {
        // Statics share the offset bitfield with instance fields, so there is nothing to fall
        // back on — and refusing loudly beats decoding an offset out of an unknown layout.
        using SyntheticClrTarget target = SyntheticClrTarget.Build(
            new SyntheticTargetOptions { WithStatics = true, CorruptOneExceptionOffset = true });
        using LiveProcess process = target.Attach();

        Assert.False(process.FieldDescCalibration.IsCalibrated);
        Assert.False(process.StaticsCalibration.IsCalibrated);
        Assert.Contains("FieldDesc encoding", process.StaticsCalibration.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public void RefusesWhenNoRoomAboveTheOffsetFieldHoldsTheElementType()
    {
        // The Alternate encoding packs the offset flush against the top of its word, so m_type is
        // not adjacent to it. Without m_type there is no way to tell a GC static from a non-GC
        // one — and deciding from the field's metadata signature is measurably wrong, because the
        // runtime stores an enum static as its underlying primitive in the NON-GC blob while its
        // signature says VALUETYPE (§14.0).
        using SyntheticClrTarget target = SyntheticClrTarget.Build(
            new SyntheticTargetOptions { WithStatics = true, Style = FieldDescStyle.Alternate });
        using LiveProcess process = target.Attach();

        Assert.True(process.FieldDescCalibration.IsCalibrated, process.FieldDescCalibration.Detail);
        Assert.False(process.StaticsCalibration.IsCalibrated);
        Assert.Contains("m_type", process.StaticsCalibration.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public void TheAnchorSeparatesGateSetFromGateClearTypesCompletely()
    {
        // §14.0's headline measurement, reproduced against the fixture: 3033/3033 gate-set types
        // anchored, 0/9250 gate-clear. A single gate-clear type that anchored would mean the gate
        // and the slot are not describing the same thing.
        using SyntheticClrTarget target = SyntheticClrTarget.Build(Statics());
        using LiveProcess process = target.Attach();

        StaticsEncoding encoding = process.StaticsCalibration.Encoding!.Value;
        IMemoryReader memory = process.Memory;
        ClrModuleInfo coreLib = process.TypeSystem.Modules.Single(m => m.ModulePointer == target.CoreLibModulePointer);

        int gateSet = 0, gateSetAnchored = 0, gateClear = 0, gateClearAnchored = 0;

        for (int rid = 1; rid <= coreLib.Metadata.Reader.TypeDefinitions.Count; rid++)
        {
            if (!coreLib.TryGetMethodTable(memory, rid, out ulong methodTable) || methodTable == 0) continue;

            bool gate = encoding.HasDynamicStatics(memory, methodTable);
            bool anchored = encoding.TryReadBases(memory, methodTable, out _);

            if (gate) { gateSet++; if (anchored) gateSetAnchored++; }
            else { gateClear++; if (anchored) gateClearAnchored++; }
        }

        Assert.True(gateSet >= 100, $"only {gateSet} gate-set types");
        Assert.True(gateClear >= 100, $"only {gateClear} gate-clear types");
        Assert.Equal(gateSet, gateSetAnchored);
        Assert.Equal(0, gateClearAnchored);
    }

    [Fact]
    public void HostileMethodTablesAreRefusedRatherThanAnswered()
    {
        using SyntheticClrTarget target = SyntheticClrTarget.Build(Statics());
        using LiveProcess process = target.Attach();

        StaticsEncoding encoding = process.StaticsCalibration.Encoding!.Value;
        IMemoryReader memory = process.Memory;
        ulong methodTable = AnyCarrier(target).MethodTable;

        Assert.True(memory.TryReadPointer(methodTable + (ulong)encoding.AuxiliaryDataSlot, out ulong auxiliary));
        Assert.True(memory.TryReadPointer(methodTable + (ulong)process.Layouts.MethodTableModuleOffset, out ulong module));

        // The real one works, so the refusals below are not a blanket "no".
        Assert.True(encoding.TryReadBases(memory, methodTable, out _));

        (string What, ulong Address)[] hostile =
        [
            ("zero", 0),
            ("unmapped high", 0x0000_7FF0_DEAD_0000),
            ("unmapped low", 0x0000_0000_DEAD_BEE0),
            ("PE header", process.CoreClr.BaseAddress),
            ("inside the PE image", process.CoreClr.BaseAddress + 0x1000),
            ("mt | 1", methodTable | 1),
            ("mt + 3", methodTable + 3),
            ("mt + 8", methodTable + 8),
            ("mt >> 8", methodTable >> 8),
            ("mt low 32 only", methodTable & 0xFFFF_FFFF),
            ("the auxiliary pointer itself", auxiliary),
            ("the DynamicStaticsInfo", auxiliary - 24),
            ("the Module", module),
        ];

        foreach ((string what, ulong address) in hostile)
        {
            Assert.False(encoding.TryReadBases(memory, address, out StaticsBases bases), what);
            Assert.Equal(default, bases);
        }
    }

    private static SyntheticClrTarget.StaticsFixtureType AnyCarrier(SyntheticClrTarget target) =>
        target.StaticsTypes[target.StaticsTypes.Keys.First(k => target.StaticsTypes[k].GcStatics != 0)];
}
