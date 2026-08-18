namespace LiveClr.Tests.Runtime;

using LiveClr.Memory;
using LiveClr.Runtime;

/// <summary>
/// The per-field half of §14: what resolves, what is refused, and — the part that matters — that
/// each refusal is refusing something that would otherwise have looked like an answer.
/// </summary>
/// <remarks>
/// Every refusal test here also asserts that the address it declined to produce is BACKED BY
/// PLAUSIBLE DATA in the fixture. A thread static's slot holds a real object; a misattributed
/// descriptor points at a real offset. §14.0's finding is not "these cases fail", it is "these
/// cases succeed, wrongly" — so a test that only asserted the refusal would still pass against a
/// reader that refused for the wrong reason, or against a fixture where there was nothing to get
/// wrong.
/// </remarks>
public sealed class StaticFieldTests : IDisposable
{
    private readonly SyntheticClrTarget _target = SyntheticClrTarget.Build(new SyntheticTargetOptions { WithStatics = true });
    private readonly LiveProcess _process;
    private readonly ISnapshot _snapshot;

    public StaticFieldTests()
    {
        _process = _target.Attach();

        // §5.5: the descriptor does not publish the assembly list, so the application's own module
        // has to be seeded before its types resolve by name.
        _process.RegisterManagedModule(_target.AppModulePointer);
        _snapshot = _process.BeginSnapshot();
    }

    public void Dispose()
    {
        _snapshot.Dispose();
        _process.Dispose();
        _target.Dispose();
    }

    [Fact]
    public void ResolvesAReferenceStaticToTheSlotTheFixtureWrote()
    {
        (string typeName, string fieldName, SyntheticClrTarget.StaticsFixtureType fixture) = ReferenceStatic();
        ClrType type = TypeOf(typeName);

        ClrStaticField located = type.ResolveStatic(fieldName);

        Assert.Equal(ClrStaticStatus.Resolved, located.Status);
        Assert.Equal(ClrElementType.Class, located.ElementType);
        Assert.True(located.IsGcStatic);
        Assert.True(located.IsClassInitialized);

        // Against the address the FIXTURE wrote, not against whatever production recomputes.
        Assert.Equal(fixture.GcStatics + (ulong)fixture.Offsets[fieldName], located.Address);

        // And end to end: the slot really does hold the object the fixture put there.
        Assert.Equal("StaticsCorpusTarget", type.Static(fieldName)!.AsString());
    }

    [Fact]
    public void ResolvesAPrimitiveStaticThroughTheNonGcBase()
    {
        (string typeName, string fieldName, SyntheticClrTarget.StaticsFixtureType fixture) = PrimitiveStatic();
        ClrType type = TypeOf(typeName);

        ClrStaticField located = type.ResolveStatic(fieldName);

        Assert.Equal(ClrStaticStatus.Resolved, located.Status);
        Assert.False(located.IsGcStatic);
        Assert.Equal(fixture.NonGcStatics + (ulong)fixture.Offsets[fieldName], located.Address);
        Assert.Equal(SyntheticClrTarget.ExpectedPrimitiveStatic, type.Static(fieldName)!.Read<long>());

        // The control, per field: the same offset applied to the GC base is not this value. If it
        // were, the two bases would be interchangeable and the test above would prove nothing.
        Assert.NotEqual(fixture.GcStatics, fixture.NonGcStatics);
    }

    [Fact]
    public void RefusesAThreadStaticEvenThoughItsSlotHoldsARealObject()
    {
        (string typeName, string fieldName) = Split(_target.ThreadStaticField!);
        ClrType type = TypeOf(typeName);
        SyntheticClrTarget.StaticsFixtureType fixture = _target.StaticsTypes[typeName];

        // The trap, made explicit: the gate passes, the anchor closes, and the address the naive
        // chain would produce resolves to a perfectly good object. §14.0, correction 2.
        ulong wouldBe = fixture.GcStatics + (ulong)fixture.Offsets[fieldName];
        Assert.True(_process.Memory.TryReadPointer(wouldBe, out ulong decoy));
        Assert.Equal(_target.ThreadStaticDecoyObject, decoy);
        Assert.NotNull(_snapshot.Object(decoy));

        Assert.Equal(ClrStaticStatus.ThreadStatic, type.ResolveStatic(fieldName).Status);
        Assert.Null(type.Static(fieldName));
    }

    [Fact]
    public void RefusesAnOpenGenericDefinition()
    {
        // §14.0, correction 3: statics belong to each instantiation, so the definition's raw
        // bases read 1 and there is nothing here to hand out.
        ClrType type = TypeOf(_target.GenericStaticsType!);
        string fieldName = _target.StaticsTypes[_target.GenericStaticsType!].Offsets.Keys.First();

        ClrStaticField located = type.ResolveStatic(fieldName);

        Assert.Equal(ClrStaticStatus.OpenGenericDefinition, located.Status);
        Assert.Equal(0UL, located.Address);
        Assert.Null(type.Static(fieldName));
    }

    [Fact]
    public void RefusesAnRvaStaticOnTheMetadataAloneBecauseThereIsNoDescriptor()
    {
        Assert.NotNull(_target.RvaStaticsType);
        ClrType type = TypeOf(_target.RvaStaticsType!);

        ClrStaticField located = type.ResolveStatic(_target.RvaStaticField!);

        Assert.Equal(ClrStaticStatus.RvaStatic, located.Status);
        Assert.Equal(0UL, located.Address);
    }

    [Fact]
    public void RefusesADescriptorThatBelongsToAnotherType()
    {
        using SyntheticClrTarget target = SyntheticClrTarget.Build(
            new SyntheticTargetOptions { WithStatics = true, MisattributeOneStaticFieldDesc = true });
        using LiveProcess process = target.Attach();
        using ISnapshot snapshot = process.BeginSnapshot();

        Assert.NotNull(target.MisattributedStaticField);
        var type = (ClrType)snapshot.Type(target.MisattributedStaticType!)!;

        Assert.Equal(ClrStaticStatus.WrongDeclaringType, type.ResolveStatic(target.MisattributedStaticField!).Status);
        Assert.Null(type.Static(target.MisattributedStaticField!));
    }

    [Fact]
    public void ClassNotInitialisedIsReportedRatherThanCollapsedIntoNull()
    {
        // §14.0: Boolean.TrueString reads null because Boolean's raw GC base has bit 0 set — the
        // class was never initialised in that process. The address is real and readable; only the
        // contents are still at their default. Reporting that as plain "null" throws away the
        // difference between "nothing was stored" and "null was stored".
        ClrType uninitialised = TypeOf(_target.UninitializedStaticsType!);
        string fieldName = _target.StaticsTypes[_target.UninitializedStaticsType!]
            .Offsets.Keys.First(k => uninitialised.ResolveStatic(k).IsGcStatic);

        ClrStaticField located = uninitialised.ResolveStatic(fieldName);

        Assert.Equal(ClrStaticStatus.Resolved, located.Status);
        Assert.False(located.IsClassInitialized);
        Assert.NotEqual(0UL, located.Address);

        // And the distinction is a distinction: another type in the same fixture reports the
        // opposite, so this is not a flag that is always false.
        (string initialisedType, string initialisedField, _) = ReferenceStatic();
        Assert.True(TypeOf(initialisedType).ResolveStatic(initialisedField).IsClassInitialized);
    }

    [Fact]
    public void BoxedValueTypeStaticsReadAsValuesRatherThanAsBoxPointers()
    {
        Assert.NotNull(_target.BoxedStaticField);
        ClrType type = TypeOf(_target.BoxedStaticType!);
        SyntheticClrTarget.StaticsFixtureType fixture = _target.StaticsTypes[_target.BoxedStaticType!];

        ClrStaticField located = type.ResolveStatic(_target.BoxedStaticField!);
        Assert.Equal(ClrStaticStatus.Resolved, located.Status);
        Assert.True(located.IsBoxed);

        // The slot itself holds a POINTER. Handing it back unfollowed is the failure this guards:
        // §14.0's DateTime.MinValue reported ticks of 1798517794032, which was a heap address.
        Assert.True(_process.Memory.TryReadPointer(located.Address, out ulong box));
        Assert.NotEqual((ulong)SyntheticClrTarget.ExpectedBoxedStatic, box);

        Assert.Equal(SyntheticClrTarget.ExpectedBoxedStatic, type.Static(_target.BoxedStaticField!)!.Read<long>());
        Assert.Equal(fixture.GcStatics + (ulong)fixture.Offsets[_target.BoxedStaticField!], located.Address);
    }

    [Fact]
    public void TheRuntimeAnswerBeatsACallerSuppliedRoot()
    {
        // The §7b.2 order, applied to statics: a runtime that can answer is believed over a
        // hand-maintained table, so a stale root is corrected rather than trusted.
        (string typeName, string fieldName, SyntheticClrTarget.StaticsFixtureType fixture) = ReferenceStatic();

        var stale = new ExplicitStaticRootSource().Add(typeName, fieldName, 0xDEAD_BEE0);
        using LiveProcess process = _target.Attach(new LiveProcessOptions { StaticRoots = stale });
        using ISnapshot snapshot = process.BeginSnapshot();

        var type = (ClrType)snapshot.Type(typeName)!;

        Assert.Equal(fixture.GcStatics + (ulong)fixture.Offsets[fieldName], type.ResolveStatic(fieldName).Address);
        Assert.Equal("StaticsCorpusTarget", type.Static(fieldName)!.AsString());
    }

    [Fact]
    public void FallsBackToACallerSuppliedRootWhenTheRuntimeRefuses()
    {
        // The app module's types have no statics chain, so the runtime route correctly refuses and
        // §5.5's hand-off still works. The two are complements, not alternatives.
        using LiveProcess process = _target.Attach(new LiveProcessOptions { StaticRoots = _target.StaticRoots() });
        process.RegisterManagedModule(_target.AppModulePointer);
        using ISnapshot snapshot = process.BeginSnapshot();

        var holder = (ClrType)snapshot.Type(typeof(FixtureHolder).FullName!)!;

        Assert.Equal(ClrStaticStatus.NoStaticsStorage, holder.ResolveStatic(nameof(FixtureHolder.Instance)).Status);
        Assert.Equal(_target.HolderAddress, holder.Static(nameof(FixtureHolder.Instance))!.AsObject()!.Address);
    }

    [Fact]
    public void RefusesATypeWhoseBackPointerAnchorDoesNotClose()
    {
        // The anchor is the whole reason MT+0x20 does not have to be trusted (§14.2). Here the
        // gate still says "this type has statics" and the two pointers below the auxiliary data
        // still look exactly like bases — the ONLY thing wrong is that the back-pointer names a
        // different method table. Everything downstream would have produced an address.
        using SyntheticClrTarget target = SyntheticClrTarget.Build(
            new SyntheticTargetOptions { WithStatics = true, BreakOneStaticsAnchor = true });
        using LiveProcess process = target.Attach();
        process.RegisterManagedModule(target.AppModulePointer);
        using ISnapshot snapshot = process.BeginSnapshot();

        Assert.True(process.StaticsCalibration.IsCalibrated, process.StaticsCalibration.Detail);
        Assert.NotNull(target.BrokenAnchorType);

        var type = (ClrType)snapshot.Type(target.BrokenAnchorType!)!;

        // The gate still says this type has statics, so nothing before the anchor declines it.
        Assert.True(process.StaticsCalibration.Encoding!.Value.HasDynamicStatics(process.Memory, type.MethodTable));

        Assert.Equal(ClrStaticStatus.AnchorFailed, type.ResolveStatic(target.BrokenAnchorField!).Status);
        Assert.Null(type.Static(target.BrokenAnchorField!));

        // And the rest of the process is unaffected: a targeted refusal, not a collapse.
        (string typeName, string fieldName, _) = FindIn(snapshot, target, f => f.IsResolved);
        Assert.NotEqual(target.BrokenAnchorType, typeName);
        Assert.Equal("StaticsCorpusTarget", ((ClrType)snapshot.Type(typeName)!).Static(fieldName)!.AsString());
    }

    [Fact]
    public void AnInstanceFieldIsNotAStaticAndAnUnknownNameIsNotDeclared()
    {
        ClrType derived = (ClrType)_snapshot.Type(typeof(FixtureDerived).FullName!)!;

        Assert.Equal(ClrStaticStatus.NotDeclared, derived.ResolveStatic("NoSuchField").Status);
        Assert.Null(derived.Static(nameof(FixtureDerived.Name)));
    }

    [Fact]
    public void ARuntimeWithoutAStaticsChainRefusesEveryStatic()
    {
        using SyntheticClrTarget plain = SyntheticClrTarget.Build();
        using LiveProcess process = plain.Attach();
        using ISnapshot snapshot = process.BeginSnapshot();

        var type = (ClrType)snapshot.Type("System.String")!;

        Assert.Equal(ClrStaticStatus.NotCalibrated, type.ResolveStatic("Empty").Status);
        Assert.Null(type.Static("Empty"));
    }

    private ClrType TypeOf(string fullName) =>
        (ClrType?)_snapshot.Type(fullName) ?? throw new InvalidOperationException($"the fixture defines no '{fullName}'.");

    private static (string Type, string Field) Split(string qualified)
    {
        int dot = qualified.LastIndexOf('.');
        return (qualified[..dot], qualified[(dot + 1)..]);
    }

    /// <summary>An initialised carrier's reference static, and what the fixture wrote for it.</summary>
    private (string Type, string Field, SyntheticClrTarget.StaticsFixtureType Fixture) ReferenceStatic() =>
        Find(f => f.Status == ClrStaticStatus.Resolved && f.ElementType == ClrElementType.Class && f.IsClassInitialized);

    private (string Type, string Field, SyntheticClrTarget.StaticsFixtureType Fixture) PrimitiveStatic() =>
        Find(f => f.Status == ClrStaticStatus.Resolved && !f.IsGcStatic);

    private (string Type, string Field, SyntheticClrTarget.StaticsFixtureType Fixture) Find(
        Func<ClrStaticField, bool> predicate) => FindIn(_snapshot, _target, predicate);

    private static (string Type, string Field, SyntheticClrTarget.StaticsFixtureType Fixture) FindIn(
        ISnapshot snapshot, SyntheticClrTarget target, Func<ClrStaticField, bool> predicate)
    {
        foreach ((string typeName, SyntheticClrTarget.StaticsFixtureType fixture) in target.StaticsTypes)
        {
            if (snapshot.Type(typeName) is not ClrType type) continue;

            foreach (string fieldName in fixture.Offsets.Keys)
            {
                if (predicate(type.ResolveStatic(fieldName))) return (typeName, fieldName, fixture);
            }
        }

        throw new InvalidOperationException("the fixture produced no static matching the requested shape.");
    }
}
