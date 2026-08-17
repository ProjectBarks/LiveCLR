namespace LiveClr.Tests.Runtime;

// These types exist so that LiveClr.Tests.dll — a real, Roslyn-produced assembly with a real
// ECMA-335 metadata blob — can stand in for the game module. The synthetic heap in
// SyntheticClrTarget assigns them method tables, field descriptors and instances; every NAME
// and every metadata TOKEN the reader resolves is genuine, and only the runtime-side structures
// are fabricated. That is the split that makes the fixture worth trusting: the parts under test
// (token → FieldDesc → offset, MethodTable → Module → metadata → name) run against real
// metadata rather than against a mock of it.
//
// Fields, not properties: a property's backing field is name-mangled, and the point here is to
// read fields by the names a caller would actually write.
#pragma warning disable CA1051, CS0649, IDE0044

/// <summary>An inline value type, so a struct-typed field exists to read.</summary>
/// <remarks>
/// Live validation found this blind spot: the independent reader used to cross-check field
/// values only surfaces scalars, so no struct-typed field was ever in the comparison set — and
/// a struct field is exactly what a one-bit-too-wide FieldDesc decode breaks, because
/// <c>ELEMENT_TYPE_VALUETYPE</c> is 17 and odd.
/// </remarks>
internal struct FixturePoint
{
    /// <summary>First component.</summary>
    public int X;

    /// <summary>Second component.</summary>
    public int Y;
}

/// <summary>A base class, so inheritance has something to walk.</summary>
internal class FixtureBase
{
    /// <summary>Declared on the base; read through a derived instance.</summary>
    public int Hp;
}

/// <summary>A derived class with a string, a reference and an inline struct field.</summary>
internal class FixtureDerived : FixtureBase
{
    /// <summary>Exercises the §5.2 string decode.</summary>
    public string? Name;

    /// <summary>Exercises following a reference to another object.</summary>
    public FixtureBase? Link;

    /// <summary>Inline, not a reference — and an odd <c>m_type</c>, which is the point.</summary>
    public FixturePoint Position;
}

/// <summary>Holds the collections, plus a static root to resolve from.</summary>
internal class FixtureHolder
{
    /// <summary>The §12.4 capacity-versus-count case.</summary>
    public List<FixtureDerived>? Items;

    /// <summary>A primitive array.</summary>
    public int[]? Numbers;

    /// <summary>Stands in for <c>RunManager.Instance</c> (§8.8's API invariant).</summary>
    public static FixtureHolder? Instance;
}

#pragma warning restore CA1051, CS0649, IDE0044
