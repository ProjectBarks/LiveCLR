namespace LiveClr.Tests.Metadata;

using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using LiveClr.Metadata;

/// <summary>
/// Name-side resolution (§12.4d): type by full name, field names and tokens, nested types,
/// base types — with no scry and no ClrMD in the picture.
/// </summary>
public sealed class TypeResolverTests : IDisposable
{
    private readonly IDisposable _reader;
    private readonly ModuleMetadata _metadata;

    public TypeResolverTests()
    {
        // The test assembly itself: it defines the nested and derived shapes below, so the
        // expectations are checked in next to the fixture rather than borrowed from CoreLib.
        MappedPeImage mapped = MappedPeImage.FromFile(typeof(TypeResolverTests).Assembly.Location);
        var reader = mapped.CreateReader();
        _reader = reader;
        _metadata = ModuleMetadata.TryLoad(reader, MappedPeImage.BaseAddress)
            ?? throw new InvalidOperationException("test assembly has no metadata");
    }

    private TypeResolver Types => _metadata.Types;

    [Fact]
    public void ResolvesByNamespaceQualifiedName()
    {
        Assert.True(Types.TryResolveType("LiveClr.Tests.Metadata.SampleType", out var handle));
        Assert.Equal("LiveClr.Tests.Metadata.SampleType", Types.GetFullName(handle));
    }

    [Fact]
    public void ReturnsFalseForAnUnknownNameInsteadOfThrowing()
    {
        Assert.False(Types.TryResolveType("MegaCrit.Sts2.Core.Runs.RunManager", out _));
        Assert.Null(Types.ResolveType("Nope.Nothing.Here"));
        Assert.False(Types.ContainsType(""));
    }

    [Fact]
    public void EnumeratesDeclaredFieldNamesAndTokens()
    {
        Assert.True(Types.TryResolveType("LiveClr.Tests.Metadata.SampleType", out var handle));

        IReadOnlyList<MetadataField> fields = Types.GetFields(handle);
        string[] names = [.. fields.Select(f => f.Name)];

        Assert.Contains("_instanceField", names);
        Assert.Contains("SharedCounter", names);
        Assert.Contains("MaxValue", names);

        foreach (MetadataField field in fields)
        {
            // Token table 0x04 == Field. The token is what pairs a metadata name with the
            // runtime's FieldDefToDescMap (§5.2, Module.FieldDefToDescMap = 432).
            Assert.Equal((byte)0x04, (byte)(field.Token >> 24));
            Assert.Equal(HandleKind.FieldDefinition, MetadataTokens.EntityHandle(field.Token).Kind);
        }
    }

    [Fact]
    public void DistinguishesStaticAndLiteralFields()
    {
        Assert.True(Types.TryResolveType("LiveClr.Tests.Metadata.SampleType", out var handle));

        Assert.True(Types.TryGetField(handle, "_instanceField", out MetadataField instance));
        Assert.False(instance.IsStatic);
        Assert.False(instance.IsLiteral);

        Assert.True(Types.TryGetField(handle, "SharedCounter", out MetadataField shared));
        Assert.True(shared.IsStatic);
        Assert.False(shared.IsLiteral);

        // A const has no storage at all — it can never appear in an object's layout.
        Assert.True(Types.TryGetField(handle, "MaxValue", out MetadataField literal));
        Assert.True(literal.IsLiteral);
        Assert.True(literal.IsStatic);

        Assert.True(Types.TryGetField(handle, "_instanceField", out MetadataField again));
        Assert.Equal(FieldAttributes.Private, again.Attributes & FieldAttributes.FieldAccessMask);
    }

    [Fact]
    public void ReportsMissingFieldsWithoutThrowing()
    {
        Assert.True(Types.TryResolveType("LiveClr.Tests.Metadata.SampleType", out var handle));
        Assert.False(Types.TryGetField(handle, "NoSuchField", out _));
    }

    [Fact]
    public void ResolvesNestedTypesWithBothSeparators()
    {
        Assert.True(Types.TryResolveType("LiveClr.Tests.Metadata.SampleType+Nested", out var plus));
        Assert.True(Types.TryResolveType("LiveClr.Tests.Metadata.SampleType/Nested", out var slash));
        Assert.Equal(plus, slash);

        Assert.True(Types.TryResolveType(
            "LiveClr.Tests.Metadata.SampleType+Nested+Deeper", out var deeper));
        Assert.Equal("LiveClr.Tests.Metadata.SampleType+Nested+Deeper", Types.GetFullName(deeper));

        Assert.True(Types.TryResolveType("LiveClr.Tests.Metadata.SampleType", out var outer));
        IReadOnlyList<TypeDefinitionHandle> nested = Types.GetNestedTypes(outer);
        Assert.Contains(plus, nested);
        Assert.DoesNotContain(deeper, nested); // direct children only
    }

    [Fact]
    public void ResolvesBaseTypesInsideAndOutsideTheModule()
    {
        Assert.True(Types.TryResolveType("LiveClr.Tests.Metadata.SampleDerived", out var derived));
        Assert.True(Types.TryGetBaseType(derived, out MetadataBaseType baseType));
        Assert.Equal("LiveClr.Tests.Metadata.SampleType", baseType.FullName);
        Assert.True(baseType.IsInThisModule);
        Assert.False(baseType.IsGenericInstantiation);

        // The chain terminates at a TypeRef into another module — the metadata layer cannot
        // follow it, which is precisely why the runtime side walks ParentMethodTable (§5.2).
        Assert.True(Types.TryGetBaseType(baseType.Definition, out MetadataBaseType root));
        Assert.Equal("System.Object", root.FullName);
        Assert.False(root.IsInThisModule);
    }

    [Fact]
    public void FlagsAGenericInstantiationBaseRatherThanGuessingItsName()
    {
        Assert.True(Types.TryResolveType("LiveClr.Tests.Metadata.SampleList", out var handle));
        Assert.True(Types.TryGetBaseType(handle, out MetadataBaseType baseType));
        Assert.True(baseType.IsGenericInstantiation);
        Assert.Null(baseType.FullName);
    }

    [Fact]
    public void EnumeratesEveryTypeInTheModule()
    {
        List<string> names = [.. Types.EnumerateTypeNames()];

        // Count against TypeCount is the enumeration measured against the collection it
        // enumerates: both are TypeDefinitions.Count, so it agrees however many rows the walk
        // drops (§13.11). What can disagree is the SHAPE of what comes out — one name per row,
        // every one readable, and the nesting, namespace and generic-arity spellings all
        // reconstructed rather than left as raw #Strings entries.
        Assert.Equal(Types.TypeCount, names.Count);
        Assert.DoesNotContain(TypeResolver.UnreadableName, names);
        Assert.All(names, n => Assert.False(string.IsNullOrWhiteSpace(n)));

        Assert.Contains("LiveClr.Tests.Metadata.SampleType", names);           // namespaced root
        Assert.Contains("LiveClr.Tests.Metadata.SampleType+Nested", names);    // reconstructed nesting
        Assert.Contains("LiveClr.Tests.Metadata.SampleList", names);           // generic base
        Assert.Contains("<Module>", names);                                    // row 1, no namespace
    }

    public void Dispose()
    {
        _metadata.Dispose();
        _reader.Dispose();
    }
}

/// <summary>Fixture whose metadata shape the tests above assert against.</summary>
internal class SampleType
{
    public const int MaxValue = 42;
    internal static int SharedCounter = 1;
    private readonly int _instanceField;

    public SampleType(int value) => _instanceField = value;

    public int Value => _instanceField;

    internal class Nested
    {
        internal class Deeper;
    }
}

internal sealed class SampleDerived : SampleType
{
    public SampleDerived() : base(0) { }
}

internal sealed class SampleList : List<int>;
