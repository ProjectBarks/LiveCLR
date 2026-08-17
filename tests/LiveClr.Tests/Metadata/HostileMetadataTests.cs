namespace LiveClr.Tests.Metadata;

using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using LiveClr.Metadata;

/// <summary>
/// The gap that structural validation cannot close: blobs whose ROOT is valid and whose TABLE
/// CONTENTS are not.
/// </summary>
/// <remarks>
/// Every input here passes <see cref="MetadataBlobValidator"/> and constructs a
/// <c>MetadataReader</c> without complaint. The realistic origin is not an attacker but a stale
/// <c>Module.Base</c> (§7b.1) resolving onto a plausible-but-wrong image, which is precisely
/// the failure mode §12.4e warns is silent — so the required behaviour is a degraded answer,
/// never an exception and never a crash.
/// </remarks>
public sealed class HostileMetadataTests
{
    [Fact]
    public void ACyclicNestedClassRowDoesNotRecurseForever()
    {
        // A type that encloses itself. Recursive name construction turns this into a
        // StackOverflowException, which no catch block can intercept and which takes the
        // whole process with it.
        byte[] blob = SyntheticMetadata.Build(builder =>
        {
            TypeDefinitionHandle cyclic = SyntheticMetadata.AddNestedShapedType(builder, "Cyclic");
            builder.AddNestedType(cyclic, cyclic);
        });

        // The validator sees nothing wrong, which is the whole point of this test class.
        Assert.True(MetadataBlobValidator.TryValidate(blob, out _, out _));

        var (provider, resolver) = SyntheticMetadata.ResolverOver(blob);
        using (provider)
        {
            // Proof the row really is self-referential, so this test cannot pass vacuously if
            // the encoding ever changes: the type is flagged nested AND declares itself.
            TypeDefinition definition = resolver.Reader.GetTypeDefinition(
                MetadataTokens.TypeDefinitionHandle(2));
            Assert.True(definition.IsNested);
            Assert.Equal(
                MetadataTokens.GetToken(MetadataTokens.TypeDefinitionHandle(2)),
                MetadataTokens.GetToken(definition.GetDeclaringType()));

            // The doubled segment is the signature of the cycle guard firing: the walk
            // stopped at the repeat and rebuilt one level inward.
            List<string> names = [.. resolver.EnumerateTypeNames()];
            Assert.Contains("Cyclic+Cyclic", names);

            // And the index built from those names still answers lookups.
            Assert.False(resolver.ContainsType("Nope"));
        }
    }

    [Fact]
    public void AMutuallyNestedPairDoesNotRecurseForever()
    {
        // A encloses B and B encloses A: the cycle spans two rows, so a naive "is this the
        // handle I started from" guard would miss it. Only a visited set catches this.
        byte[] blob = SyntheticMetadata.Build(builder =>
        {
            TypeDefinitionHandle a = SyntheticMetadata.AddNestedShapedType(builder, "A");
            TypeDefinitionHandle b = SyntheticMetadata.AddNestedShapedType(builder, "B");
            builder.AddNestedType(a, b);
            builder.AddNestedType(b, a);
        });

        var (provider, resolver) = SyntheticMetadata.ResolverOver(blob);
        using (provider)
        {
            List<string> names = [.. resolver.EnumerateTypeNames()];
            Assert.Equal(resolver.TypeCount, names.Count);

            // Each side terminates at the repeat rather than ping-ponging forever.
            Assert.Contains("A+B", names);
            Assert.Contains("A+B+A", names);
        }
    }

    [Fact]
    public void AnAbsurdlyDeepNestingChainIsCapped()
    {
        const int Depth = 4000;

        byte[] blob = SyntheticMetadata.Build(builder =>
        {
            var handles = new TypeDefinitionHandle[Depth];
            for (int i = 0; i < Depth; i++)
            {
                handles[i] = SyntheticMetadata.AddNestedShapedType(builder, "T" + i);
            }

            // T0 nested in T1 nested in T2 ... Rows are added in ascending nested-type order,
            // which is the sort the NestedClass table requires.
            for (int i = 0; i < Depth - 1; i++)
            {
                builder.AddNestedType(handles[i], handles[i + 1]);
            }
        });

        var (provider, resolver) = SyntheticMetadata.ResolverOver(blob);
        using (provider)
        {
            List<string> names = [.. resolver.EnumerateTypeNames()];
            int longest = names.Max(n => n.Split('+').Length);

            // Bounded output, and bounded EXACTLY at the cap — an inequality alone would
            // still pass if the chain were silently not being followed at all.
            Assert.Equal(TypeResolver.MaxNestingDepth + 1, longest);
        }
    }

    [Fact]
    public void NestedFlagsWithNoNestedClassRowResolveAsARootType()
    {
        // IsNested comes from the visibility flags; GetDeclaringType comes from the
        // NestedClass table. A corrupt image can set the first and omit the second.
        byte[] blob = SyntheticMetadata.Build(builder =>
            SyntheticMetadata.AddNestedShapedType(builder, "Orphan"));

        var (provider, resolver) = SyntheticMetadata.ResolverOver(blob);
        using (provider)
        {
            Assert.True(resolver.ContainsType("Orphan"));
        }
    }

    [Fact]
    public void AnOutOfRangeStringHandleReadsAsNotFoundRatherThanThrowing()
    {
        // SRM bounds-checks heap handles LAZILY. Shrinking #Strings leaves every existing
        // name handle pointing past the heap end, while the stream still lies inside the
        // blob so structural validation passes.
        MappedPeImage mapped = MappedPeImage.FromFile(typeof(HostileMetadataTests).Assembly.Location);
        uint rva = MetadataRvaOf(mapped);
        SyntheticMetadata.SetStreamSize(mapped.Image, (int)rva, "#Strings", 8);

        using var reader = mapped.CreateReader();
        using ModuleMetadata? metadata = ModuleMetadata.TryLoad(
            reader, MappedPeImage.BaseAddress, out ModuleMetadataStatus status, out _);

        // Construction may or may not notice; both outcomes must be non-throwing.
        if (metadata is null)
        {
            Assert.Equal(ModuleMetadataStatus.MalformedMetadata, status);
            return;
        }

        TypeResolver resolver = metadata.Types;

        // Every documented-as-safe entry point must degrade, not throw.
        Assert.False(resolver.TryResolveType("LiveClr.Tests.Metadata.SampleType", out _));
        Assert.False(resolver.ContainsType("System.Object"));
        Assert.Null(resolver.ResolveType("Whatever"));
        Assert.Equal(TypeResolver.UnreadableName, resolver.GetFullName(MetadataTokens.TypeDefinitionHandle(2)));
        Assert.Empty(resolver.GetFields(MetadataTokens.TypeDefinitionHandle(2)));
        Assert.Empty(resolver.GetFieldNames(MetadataTokens.TypeDefinitionHandle(2)));
        Assert.False(resolver.TryGetField(MetadataTokens.TypeDefinitionHandle(2), "x", out _));
        Assert.All(resolver.EnumerateTypeNames(), n => Assert.NotNull(n));
    }

    [Fact]
    public void ATruncatedTableStreamIsRejectedByTryLoadRatherThanThrowing()
    {
        // Exercises the catch(BadImageFormatException) around GetMetadataReader: the #~
        // stream is still in bounds, so the structural gate passes it through, but there is
        // no longer a readable table header behind it.
        MappedPeImage mapped = MappedPeImage.FromFile(typeof(HostileMetadataTests).Assembly.Location);
        uint rva = MetadataRvaOf(mapped);
        SyntheticMetadata.SetStreamSize(mapped.Image, (int)rva, "#~", 4);

        using var reader = mapped.CreateReader();
        ModuleMetadata? metadata = ModuleMetadata.TryLoad(
            reader, MappedPeImage.BaseAddress, out ModuleMetadataStatus status, out string? detail);

        Assert.Null(metadata);
        Assert.Equal(ModuleMetadataStatus.MalformedMetadata, status);
        Assert.NotNull(detail);
    }

    private static uint MetadataRvaOf(MappedPeImage mapped)
    {
        using var reader = mapped.CreateReader();
        using ModuleMetadata? metadata = ModuleMetadata.TryLoad(reader, MappedPeImage.BaseAddress);
        Assert.NotNull(metadata);
        return metadata.MetadataRva;
    }
}
