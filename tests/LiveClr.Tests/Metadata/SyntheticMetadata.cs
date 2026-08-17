namespace LiveClr.Tests.Metadata;

using System.Buffers.Binary;
using System.Collections.Immutable;
using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Text;
using LiveClr.Metadata;

/// <summary>
/// Builds metadata blobs with deliberately hostile TABLE CONTENTS.
/// </summary>
/// <remarks>
/// The structural validator cannot reach any of this — that is the point. These blobs have a
/// valid <c>BSJB</c> root and in-bounds streams, so they pass validation and construct a
/// <c>MetadataReader</c>, and everything dangerous is inside the tables. Using
/// <c>MetadataBuilder</c> rather than byte-patching keeps the rows well-formed at the encoding
/// level, which is exactly the case that slips past a structural gate.
/// </remarks>
internal static class SyntheticMetadata
{
    /// <summary>Emit a minimal but genuine metadata root, then let the caller add hostile rows.</summary>
    internal static byte[] Build(Action<MetadataBuilder> configure)
    {
        var builder = new MetadataBuilder();

        builder.AddModule(
            0,
            builder.GetOrAddString("hostile.dll"),
            builder.GetOrAddGuid(Guid.NewGuid()),
            default,
            default);

        builder.AddAssembly(
            builder.GetOrAddString("hostile"),
            new Version(1, 0, 0, 0),
            default,
            default,
            default,
            AssemblyHashAlgorithm.None);

        // Row 1 of TypeDef is <Module> by convention; keep the shape realistic.
        builder.AddTypeDefinition(
            TypeAttributes.NotPublic,
            default,
            builder.GetOrAddString("<Module>"),
            default,
            MetadataTokens.FieldDefinitionHandle(1),
            MetadataTokens.MethodDefinitionHandle(1));

        configure(builder);

        // suppressValidation: the builder would otherwise refuse to emit the very rows under
        // test, which are illegal by construction.
        var root = new MetadataRootBuilder(builder, suppressValidation: true);
        var blob = new BlobBuilder();
        root.Serialize(blob, methodBodyStreamRva: 0, mappedFieldDataStreamRva: 0);
        return blob.ToArray();
    }

    /// <summary>Add a type whose visibility flags mark it nested. Its declaring row is set separately.</summary>
    internal static TypeDefinitionHandle AddNestedShapedType(MetadataBuilder builder, string name) =>
        builder.AddTypeDefinition(
            TypeAttributes.NestedPublic,
            default,
            builder.GetOrAddString(name),
            default,
            MetadataTokens.FieldDefinitionHandle(1),
            MetadataTokens.MethodDefinitionHandle(1));

    /// <summary>A <c>TypeResolver</c> over a raw blob, with the provider kept alive by the caller.</summary>
    internal static (MetadataReaderProvider Provider, TypeResolver Resolver) ResolverOver(byte[] blob)
    {
        var provider = MetadataReaderProvider.FromMetadataImage(ImmutableArray.Create(blob));
        return (provider, new TypeResolver(provider.GetMetadataReader()));
    }

    /// <summary>
    /// Offset of a named stream's <c>Size</c> field within a metadata root. Shrinking that
    /// size is how a heap is made to under-run its own handles while every structural bound
    /// still holds.
    /// </summary>
    internal static int StreamSizeFieldOffset(ReadOnlySpan<byte> blob, string streamName)
    {
        int versionLength = BinaryPrimitives.ReadInt32LittleEndian(blob[12..]);
        int cursor = 16 + versionLength;
        int count = BinaryPrimitives.ReadUInt16LittleEndian(blob[(cursor + 2)..]);
        cursor += 4;

        for (int i = 0; i < count; i++)
        {
            int sizeField = cursor + 4;
            int nameStart = cursor + 8;
            int nameEnd = nameStart;
            while (blob[nameEnd] != 0) nameEnd++;

            if (Encoding.ASCII.GetString(blob[nameStart..nameEnd]) == streamName) return sizeField;
            cursor = (nameEnd + 1 + 3) & ~3;
        }

        throw new InvalidOperationException($"stream '{streamName}' not present");
    }

    /// <summary>Rewrite a stream's declared size in place.</summary>
    internal static void SetStreamSize(byte[] blob, int blobStart, string streamName, uint size)
    {
        int field = StreamSizeFieldOffset(blob.AsSpan(blobStart), streamName);
        BinaryPrimitives.WriteUInt32LittleEndian(blob.AsSpan(blobStart + field), size);
    }
}
