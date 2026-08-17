namespace LiveClr.Tests.Metadata;

using System.Buffers.Binary;
using LiveClr.Metadata;

/// <summary>
/// Exercises the §12.4d route end to end against a real managed assembly mapped as a loaded
/// image behind a fake <c>IMemoryReader</c>: PE headers → data directory 14 → CLI header →
/// metadata root → validated blob → <c>MetadataReader</c>.
/// </summary>
public sealed class ModuleMetadataTests
{
    private static string LiveClrAssemblyPath =>
        typeof(ModuleMetadata).Assembly.Location;

    private static MappedPeImage LiveClrImage() => MappedPeImage.FromFile(LiveClrAssemblyPath);

    [Fact]
    public void LoadsMetadataFromAMappedManagedImage()
    {
        MappedPeImage mapped = LiveClrImage();
        using var reader = mapped.CreateReader();

        using ModuleMetadata? metadata = ModuleMetadata.TryLoad(
            reader, MappedPeImage.BaseAddress, out ModuleMetadataStatus status, out string? detail);

        Assert.Equal(ModuleMetadataStatus.Loaded, status);
        Assert.Null(detail);
        Assert.NotNull(metadata);
        Assert.Equal(MappedPeImage.BaseAddress, metadata.ModuleBase);
        Assert.True(metadata.MetadataRva > 0);
        Assert.True(metadata.MetadataSize > 0);
    }

    [Fact]
    public void MetadataRootMatchesTheShapeDocumentedInSection12_4d()
    {
        MappedPeImage mapped = LiveClrImage();
        using var reader = mapped.CreateReader();
        using ModuleMetadata? metadata = ModuleMetadata.TryLoad(reader, MappedPeImage.BaseAddress);

        Assert.NotNull(metadata);
        // §12.4d observed "v4.0.30319" live; every Roslyn-produced assembly carries the same.
        Assert.Equal("v4.0.30319", metadata.Root.VersionString);
        Assert.True(metadata.Root.HasStream("#~"));
        Assert.True(metadata.Root.HasStream("#Strings"));
        Assert.True(metadata.Root.HasStream("#GUID"));
        Assert.True(metadata.Root.HasStream("#Blob"));

        // NOT "every stream lies inside the blob": TryLoad refuses a blob for which that is
        // false, so by the time there is a ModuleMetadata to ask, the answer is fixed and the
        // loop cannot come out any way but true (§13.11). That property is falsifiable one
        // layer down, where a blob can be built that violates it — see
        // MetadataBlobValidatorTests. What is worth asserting here is what the loader does NOT
        // guarantee: that the stream table is a set of distinct, non-empty streams rather than
        // whatever repeated or zero-length entries a header happens to list.
        MetadataStreamHeader[] streams = [.. metadata.Root.Streams];
        Assert.True(streams.Length >= 4, $"only {streams.Length} streams");
        Assert.Equal(streams.Length, streams.Select(s => s.Name).Distinct(StringComparer.Ordinal).Count());
        Assert.All(streams, s => Assert.True(s.Size > 0, $"{s.Name} is empty"));
    }

    [Fact]
    public void ResolvesAKnownTypeAndItsFieldNames()
    {
        MappedPeImage mapped = LiveClrImage();
        using var reader = mapped.CreateReader();
        using ModuleMetadata? metadata = ModuleMetadata.TryLoad(reader, MappedPeImage.BaseAddress);

        Assert.NotNull(metadata);
        Assert.True(metadata.Types.TryResolveType("LiveClr.Metadata.ModuleMetadata", out var handle));

        IReadOnlyList<string> fields = metadata.Types.GetFieldNames(handle);

        // These are this class's own private instance fields — read out of the target's
        // #Strings heap, exactly as §12.4d did for real identifiers.
        Assert.Contains("_provider", fields);
        Assert.Contains("_blob", fields);
        Assert.Contains("_types", fields);
        Assert.Contains("ChunkSize", fields); // a const: present in metadata, absent from layout
    }

    [Fact]
    public void BulkCopiesTheBlobRatherThanWalkingItRemotely()
    {
        // §7b.3: the blob is ~5 MB for sts2.dll and must not be walked field-by-field.
        // A handful of header reads plus ONE copy is the whole remote cost.
        MappedPeImage mapped = LiveClrImage();
        var counting = new FakeImageMemoryReader(mapped.Image, MappedPeImage.BaseAddress);

        using ModuleMetadata? metadata = ModuleMetadata.TryLoad(counting, MappedPeImage.BaseAddress);

        Assert.NotNull(metadata);
        Assert.InRange(counting.ReadCount, 1, 12);

        // Every subsequent name lookup must be local — no further remote reads at all.
        int afterLoad = counting.ReadCount;
        Assert.True(metadata.Types.ContainsType("LiveClr.Metadata.TypeResolver"));
        _ = metadata.Types.EnumerateTypeNames().ToList();
        Assert.Equal(afterLoad, counting.ReadCount);
    }

    [Fact]
    public void LoadsAMultiMegabyteBlobLikeTheOneInSection12_4d()
    {
        // sts2.dll's metadata is 4,967,924 bytes (§7b.3). System.Private.CoreLib is the
        // closest thing available in CI to that scale.
        MappedPeImage mapped = MappedPeImage.FromFile(typeof(object).Assembly.Location);
        using var reader = mapped.CreateReader();

        using ModuleMetadata? metadata = ModuleMetadata.TryLoad(
            reader, MappedPeImage.BaseAddress, out ModuleMetadataStatus status, out _);

        Assert.Equal(ModuleMetadataStatus.Loaded, status);
        Assert.NotNull(metadata);
        Assert.True(metadata.MetadataSize > 1_000_000, $"metadata was {metadata.MetadataSize} bytes");
        Assert.True(metadata.Types.ContainsType("System.String"));
    }

    [Fact]
    public void FallsBackToChunkedReadsWhenOneLargeReadIsRejected()
    {
        // A single multi-megabyte ReadProcessMemory can be refused where 64 KiB reads succeed.
        MappedPeImage mapped = MappedPeImage.FromFile(typeof(object).Assembly.Location);

        var strict = new FakeImageMemoryReader(mapped.Image, MappedPeImage.BaseAddress)
        {
            MaxSingleRead = 100 * 1024,
        };
        using ModuleMetadata? chunked = ModuleMetadata.TryLoad(strict, MappedPeImage.BaseAddress);

        Assert.NotNull(chunked);
        Assert.True(chunked.Types.ContainsType("System.Object"));
        Assert.True(strict.ReadCount > 12, "the blob should have been copied in chunks");

        // Below the chunk size nothing can satisfy the copy: fail cleanly rather than hand a
        // partially-filled buffer to MetadataReader.
        var impossible = new FakeImageMemoryReader(mapped.Image, MappedPeImage.BaseAddress)
        {
            MaxSingleRead = 4096,
        };
        ModuleMetadata? failed = ModuleMetadata.TryLoad(
            impossible, MappedPeImage.BaseAddress, out ModuleMetadataStatus status, out _);

        Assert.Null(failed);
        Assert.Equal(ModuleMetadataStatus.MetadataUnreadable, status);
    }

    [Fact]
    public void ReturnsNullForANativeImageInsteadOfThrowing()
    {
        // Requirement 3: a module with no CLI header is ordinary, not exceptional.
        MappedPeImage mapped = LiveClrImage();
        mapped.Image.AsSpan(mapped.CliDirectoryOffset, 8).Clear();

        using var reader = mapped.CreateReader();
        ModuleMetadata? metadata = ModuleMetadata.TryLoad(
            reader, MappedPeImage.BaseAddress, out ModuleMetadataStatus status, out string? detail);

        Assert.Null(metadata);
        Assert.Equal(ModuleMetadataStatus.NoCliHeader, status);
        Assert.NotNull(detail);
    }

    [Fact]
    public void ReturnsNullWhenTheBaseIsNotAPeImage()
    {
        var garbage = new byte[0x2000];
        Random.Shared.NextBytes(garbage);
        garbage[0] = 0x00; // definitely not 'MZ'

        using var reader = new FakeImageMemoryReader(garbage, MappedPeImage.BaseAddress);
        ModuleMetadata? metadata = ModuleMetadata.TryLoad(
            reader, MappedPeImage.BaseAddress, out ModuleMetadataStatus status, out _);

        Assert.Null(metadata);
        Assert.Equal(ModuleMetadataStatus.NotAPeImage, status);
    }

    [Fact]
    public void RejectsACorruptedBsjbSignatureBeforeReachingMetadataReader()
    {
        MappedPeImage mapped = LiveClrImage();
        uint rva = MetadataRvaOf(mapped);

        mapped.Image[(int)rva] = (byte)'X'; // 'BSJB' -> 'XSJB'

        using var reader = mapped.CreateReader();
        ModuleMetadata? metadata = ModuleMetadata.TryLoad(
            reader, MappedPeImage.BaseAddress, out ModuleMetadataStatus status, out string? detail);

        Assert.Null(metadata);
        Assert.Equal(ModuleMetadataStatus.MalformedMetadata, status);
        Assert.Contains("BSJB", detail ?? string.Empty);
    }

    [Fact]
    public void RejectsAStreamThatRunsPastTheEndOfTheBlob()
    {
        // The exact attack the SECURITY note is about: a self-describing offset that points
        // outside the buffer. MetadataReader would trust it; we must not reach it.
        MappedPeImage mapped = LiveClrImage();
        uint rva = MetadataRvaOf(mapped);

        int versionLength = BinaryPrimitives.ReadInt32LittleEndian(mapped.Image.AsSpan((int)rva + 12));
        int firstStreamHeader = (int)rva + 16 + versionLength + 4;

        // Inflate the first stream's size so offset+size exceeds the blob.
        BinaryPrimitives.WriteUInt32LittleEndian(
            mapped.Image.AsSpan(firstStreamHeader + 4), 0xFFFF_0000u);

        using var reader = mapped.CreateReader();
        ModuleMetadata? metadata = ModuleMetadata.TryLoad(
            reader, MappedPeImage.BaseAddress, out ModuleMetadataStatus status, out string? detail);

        Assert.Null(metadata);
        Assert.Equal(ModuleMetadataStatus.MalformedMetadata, status);
        Assert.Contains("outside", detail ?? string.Empty);
    }

    [Fact]
    public void RejectsATruncatedBlob()
    {
        // Shrink the metadata directory size so the copied blob cannot hold its own streams.
        MappedPeImage mapped = LiveClrImage();
        int cliRva = (int)BinaryPrimitives.ReadUInt32LittleEndian(
            mapped.Image.AsSpan(mapped.CliDirectoryOffset));

        BinaryPrimitives.WriteUInt32LittleEndian(mapped.Image.AsSpan(cliRva + 12), 64);

        using var reader = mapped.CreateReader();
        ModuleMetadata? metadata = ModuleMetadata.TryLoad(
            reader, MappedPeImage.BaseAddress, out ModuleMetadataStatus status, out _);

        Assert.Null(metadata);
        Assert.Equal(ModuleMetadataStatus.MalformedMetadata, status);
    }

    [Fact]
    public void CacheReturnsTheSameInstancePerModuleBase()
    {
        // §8.8 Process tier: module metadata is loaded once for the life of the connection.
        MappedPeImage mapped = LiveClrImage();
        var reader = new FakeImageMemoryReader(mapped.Image, MappedPeImage.BaseAddress);

        using var cache = new ModuleMetadataCache(reader);
        ModuleMetadata? first = cache.GetOrLoad(MappedPeImage.BaseAddress);
        int afterFirst = reader.ReadCount;
        ModuleMetadata? second = cache.GetOrLoad(MappedPeImage.BaseAddress);

        Assert.NotNull(first);
        Assert.Same(first, second);
        Assert.Equal(afterFirst, reader.ReadCount);

        // Negative results are cached too — a native module stays native.
        Assert.Null(cache.GetOrLoad(MappedPeImage.BaseAddress + 0x10));
        int afterMiss = reader.ReadCount;
        Assert.Null(cache.GetOrLoad(MappedPeImage.BaseAddress + 0x10));
        Assert.Equal(afterMiss, reader.ReadCount);
    }

    private static uint MetadataRvaOf(MappedPeImage mapped)
    {
        using var reader = mapped.CreateReader();
        using ModuleMetadata? metadata = ModuleMetadata.TryLoad(reader, MappedPeImage.BaseAddress);
        Assert.NotNull(metadata);
        return metadata.MetadataRva;
    }
}
