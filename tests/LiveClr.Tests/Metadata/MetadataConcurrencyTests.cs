namespace LiveClr.Tests.Metadata;

using System.Collections.Concurrent;
using System.Reflection.Metadata;
using LiveClr.Metadata;

/// <summary>
/// The Process tier (§8.8) is shared by every snapshot, and snapshots are not promised to be
/// single-threaded. These tests exercise the "write-once under a Lock" claims in the class
/// remarks rather than leaving them as assertions in prose.
/// </summary>
public sealed class MetadataConcurrencyTests
{
    private const int Threads = 8;
    private const int Iterations = 150;

    [Fact]
    public void CacheLoadsEachModuleExactlyOnceUnderConcurrentCallers()
    {
        MappedPeImage mapped = MappedPeImage.FromFile(typeof(ModuleMetadata).Assembly.Location);
        var reader = new FakeImageMemoryReader(mapped.Image, MappedPeImage.BaseAddress);

        using var cache = new ModuleMetadataCache(reader);
        var seen = new ConcurrentBag<ModuleMetadata?>();

        Parallel.For(0, Threads, _ =>
        {
            for (int i = 0; i < Iterations; i++) seen.Add(cache.GetOrLoad(MappedPeImage.BaseAddress));
        });

        ModuleMetadata?[] results = [.. seen];
        Assert.Equal(Threads * Iterations, results.Length);
        Assert.All(results, r => Assert.NotNull(r));

        // One instance for everyone: a duplicate would mean a second 5 MB copy AND a leak,
        // since only the cached one is ever disposed.
        Assert.Single(results.Distinct());
    }

    [Fact]
    public void ResolverCachesAreConsistentUnderConcurrentReaders()
    {
        MappedPeImage mapped = MappedPeImage.FromFile(typeof(ModuleMetadata).Assembly.Location);
        using var reader = mapped.CreateReader();
        using ModuleMetadata? metadata = ModuleMetadata.TryLoad(reader, MappedPeImage.BaseAddress);
        Assert.NotNull(metadata);

        // Every thread races on the SAME first-touch: index build, name cache, field caches.
        var resolvers = new ConcurrentBag<TypeResolver>();
        var names = new ConcurrentBag<string>();
        var fieldCounts = new ConcurrentBag<int>();

        Parallel.For(0, Threads, _ =>
        {
            for (int i = 0; i < Iterations; i++)
            {
                TypeResolver types = metadata.Types;
                resolvers.Add(types);

                Assert.True(types.TryResolveType("LiveClr.Metadata.ModuleMetadata", out var handle));
                names.Add(types.GetFullName(handle));
                fieldCounts.Add(types.GetFieldNames(handle).Count);
            }
        });

        // Lazy<T> with ExecutionAndPublication: exactly one resolver, so exactly one index.
        Assert.Single(resolvers.Distinct());
        Assert.Single(names.Distinct());
        Assert.Single(fieldCounts.Distinct());
    }

    [Fact]
    public void FieldNameListsAreCachedNotRebuiltPerCall()
    {
        MappedPeImage mapped = MappedPeImage.FromFile(typeof(ModuleMetadata).Assembly.Location);
        using var reader = mapped.CreateReader();
        using ModuleMetadata? metadata = ModuleMetadata.TryLoad(reader, MappedPeImage.BaseAddress);
        Assert.NotNull(metadata);

        Assert.True(metadata.Types.TryResolveType("LiveClr.Metadata.ModuleMetadata", out var handle));

        IReadOnlyList<string> first = metadata.Types.GetFieldNames(handle);
        IReadOnlyList<string> second = metadata.Types.GetFieldNames(handle);

        // Reference equality: the class remarks promise everything is cached, and §12.4
        // (API fact 1) makes repeated field-name lookup the hot path.
        Assert.Same(first, second);
        Assert.Same(metadata.Types.GetFields(handle), metadata.Types.GetFields(handle));
    }

    [Fact]
    public void CacheRejectsUseAfterDisposeRatherThanHandingBackAnOrphan()
    {
        MappedPeImage mapped = MappedPeImage.FromFile(typeof(ModuleMetadata).Assembly.Location);
        using var reader = mapped.CreateReader();

        var cache = new ModuleMetadataCache(reader);
        Assert.NotNull(cache.GetOrLoad(MappedPeImage.BaseAddress));
        cache.Dispose();

        Assert.Throws<ObjectDisposedException>(() => cache.GetOrLoad(MappedPeImage.BaseAddress));

        // Dispose is idempotent — an overlay tearing down a connection should not have to
        // track whether it already did.
        cache.Dispose();
    }

    [Fact]
    public void HandlesRemainValidAcrossThreadsForTheSameType()
    {
        MappedPeImage mapped = MappedPeImage.FromFile(typeof(ModuleMetadata).Assembly.Location);
        using var reader = mapped.CreateReader();
        using ModuleMetadata? metadata = ModuleMetadata.TryLoad(reader, MappedPeImage.BaseAddress);
        Assert.NotNull(metadata);

        var handles = new ConcurrentBag<TypeDefinitionHandle>();
        Parallel.For(0, Threads, _ =>
        {
            for (int i = 0; i < Iterations; i++)
            {
                if (metadata.Types.TryResolveType("LiveClr.Metadata.TypeResolver", out var h))
                {
                    handles.Add(h);
                }
            }
        });

        Assert.Equal(Threads * Iterations, handles.Count);
        Assert.Single(handles.Distinct());
    }
}
