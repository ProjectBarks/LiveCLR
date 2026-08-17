namespace LiveClr.Tests.Metadata;

using System.Collections.Concurrent;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
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

    /// <summary>
    /// Eight threads released simultaneously onto a cold resolver, asserting on the identity of
    /// what they get back rather than on its value.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Reference equality is the whole point.</b> This test used to collect
    /// <c>GetFullName(handle)</c> and <c>GetFieldNames(handle).Count</c> and assert one distinct
    /// value of each. Both are pure functions of the metadata blob, so both agree whatever the
    /// caches do: replacing all six <c>lock (_gate)</c> statements with <c>if (true)</c> left
    /// the whole suite green (§13.11). Identity does not agree — an unguarded cache lets two
    /// racing callers each publish and return their own instance — so that is what is asserted.
    /// </para>
    /// <para>
    /// <b>A Barrier, not Parallel.For.</b> Contention here is one dictionary key deep and lives
    /// entirely in the first microsecond of the first touch. Threads that trickle in find the
    /// cache warm and race with nobody, which is the other half of why the old test could not
    /// fail. The barrier makes the first touch genuinely simultaneous.
    /// </para>
    /// <para>
    /// <b>Exactly what is covered, stated rather than implied.</b> <see cref="TypeResolver"/>
    /// takes <c>_gate</c> in six places. Four of them are falsifiable through this API and each
    /// was confirmed by removing it individually: <c>TryResolveType</c>, <c>GetFullName</c>, and
    /// the publishing lock in each of <c>GetFields</c> and <c>GetFieldNames</c> (the last three
    /// via the two sweep tests below). The remaining two — the cache-hit CHECK at the top of
    /// <c>GetFields</c> and of <c>GetFieldNames</c> — guard only against reading a dictionary
    /// while another thread mutates it. Removing either leaves this whole suite green, because a
    /// racing reader that misses simply builds a value and then loses the publish race, which is
    /// indistinguishable from having lost it anyway. Their real hazard, a structurally corrupted
    /// <c>Dictionary</c>, surfaces as a throw or a spin and cannot be made deterministic, so
    /// nothing automated tries to violate it and no coverage is claimed for it.
    /// </para>
    /// </remarks>
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
        var fieldNameLists = new ConcurrentBag<IReadOnlyList<string>>();
        var fieldLists = new ConcurrentBag<IReadOnlyList<MetadataField>>();

        RaceFromABarrier(() =>
        {
            for (int i = 0; i < Iterations; i++)
            {
                TypeResolver types = metadata.Types;
                resolvers.Add(types);

                Assert.True(types.TryResolveType("LiveClr.Metadata.ModuleMetadata", out var handle));
                names.Add(types.GetFullName(handle));
                fieldNameLists.Add(types.GetFieldNames(handle));
                fieldLists.Add(types.GetFields(handle));
            }
        });

        Assert.Equal(Threads * Iterations, fieldNameLists.Count);

        // Lazy<T> with ExecutionAndPublication: exactly one resolver, so exactly one index.
        Assert.Single(resolvers.Distinct());

        // One published instance per key, handed to everyone — not one value per key.
        AssertOneInstance(names);
        AssertOneInstance(fieldNameLists);
        AssertOneInstance(fieldLists);
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

    /// <summary>
    /// The field caches, swept across every type in the module with all eight threads
    /// rendezvousing before each one.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see cref="ResolverCachesAreConsistentUnderConcurrentReaders"/> races on ONE cold key, and
    /// on a cold resolver the index build inside <c>TryResolveType</c> holds the gate long enough
    /// to serialise everyone behind it. So it only reddens when every lock is removed at once and
    /// cannot say which one mattered — and a single key gives the race exactly one chance, which
    /// a fast path like <c>GetFields</c> wins outright more often than not.
    /// </para>
    /// <para>
    /// Sweeping every type gives the race hundreds of chances, and the per-key rendezvous makes
    /// each of them a genuine simultaneous first touch rather than a hope about scheduling. The
    /// handles come from the raw reader, so no index build is involved and the two publish locks
    /// are the only thing standing between this and two callers holding different arrays.
    /// </para>
    /// </remarks>
    [Fact]
    public void FieldCachesPublishOneInstanceToEveryConcurrentCaller()
    {
        MappedPeImage mapped = MappedPeImage.FromFile(typeof(ModuleMetadata).Assembly.Location);
        using var reader = mapped.CreateReader();
        using ModuleMetadata? metadata = ModuleMetadata.TryLoad(reader, MappedPeImage.BaseAddress);
        Assert.NotNull(metadata);

        TypeResolver types = metadata.Types;
        TypeDefinitionHandle[] handles = [.. types.Reader.TypeDefinitions];
        Assert.True(handles.Length > 20, $"only {handles.Length} cold keys to race over");

        var fields = new ConcurrentDictionary<TypeDefinitionHandle, ConcurrentBag<object>>();
        var fieldNames = new ConcurrentDictionary<TypeDefinitionHandle, ConcurrentBag<object>>();

        RaceOverKeys(handles, handle =>
        {
            fields.GetOrAdd(handle, _ => []).Add(types.GetFields(handle));
            fieldNames.GetOrAdd(handle, _ => []).Add(types.GetFieldNames(handle));
        });

        AssertOneInstancePerKey(fields, handles.Length);
        AssertOneInstancePerKey(fieldNames, handles.Length);
    }

    /// <summary>
    /// The name cache, swept the same way. Handles come from the raw reader because going through
    /// <c>TryResolveType</c> would populate <c>_nameCache</c> for every type in the module as a
    /// side effect of building the index, after which <c>GetFullName</c> can only ever hit the
    /// cache and its lock becomes unfalsifiable.
    /// </summary>
    [Fact]
    public void FullNamesPublishOneInstanceToEveryConcurrentCaller()
    {
        MappedPeImage mapped = MappedPeImage.FromFile(typeof(ModuleMetadata).Assembly.Location);
        using var reader = mapped.CreateReader();
        using ModuleMetadata? metadata = ModuleMetadata.TryLoad(reader, MappedPeImage.BaseAddress);
        Assert.NotNull(metadata);

        TypeResolver types = metadata.Types;
        TypeDefinitionHandle[] handles = [.. types.Reader.TypeDefinitions];
        var names = new ConcurrentDictionary<TypeDefinitionHandle, ConcurrentBag<object>>();

        RaceOverKeys(handles, handle => names.GetOrAdd(handle, _ => []).Add(types.GetFullName(handle)));

        AssertOneInstancePerKey(names, handles.Length);
    }

    private static void AssertOneInstancePerKey<TKey>(
        ConcurrentDictionary<TKey, ConcurrentBag<object>> observed, int expectedKeys)
        where TKey : notnull
    {
        Assert.Equal(expectedKeys, observed.Count);

        foreach ((TKey key, ConcurrentBag<object> instances) in observed)
        {
            Assert.Equal(Threads, instances.Count);
            Assert.Single(instances.Distinct(ReferenceEqualityComparer.Instance));
            Assert.NotNull(key);
        }
    }

    private static void AssertOneInstance<T>(IEnumerable<T> observed) where T : class =>
        Assert.Single(observed.Cast<object>().Distinct(ReferenceEqualityComparer.Instance));

    /// <summary>
    /// Run <paramref name="body"/> on <see cref="Threads"/> real threads that all leave the
    /// starting line together.
    /// </summary>
    /// <remarks>
    /// Real threads rather than <c>Parallel.For</c>: the barrier needs exactly
    /// <see cref="Threads"/> participants, and the thread pool is free to supply fewer.
    /// </remarks>
    private static void RaceFromABarrier(Action body) => Race(rendezvous =>
    {
        rendezvous();
        body();
    });

    /// <summary>
    /// Same, but with every thread re-synchronising immediately before each key, so each key gets
    /// a genuine simultaneous first touch instead of one hope about scheduling.
    /// </summary>
    private static void RaceOverKeys<T>(IReadOnlyList<T> keys, Action<T> body) => Race(rendezvous =>
    {
        foreach (T key in keys)
        {
            rendezvous();
            body(key);
        }
    });

    private static void Race(Action<Action> body)
    {
        using var startLine = new Barrier(Threads);
        var failures = new ConcurrentBag<Exception>();
        var threads = new Thread[Threads];

        // A bounded wait, not an unbounded one. If a thread dies mid-sweep — which is exactly
        // what an unguarded cache can do — the survivors must fall through and let the test
        // report the exception, not deadlock and take the run with them.
        void Rendezvous() => startLine.SignalAndWait(TimeSpan.FromSeconds(5));

        for (int t = 0; t < Threads; t++)
        {
            threads[t] = new Thread(() =>
            {
                try
                {
                    body(Rendezvous);
                }
                catch (Exception e)
                {
                    failures.Add(e);
                }
            });

            threads[t].Start();
        }

        foreach (Thread thread in threads) thread.Join();
        Assert.Empty(failures);
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
