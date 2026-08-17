namespace LiveClr.Tests.Memory;

using LiveClr.Memory;

public class PageCacheTests
{
    private const ulong Base = 0x1000;

    private static FakeMemoryReader Mapped(int length = 64, byte seed = 0)
    {
        var data = new byte[length];
        for (int i = 0; i < length; i++) data[i] = (byte)(seed + i);
        return new FakeMemoryReader().Map(Base, data);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(4)]
    [InlineData(24)]
    [InlineData(-4096)]
    [InlineData(1 << 21)]
    public void Rejects_page_sizes_that_are_not_powers_of_two_in_range(int pageSize)
    {
        using var inner = new FakeMemoryReader();
        Assert.Throws<ArgumentOutOfRangeException>(() => new PageCache(inner, pageSize));
    }

    [Fact]
    public void Default_page_size_is_the_os_page()
    {
        using var inner = new FakeMemoryReader();
        using var cache = new PageCache(inner);
        Assert.Equal(4096, cache.PageSize);
        Assert.Equal(PageCache.DefaultPageSize, cache.PageSize);
    }

    [Fact]
    public void Serves_bytes_identical_to_the_inner_reader()
    {
        using var inner = Mapped();
        using var cache = new PageCache(inner, 16);

        var direct = new byte[10];
        Assert.True(inner.TryRead(Base + 3, direct));

        var cached = new byte[10];
        Assert.True(cache.TryRead(Base + 3, cached));

        Assert.Equal(direct, cached);
    }

    [Fact]
    public void Repeated_reads_of_one_block_hit_the_inner_reader_once()
    {
        using var inner = Mapped();
        using var cache = new PageCache(inner, 16);

        var buf = new byte[4];
        for (int i = 0; i < 10; i++) Assert.True(cache.TryRead(Base, buf));

        Assert.Equal(1, inner.ReadCalls);
        Assert.Equal(1L, cache.Misses);
        Assert.Equal(9L, cache.Hits);
        Assert.Equal(1, cache.CachedBlocks);
        Assert.Equal(16L, cache.CachedBytes);
    }

    [Fact]
    public void A_read_spanning_two_blocks_fetches_both_and_counts_both()
    {
        using var inner = Mapped();
        using var cache = new PageCache(inner, 16);

        var buf = new byte[8];
        Assert.True(cache.TryRead(Base + 12, buf)); // straddles the 0x1000/0x1010 boundary

        Assert.Equal(2, inner.ReadCalls);
        Assert.Equal(2L, cache.Misses);
        Assert.Equal(0L, cache.Hits);

        // Second identical read is fully cached.
        Assert.True(cache.TryRead(Base + 12, buf));
        Assert.Equal(2, inner.ReadCalls);
        Assert.Equal(2L, cache.Hits);
    }

    [Fact]
    public void Unaligned_and_multi_block_reads_reassemble_correctly()
    {
        using var inner = Mapped(length: 64);
        using var cache = new PageCache(inner, 16);

        var buf = new byte[40];
        Assert.True(cache.TryRead(Base + 5, buf));

        for (int i = 0; i < buf.Length; i++) Assert.Equal((byte)(5 + i), buf[i]);
    }

    /// <summary>
    /// The §4.7 / §6.4 property this class exists for: once a block is cached,
    /// mutation in the target is invisible, so a traversal sees one moment.
    /// </summary>
    [Fact]
    public void Target_mutation_after_caching_is_not_observed()
    {
        using var inner = Mapped();
        using var cache = new PageCache(inner, 16);

        var before = new byte[4];
        Assert.True(cache.TryRead(Base, before));

        inner.Poke(Base, 0xDE, 0xAD, 0xBE, 0xEF);

        var after = new byte[4];
        Assert.True(cache.TryRead(Base, after));
        Assert.Equal(before, after);

        // The mutation really did land — the cache is hiding it, not the fake.
        var raw = new byte[4];
        Assert.True(inner.TryRead(Base, raw));
        Assert.Equal(new byte[] { 0xDE, 0xAD, 0xBE, 0xEF }, raw);
    }

    [Fact]
    public void Mutation_is_observed_again_after_Clear()
    {
        using var inner = Mapped();
        using var cache = new PageCache(inner, 16);

        var buf = new byte[4];
        Assert.True(cache.TryRead(Base, buf));

        inner.Poke(Base, 0xDE, 0xAD, 0xBE, 0xEF);
        cache.Clear();

        Assert.Equal(0L, cache.Hits);
        Assert.Equal(0L, cache.Misses);
        Assert.Equal(0, cache.CachedBlocks);

        Assert.True(cache.TryRead(Base, buf));
        Assert.Equal(new byte[] { 0xDE, 0xAD, 0xBE, 0xEF }, buf);
    }

    [Fact]
    public void Unreadable_blocks_fail_and_are_negatively_cached()
    {
        using var inner = Mapped();
        using var cache = new PageCache(inner, 16);

        var buf = new byte[4];
        Assert.False(cache.TryRead(0x9000, buf));
        Assert.False(cache.TryRead(0x9000, buf));

        // One fetch attempt, then served from the negative entry: a page that
        // failed must keep failing, or the image stops being one moment.
        Assert.Equal(1, inner.ReadCalls);
        Assert.Equal(1L, cache.Misses);
        Assert.Equal(1L, cache.Hits);
        Assert.Equal(1, cache.CachedBlocks);
        Assert.Equal(0L, cache.CachedBytes);
    }

    [Fact]
    public void A_failed_read_leaves_the_buffer_zeroed_not_partly_filled()
    {
        using var inner = Mapped(length: 16);
        using var cache = new PageCache(inner, 16);

        // First 16 bytes map; the following block does not. A 12-byte read from
        // +8 straddles the boundary, so the readable prefix must be discarded.
        var buf = new byte[12];
        buf.AsSpan().Fill(0xCC);

        Assert.False(cache.TryRead(Base + 8, buf));
        Assert.All(buf, b => Assert.Equal(0, b));
    }

    [Fact]
    public void Zero_address_fails_without_touching_the_inner_reader()
    {
        using var inner = Mapped();
        using var cache = new PageCache(inner, 16);

        Assert.False(cache.TryRead(0, new byte[4]));
        Assert.Equal(0, inner.ReadCalls);
        Assert.Equal(0L, cache.Misses);
    }

    [Fact]
    public void Empty_read_succeeds_trivially()
    {
        using var inner = Mapped();
        using var cache = new PageCache(inner, 16);

        Assert.True(cache.TryRead(Base, Span<byte>.Empty));
        Assert.Equal(0, inner.ReadCalls);
    }

    [Fact]
    public void Address_space_wraparound_fails()
    {
        using var inner = Mapped();
        using var cache = new PageCache(inner, 16);

        Assert.False(cache.TryRead(ulong.MaxValue - 2, new byte[8]));
        Assert.Equal(0, inner.ReadCalls);
    }

    [Fact]
    public void Bitness_is_taken_from_the_inner_reader()
    {
        using var inner32 = new FakeMemoryReader(is64Bit: false);
        using var cache32 = new PageCache(inner32, 16);
        Assert.False(cache32.Is64Bit);

        using var inner64 = new FakeMemoryReader(is64Bit: true);
        using var cache64 = new PageCache(inner64, 16);
        Assert.True(cache64.Is64Bit);
    }

    [Fact]
    public void Does_not_dispose_the_inner_reader_by_default()
    {
        var inner = new FakeMemoryReader();
        new PageCache(inner).Dispose();
        Assert.False(inner.IsDisposed);

        new PageCache(inner, ownsInner: true).Dispose();
        Assert.True(inner.IsDisposed);
    }

    [Fact]
    public void Use_after_dispose_throws_rather_than_returning_stale_bytes()
    {
        using var inner = Mapped();
        var cache = new PageCache(inner, 16);
        cache.Dispose();

        Assert.Throws<ObjectDisposedException>(() => cache.TryRead(Base, new byte[4]));
    }

    /// <summary>
    /// Blocks larger than the 4 KiB protection granularity must not lose reads
    /// that a 4 KiB cache would have served: one unmapped 4 KiB page inside the
    /// block may not poison its readable neighbours.
    /// </summary>
    [Fact]
    public void Oversized_blocks_fall_back_to_per_protection_page_reads()
    {
        const ulong region = 0x10000;
        var data = new byte[8192];
        for (int i = 0; i < data.Length; i++) data[i] = (byte)i;

        using var inner = new FakeMemoryReader().Map(region, data);
        for (ulong a = region + 4096; a < region + 8192; a++) inner.UnreadableAddresses.Add(a);

        using var cache = new PageCache(inner, 8192);

        var first = new byte[16];
        Assert.True(cache.TryRead(region + 100, first));
        for (int i = 0; i < first.Length; i++) Assert.Equal((byte)(100 + i), first[i]);

        Assert.False(cache.TryRead(region + 5000, new byte[16]));

        // A read straddling the readable/unreadable boundary fails as a whole.
        Assert.False(cache.TryRead(region + 4090, new byte[16]));
    }

    /// <summary>
    /// Extension methods layered on TryRead must not paper over a failure — a
    /// half-read pointer surfacing as a plausible value is the §4.8 / §6.4 bug.
    /// </summary>
    [Fact]
    public void Pointer_extensions_over_the_cache_fail_closed()
    {
        using var inner = Mapped(length: 16);
        using var cache = new PageCache(inner, 16);

        // Bytes 8..15 are mapped, 16..23 are not: an 8-byte pointer read at +12
        // straddles the boundary.
        Assert.False(cache.TryReadPointer(Base + 12, out ulong value));
        Assert.Equal(0UL, value);
        Assert.Throws<MemoryAccessException>(() => cache.ReadPointer(Base + 12));
        Assert.Throws<MemoryAccessException>(() => cache.ReadBytes(Base + 12, 8));
    }

    /// <summary>
    /// Reproduces <c>scryObject.ts</c>'s <c>isTransientRead</c> exactly. Asserting
    /// on a prefix of the message is what let the contract break unnoticed: the
    /// old shape ended at the address, so it matched neither arm and retry never
    /// fired for anything.
    /// </summary>
    private static bool IsTransientRead(string message)
    {
        if (System.Text.RegularExpressions.Regex.IsMatch(message, "remote address 0+:")) return false;
        return message.Contains("Invalid access to memory location")
            || message.Contains("Only part of a Read");
    }

    [Theory]
    [InlineData(299)]  // ERROR_PARTIAL_COPY — torn or straddling read
    [InlineData(998)]  // ERROR_NOACCESS — bad pointer
    [InlineData(0)]    // unknown
    public void Read_failures_are_classified_as_transient_and_therefore_retried(int nativeErrorCode)
    {
        var ex = new MemoryAccessException(0x7FFE_1234, 8, nativeErrorCode);

        Assert.StartsWith("Failed to read 8 bytes from remote address 7FFE1234:", ex.Message);
        Assert.True(IsTransientRead(ex.Message), $"isTransientRead rejected: {ex.Message}");
        Assert.Equal(0x7FFE_1234UL, ex.Address);
        Assert.Equal(8, ex.Length);
        Assert.Equal(nativeErrorCode, ex.NativeErrorCode);
    }

    [Fact]
    public void A_torn_read_and_a_bad_pointer_render_different_substrings()
    {
        Assert.Contains("Only part of a Read", new MemoryAccessException(0x1000, 8, 299).Message);
        Assert.Contains("Invalid access to memory location", new MemoryAccessException(0x1000, 8, 998).Message);
    }

    /// <summary>
    /// §6.4's deliberate exclusion: a null deref is a structural bug in the walk,
    /// not a transient condition, and must never be retried. The trailing colon
    /// is what terminates the address in the <c>0+:</c> pattern.
    /// </summary>
    [Theory]
    [InlineData(0)]
    [InlineData(998)]
    [InlineData(299)]
    public void Address_zero_is_excluded_from_retry(int nativeErrorCode)
    {
        var ex = new MemoryAccessException(0, 8, nativeErrorCode);

        Assert.Matches("remote address 0+:", ex.Message);
        Assert.False(IsTransientRead(ex.Message), $"isTransientRead retried a null deref: {ex.Message}");
    }

    [Fact]
    public void ReadFailure_carries_the_readers_native_error_into_the_message()
    {
        using var inner = Mapped(length: 16);
        using var cache = new PageCache(inner, 16);

        Assert.False(cache.TryRead(0x9000, new byte[4]));

        var ex = cache.ReadFailure(0x9000, 4);
        Assert.Equal(cache.LastNativeErrorCode, ex.NativeErrorCode);
        Assert.True(IsTransientRead(ex.Message));
    }

    [Fact]
    public void A_reader_without_diagnostics_reports_no_native_error()
    {
        using IMemoryReader plain = new UndiagnosedReader();
        Assert.Equal(0, plain.LastNativeErrorCode());
        Assert.Equal(0, plain.ReadFailure(0x1000, 8).NativeErrorCode);
    }

    /// <summary>
    /// A negative cache entry is replayed for the instance's lifetime, so the
    /// reason has to be stored with it — otherwise a torn read (retryable) would
    /// be replayed as a bad pointer, or vice versa.
    /// </summary>
    [Fact]
    public void The_cached_failure_reason_survives_replay()
    {
        using var inner = Mapped();
        inner.FailureErrorCode = 299;
        using var cache = new PageCache(inner, 16);

        Assert.False(cache.TryRead(0x9000, new byte[4]));
        Assert.Equal(299, cache.LastNativeErrorCode);

        Assert.True(cache.TryRead(Base, new byte[4]));
        Assert.Equal(0, cache.LastNativeErrorCode);
        Assert.Equal(2, inner.ReadCalls);

        // Replayed from the negative entry: no new fetch, original reason intact.
        Assert.False(cache.TryRead(0x9000, new byte[4]));
        Assert.Equal(299, cache.LastNativeErrorCode);
        Assert.Equal(2, inner.ReadCalls);
        Assert.Contains("Only part of a Read", cache.ReadFailure(0x9000, 4).Message);
    }

    [Fact]
    public void Reads_rejected_before_a_syscall_still_report_a_classifiable_error()
    {
        using var inner = Mapped();
        using var cache = new PageCache(inner, 16);

        Assert.False(cache.TryRead(0, new byte[4]));
        Assert.Equal(998, cache.LastNativeErrorCode);
        Assert.Contains("Invalid access to memory location", cache.ReadFailure(0, 4).Message);
    }

    private sealed class UndiagnosedReader : IMemoryReader
    {
        public bool Is64Bit => true;
        public bool TryRead(ulong address, Span<byte> buffer) => false;
        public void Dispose() { }
    }
}
