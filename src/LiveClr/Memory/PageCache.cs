namespace LiveClr.Memory;

/// <summary>
/// A read-through cache of page-aligned blocks over another
/// <see cref="IMemoryReader"/>. Every block is fetched at most once for the
/// lifetime of the instance, so one traversal sees one memory image.
/// </summary>
/// <remarks>
/// This is the §4.7 page cache, and per §6.4 it is the <em>structural</em>
/// mitigation for the §12.4e defect rather than a performance tweak. That bug —
/// a scene-tree walk returning ten nodes short while the tree was being spliced —
/// was silent: every individual read succeeded and returned a plausible pointer,
/// so read-level retry (<c>isTransientRead</c>) could not see it. Freezing the
/// bytes a traversal observes closes most of that window instead of detecting it
/// after the fact. The performance win — one <c>ReadProcessMemory</c> per page
/// rather than dozens of small calls, the same argument §4.1 makes for bulk
/// reads — is a side effect.
/// <para>
/// <b>Lifetime is the contract.</b> §8.8 places the page cache in the snapshot
/// tier: construct one per snapshot, dispose it with the snapshot, and never
/// share one across snapshots. A long-lived cache does not go stale in a way it
/// can detect — it silently keeps serving a moment that has passed.
/// </para>
/// <para>
/// Failures are cached too. A block that could not be read stays unreadable for
/// this instance's lifetime, because a page that becomes readable mid-traversal
/// would reintroduce exactly the mixed-moment image the cache exists to prevent.
/// </para>
/// <para>Not thread-safe; a snapshot is single-threaded by construction.</para>
/// </remarks>
public sealed class PageCache : IMemoryReader, IMemoryReadDiagnostics
{
    /// <summary>4 KiB — the x86/x64 page size, and the granularity Windows applies protections at.</summary>
    public const int DefaultPageSize = 4096;

    private const int MaxPageSize = 1 << 20;

    /// <summary>
    /// Protection granularity. Whether a byte is readable is decided per 4 KiB
    /// page, so a block larger than this can span readable and unreadable pages.
    /// </summary>
    private const int ProtectionGranularity = 4096;

    private readonly IMemoryReader _inner;
    private readonly bool _ownsInner;
    private readonly ulong _blockMask;
    private readonly Dictionary<ulong, Block> _blocks = [];

    private long _hits;
    private long _misses;
    private int _lastNativeErrorCode;
    private bool _disposed;

    /// <summary>
    /// Wraps <paramref name="inner"/>.
    /// </summary>
    /// <param name="inner">The reader to fetch uncached blocks from.</param>
    /// <param name="pageSize">
    /// Block size in bytes; must be a power of two between 8 and 1 MiB. The
    /// default matches the OS page. Values below 4 KiB exist for testing and
    /// weaken the consistency window; values above trade more speculative reading
    /// for fewer round trips.
    /// </param>
    /// <param name="ownsInner">
    /// Whether disposing this cache disposes <paramref name="inner"/>. Defaults
    /// to false: the normal arrangement is a snapshot-scoped cache over a
    /// process-scoped reader (§8.8), where the inner reader outlives the cache.
    /// </param>
    public PageCache(IMemoryReader inner, int pageSize = DefaultPageSize, bool ownsInner = false)
    {
        ArgumentNullException.ThrowIfNull(inner);
        if (pageSize < 8 || pageSize > MaxPageSize || (pageSize & (pageSize - 1)) != 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(pageSize), pageSize, $"Page size must be a power of two between 8 and {MaxPageSize}.");
        }

        _inner = inner;
        _ownsInner = ownsInner;
        PageSize = pageSize;
        _blockMask = ~(ulong)(uint)(pageSize - 1);
    }

    /// <summary>Block size in bytes.</summary>
    public int PageSize { get; }

    /// <summary>
    /// Block lookups served from the cache. Counted per block touched, not per
    /// <see cref="TryRead"/> call, so a read spanning two blocks contributes two.
    /// A ratio far from 1 means the traversal is jumping across the address
    /// space and the cache is buying consistency but little speed.
    /// </summary>
    public long Hits => _hits;

    /// <summary>Block lookups that required a fetch from the inner reader.</summary>
    public long Misses => _misses;

    /// <summary>Distinct blocks fetched, readable or not.</summary>
    public int CachedBlocks => _blocks.Count;

    /// <summary>Bytes currently retained by the cache.</summary>
    public long CachedBytes
    {
        get
        {
            long total = 0;
            foreach (var b in _blocks.Values)
            {
                if (b.Data is not null) total += b.Data.Length;
            }
            return total;
        }
    }

    /// <inheritdoc/>
    public bool Is64Bit => _inner.Is64Bit;

    /// <summary>
    /// Win32 error recorded when the failing block was <em>fetched</em>, not when
    /// it was replayed. That is the honest answer: a cached failure reports the
    /// moment the image was taken, so §4.8's classifier sees the same
    /// ERROR_PARTIAL_COPY the uncached read would have produced.
    /// </summary>
    public int LastNativeErrorCode => _lastNativeErrorCode;

    /// <inheritdoc/>
    public bool TryRead(ulong address, Span<byte> buffer)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (buffer.Length == 0)
        {
            _lastNativeErrorCode = 0;
            return true;
        }

        if (address == 0) return Reject(buffer);
        if (ulong.MaxValue - address < (ulong)(buffer.Length - 1)) return Reject(buffer);

        int copied = 0;
        ulong cursor = address;

        while (copied < buffer.Length)
        {
            ulong blockBase = cursor & _blockMask;
            int offset = (int)(cursor - blockBase);
            int take = Math.Min(PageSize - offset, buffer.Length - copied);

            var block = GetOrFetch(blockBase);
            if (block.Data is null || !IsRangeValid(block, offset, take))
            {
                // Fail closed, and discard the prefix already copied: a caller
                // that ignores the return value must not see a partly-filled
                // buffer that happens to look like a valid object (§4.8).
                _lastNativeErrorCode = block.NativeErrorCode;
                buffer.Clear();
                return false;
            }

            block.Data.AsSpan(offset, take).CopyTo(buffer.Slice(copied, take));
            copied += take;
            cursor += (ulong)take;
        }

        _lastNativeErrorCode = 0;
        return true;

        bool Reject(Span<byte> b)
        {
            _lastNativeErrorCode = NativeMethods.ERROR_NOACCESS;
            b.Clear();
            return false;
        }
    }

    /// <summary>
    /// Drops every cached block and resets the counters.
    /// </summary>
    /// <remarks>
    /// Breaks the one-image guarantee by design — reads before and after a clear
    /// come from different moments. Only meaningful for a reader deliberately
    /// reused across snapshots; prefer constructing a new cache per snapshot.
    /// </remarks>
    public void Clear()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        _blocks.Clear();
        _hits = 0;
        _misses = 0;
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _blocks.Clear();
        if (_ownsInner) _inner.Dispose();
    }

    private Block GetOrFetch(ulong blockBase)
    {
        if (_blocks.TryGetValue(blockBase, out var cached))
        {
            _hits++;
            return cached;
        }

        _misses++;
        var block = Fetch(blockBase);
        _blocks[blockBase] = block;
        return block;
    }

    private Block Fetch(ulong blockBase)
    {
        var data = new byte[PageSize];
        if (_inner.TryRead(blockBase, data)) return new Block(data, null, 0);

        // Capture why, at the moment of the failed fetch: the negative entry is
        // replayed for the cache's lifetime, so the reason has to travel with it.
        int error = _inner.LastNativeErrorCode();

        // With the default block size this is the end of it: Windows decides
        // readability per 4 KiB page, so an aligned 4 KiB read is all-or-nothing
        // and a failure means the page genuinely is not there.
        if (PageSize <= ProtectionGranularity) return Block.Unreadable(error);

        // Larger blocks can straddle a region boundary. Re-read per protection
        // page so one unmapped neighbour does not make readable pages look
        // unreadable — otherwise raising PageSize would lose reads that the
        // default size would have served.
        var valid = new bool[PageSize / ProtectionGranularity];
        bool any = false;
        for (int i = 0; i < valid.Length; i++)
        {
            var slice = data.AsSpan(i * ProtectionGranularity, ProtectionGranularity);
            if (_inner.TryRead(blockBase + (ulong)(i * ProtectionGranularity), slice))
            {
                valid[i] = true;
                any = true;
            }
            else
            {
                error = _inner.LastNativeErrorCode();
                slice.Clear();
            }
        }

        return any ? new Block(data, valid, error) : Block.Unreadable(error);
    }

    private static bool IsRangeValid(Block block, int offset, int length)
    {
        if (block.SubPageValid is null) return true;

        int first = offset / ProtectionGranularity;
        int last = (offset + length - 1) / ProtectionGranularity;
        for (int i = first; i <= last; i++)
        {
            if (!block.SubPageValid[i]) return false;
        }
        return true;
    }

    /// <param name="Data">Block contents, or null when nothing in the block is readable.</param>
    /// <param name="SubPageValid">Null when the whole block is valid — the common case, and allocation-free.</param>
    /// <param name="NativeErrorCode">Why the fetch failed, preserved so replays report the original reason.</param>
    private sealed record Block(byte[]? Data, bool[]? SubPageValid, int NativeErrorCode)
    {
        public static Block Unreadable(int nativeErrorCode) => new(null, null, nativeErrorCode);
    }
}
