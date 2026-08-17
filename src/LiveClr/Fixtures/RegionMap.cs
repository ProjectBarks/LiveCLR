namespace LiveClr.Fixtures;

/// <summary>
/// A sorted, non-overlapping, non-adjacent set of captured byte ranges.
/// </summary>
/// <remarks>
/// Recordings arrive as whatever the caller happened to read: overlapping pointer-sized
/// reads, whole 4 KiB pages from the snapshot page cache (§4.7), duplicates from a re-read.
/// Storing them verbatim would make replay ambiguous (which copy wins?) and would make a
/// read that straddles two recorded reads fail even though every byte was captured.
///
/// So the map coalesces on insert. Two consequences worth stating out loud:
/// <list type="bullet">
/// <item>Overlapping captures are LAST-WRITE-WINS. Recording a live, mutating process can
/// legitimately observe different bytes at the same address at different moments; the
/// fixture keeps the most recent. A fixture is a snapshot, not a history.</item>
/// <item>Adjacent ranges merge, so a page-cache recording collapses to a handful of large
/// regions instead of thousands of small ones — which is most of why the binary container
/// stays small.</item>
/// </list>
///
/// <para>Sequential capture (page after page, which is exactly how a page cache fills) takes
/// an in-place append path with geometric growth. The obvious implementation — allocate the
/// merged size and copy on every insert — is O(n²) in the size of the region, and a multi-MB
/// module blob (§7b.3) is recorded a page at a time.</para>
/// </remarks>
internal sealed class RegionMap
{
    private sealed class Region
    {
        public ulong Start;
        public byte[] Buffer = Array.Empty<byte>();
        public int Length;

        public ulong End => Start + (ulong)Length;
        public Span<byte> Span => Buffer.AsSpan(0, Length);
    }

    private readonly List<Region> _regions = new();

    /// <summary>One captured range: start address and its bytes.</summary>
    internal readonly record struct Entry(ulong Start, ReadOnlyMemory<byte> Data);

    public int Count => _regions.Count;

    public long TotalBytes
    {
        get
        {
            long total = 0;
            foreach (var r in _regions) total += r.Length;
            return total;
        }
    }

    /// <summary>Regions in ascending address order. Views, not copies — do not retain past a mutation.</summary>
    public IEnumerable<Entry> Entries
    {
        get
        {
            foreach (var r in _regions)
                yield return new Entry(r.Start, r.Buffer.AsMemory(0, r.Length));
        }
    }

    /// <summary>Insert <paramref name="data"/> at <paramref name="address"/>, merging into any range it overlaps or touches.</summary>
    public void Add(ulong address, ReadOnlySpan<byte> data)
    {
        if (data.Length == 0) return;
        if ((ulong)data.Length > ulong.MaxValue - address)
            throw new ArgumentException("Region wraps the end of the address space.", nameof(address));

        ulong end = address + (ulong)data.Length;

        // Regions are disjoint and sorted, so End is strictly increasing: binary-searchable.
        int first = LowerBoundByEnd(address);
        int last = first;
        while (last < _regions.Count && _regions[last].Start <= end) last++;

        if (first == last)
        {
            _regions.Insert(first, NewRegion(address, data));
            return;
        }

        // Fast path: the write touches exactly one region and starts at or inside it. This is
        // the sequential-capture case (append the next page), and it must not reallocate.
        if (last - first == 1)
        {
            var only = _regions[first];
            if (address >= only.Start)
            {
                int required = checked((int)(end - only.Start));
                if (required > only.Buffer.Length)
                {
                    // Geometric growth: amortises page-by-page recording to O(n) total copying.
                    int capacity = Math.Max(required, only.Buffer.Length == 0 ? required : only.Buffer.Length * 2);
                    Array.Resize(ref only.Buffer, capacity);
                }

                data.CopyTo(only.Buffer.AsSpan((int)(address - only.Start)));
                only.Length = Math.Max(only.Length, required);
                return;
            }
        }

        // Every region in [first, last) overlaps or abuts [address, end), so the union is contiguous.
        ulong newStart = Math.Min(address, _regions[first].Start);
        ulong newEnd = Math.Max(end, _regions[last - 1].End);
        var merged = new byte[checked((int)(newEnd - newStart))];

        for (int i = first; i < last; i++)
        {
            var r = _regions[i];
            r.Span.CopyTo(merged.AsSpan((int)(r.Start - newStart)));
        }

        // New data last: last-write-wins on overlap.
        data.CopyTo(merged.AsSpan((int)(address - newStart)));

        _regions.RemoveRange(first, last - first);
        _regions.Insert(first, new Region { Start = newStart, Buffer = merged, Length = merged.Length });
    }

    /// <summary>
    /// Fill <paramref name="buffer"/> only if the whole span sits inside one recorded region.
    /// Anything else fails closed — a fixture must never invent bytes it did not capture.
    /// </summary>
    /// <remarks>A zero-length read succeeds anywhere: no bytes were requested, so none are invented.</remarks>
    public bool TryRead(ulong address, Span<byte> buffer)
    {
        if (buffer.Length == 0) return true;

        int idx = FindContaining(address, buffer.Length);
        if (idx < 0) return false;

        var r = _regions[idx];
        r.Span.Slice((int)(address - r.Start), buffer.Length).CopyTo(buffer);
        return true;
    }

    /// <summary>True if every byte of the span was captured. Answers without copying.</summary>
    public bool Covers(ulong address, int length) => length switch
    {
        0 => true,
        < 0 => false,
        _ => FindContaining(address, length) >= 0,
    };

    /// <summary>Index of the region wholly containing the span, or -1.</summary>
    private int FindContaining(ulong address, int length)
    {
        if ((ulong)length > ulong.MaxValue - address) return -1;

        int idx = FloorByStart(address);
        if (idx < 0) return -1;

        return address + (ulong)length <= _regions[idx].End ? idx : -1;
    }

    private static Region NewRegion(ulong address, ReadOnlySpan<byte> data) =>
        new() { Start = address, Buffer = data.ToArray(), Length = data.Length };

    /// <summary>Index of the first region whose End is &gt;= <paramref name="address"/>, else Count.</summary>
    private int LowerBoundByEnd(ulong address)
    {
        int lo = 0, hi = _regions.Count;
        while (lo < hi)
        {
            int mid = (int)(((uint)lo + (uint)hi) >> 1);
            if (_regions[mid].End < address) lo = mid + 1;
            else hi = mid;
        }
        return lo;
    }

    /// <summary>Index of the last region whose Start is &lt;= <paramref name="address"/>, else -1.</summary>
    private int FloorByStart(ulong address)
    {
        int lo = 0, hi = _regions.Count - 1, found = -1;
        while (lo <= hi)
        {
            int mid = (int)(((uint)lo + (uint)hi) >> 1);
            if (_regions[mid].Start <= address) { found = mid; lo = mid + 1; }
            else hi = mid - 1;
        }
        return found;
    }
}
