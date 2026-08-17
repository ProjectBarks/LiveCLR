namespace LiveClr.Fixtures;

using LiveClr.Memory;

/// <summary>
/// Decorates a real <see cref="IMemoryReader"/> and keeps every byte it serves, so a session
/// against a live process can be replayed later as a <see cref="RecordedMemory"/> fixture.
/// </summary>
/// <remarks>
/// <para>Analysis doc §8.8, "Two additions" item 1. Recording is a decorator for the same
/// reason the page cache is one (§4.7): the layers above must not know or care whether they
/// are talking to a process or to a file. Capture happens by running the *real* code path
/// once — no separate "dump" tool that can drift from what the reader actually asks for.</para>
///
/// <para><b>Record one snapshot per fixture.</b> Captures are coalesced and re-reads overwrite,
/// so a recording spanning many polls of a mutating process produces a composite image that
/// never existed at one instant. Wrap a single snapshot's reads (§4.7 page cache), not a whole
/// session — and see the remarks on <see cref="RecordedMemory"/> for why that also means a
/// fixture cannot reproduce the §12.4e torn walk.</para>
///
/// <para>Only successful reads are recorded. A failed read captures nothing, so replay
/// reproduces the failure by omission (§4.8: unreadable stays unreadable). That is the
/// honest behaviour — recording a failure as "region present but garbage" would be the
/// silent-wrong-data failure mode the doc keeps warning about.</para>
///
/// <para>Not thread-safe for concurrent reads. Snapshots are single-threaded by construction
/// (§8.8 lifetimes), and adding a lock here would tax the live polling path to serve the
/// capture path.</para>
/// </remarks>
public sealed class RecordingMemoryReader : IMemoryReader
{
    private readonly IMemoryReader _inner;
    private readonly bool _leaveOpen;
    private readonly RegionMap _map = new();
    private bool _disposed;

    /// <param name="inner">The reader to observe. Every successful read through it is captured.</param>
    /// <param name="description">Provenance stored in the fixture header (process, build, date).</param>
    /// <param name="leaveOpen">When false (default), disposing this also disposes <paramref name="inner"/>.</param>
    public RecordingMemoryReader(IMemoryReader inner, string? description = null, bool leaveOpen = false)
    {
        ArgumentNullException.ThrowIfNull(inner);
        _inner = inner;
        _leaveOpen = leaveOpen;
        Description = description ?? string.Empty;
    }

    /// <summary>Provenance text written into the fixture header.</summary>
    public string Description { get; set; }

    /// <inheritdoc />
    public bool Is64Bit => _inner.Is64Bit;

    /// <summary>Reads that the underlying reader satisfied.</summary>
    public int ServedReads { get; private set; }

    /// <summary>Reads that the underlying reader rejected. Not captured — see remarks on the class.</summary>
    public int FailedReads { get; private set; }

    /// <summary>Coalesced regions captured so far.</summary>
    public int RegionCount => _map.Count;

    /// <summary>Distinct bytes captured so far. Re-reading the same page does not grow this.</summary>
    public long RecordedByteCount => _map.TotalBytes;

    /// <inheritdoc />
    public bool TryRead(ulong address, Span<byte> buffer)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!_inner.TryRead(address, buffer))
        {
            FailedReads++;
            return false;
        }

        ServedReads++;
        _map.Add(address, buffer);
        return true;
    }

    /// <summary>Snapshot the capture so far as a replayable reader. Recording may continue afterwards.</summary>
    /// <remarks>The returned instance owns a copy, so later reads through this decorator do not mutate it.</remarks>
    public RecordedMemory ToRecordedMemory()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        var copy = new RegionMap();
        foreach (var entry in _map.Entries)
            copy.Add(entry.Start, entry.Data.Span);
        return new RecordedMemory(copy, Is64Bit, Description);
    }

    /// <summary>Write the capture so far to a stream.</summary>
    public void Save(Stream stream)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        RecordedMemoryFormat.Write(stream, _map, Is64Bit, Description);
    }

    /// <summary>Write the capture so far to a file.</summary>
    public void Save(string path)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        using var fs = File.Create(path);
        Save(fs);
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        if (!_leaveOpen) _inner.Dispose();
    }
}
