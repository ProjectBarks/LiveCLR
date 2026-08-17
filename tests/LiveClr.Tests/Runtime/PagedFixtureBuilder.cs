namespace LiveClr.Tests.Runtime;

using System.Buffers.Binary;
using LiveClr.Fixtures;

/// <summary>
/// Accumulates scattered writes into whole 4 KiB pages, then emits a
/// <see cref="RecordedMemory"/> whose regions are page-aligned.
/// </summary>
/// <remarks>
/// Page alignment is not cosmetic. A <c>LiveValidated</c> snapshot reads through
/// <c>PageCache</c>, which fetches an aligned 4 KiB block and treats a failed fetch as "the
/// whole block is unreadable" — modelling how Windows decides readability per page. A fixture
/// that mapped exactly the bytes it wrote would therefore make every read fail for reasons that
/// have nothing to do with the code under test.
/// </remarks>
internal sealed class PagedFixtureBuilder
{
    private const int PageSize = 4096;

    private readonly SortedDictionary<ulong, byte[]> _pages = [];

    /// <summary>Bytes written so far, counted as whole pages.</summary>
    public long MappedBytes => (long)_pages.Count * PageSize;

    public void Write(ulong address, ReadOnlySpan<byte> data)
    {
        int written = 0;
        while (written < data.Length)
        {
            ulong cursor = address + (ulong)written;
            ulong pageBase = cursor & ~(ulong)(PageSize - 1);
            int offset = (int)(cursor - pageBase);
            int take = Math.Min(PageSize - offset, data.Length - written);

            if (!_pages.TryGetValue(pageBase, out byte[]? page))
            {
                page = new byte[PageSize];
                _pages[pageBase] = page;
            }

            data.Slice(written, take).CopyTo(page.AsSpan(offset, take));
            written += take;
        }
    }

    public void WriteU64(ulong address, ulong value)
    {
        Span<byte> buffer = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64LittleEndian(buffer, value);
        Write(address, buffer);
    }

    public void WriteU32(ulong address, uint value)
    {
        Span<byte> buffer = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(buffer, value);
        Write(address, buffer);
    }

    public void WriteI32(ulong address, int value) => WriteU32(address, unchecked((uint)value));

    public void WriteU16(ulong address, ushort value)
    {
        Span<byte> buffer = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16LittleEndian(buffer, value);
        Write(address, buffer);
    }

    public void WriteU8(ulong address, byte value) => Write(address, [value]);

    /// <summary>
    /// Remove the page containing <paramref name="address"/>, so reads that touch it fail.
    /// </summary>
    /// <remarks>
    /// Models the hole a segmented lookup map leaves: the runtime allocated one segment, and
    /// what follows it in the address space is not necessarily mapped at all. Must be called
    /// AFTER every write, since writing recreates a page.
    /// </remarks>
    public bool Unmap(ulong address) => _pages.Remove(address & ~(ulong)(PageSize - 1));

    /// <summary>Page-aligned base of the page containing <paramref name="address"/>.</summary>
    public static ulong PageOf(ulong address) => address & ~(ulong)(PageSize - 1);

    /// <summary>Page size the fixture aligns to.</summary>
    public static int Page => PageSize;

    /// <summary>Reserve a range so it reads as zeroes rather than failing.</summary>
    public void Reserve(ulong address, long length)
    {
        ulong end = address + (ulong)length;
        for (ulong page = address & ~(ulong)(PageSize - 1); page < end; page += PageSize)
        {
            if (!_pages.ContainsKey(page)) _pages[page] = new byte[PageSize];
        }
    }

    /// <summary>Emit one recorded region per run of contiguous pages.</summary>
    public RecordedMemory Build(string description)
    {
        var builder = new RecordedMemoryBuilder(is64Bit: true, description);

        ulong runStart = 0;
        var run = new List<byte[]>();

        foreach ((ulong pageBase, byte[] page) in _pages)
        {
            if (run.Count > 0 && pageBase != runStart + ((ulong)run.Count * PageSize))
            {
                Flush(builder, runStart, run);
                run.Clear();
            }

            if (run.Count == 0) runStart = pageBase;
            run.Add(page);
        }

        Flush(builder, runStart, run);
        return builder.Build();
    }

    private static void Flush(RecordedMemoryBuilder builder, ulong start, List<byte[]> run)
    {
        if (run.Count == 0) return;

        var block = new byte[run.Count * PageSize];
        for (int i = 0; i < run.Count; i++) run[i].CopyTo(block.AsSpan(i * PageSize));
        builder.Add(start, block);
    }
}
