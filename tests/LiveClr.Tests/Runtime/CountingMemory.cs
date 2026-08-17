namespace LiveClr.Tests.Runtime;

using LiveClr.Memory;

/// <summary>
/// A pass-through <see cref="IMemoryReader"/> that counts the reads reaching the reader
/// underneath it.
/// </summary>
/// <remarks>
/// Placed BELOW a snapshot's page cache, it measures the only thing that distinguishes a cache
/// from a bare reader: the second traversal of the same bytes costs nothing. Identity checks
/// cannot do that job — a snapshot's <c>Memory</c> is wrapped by <c>CountingMemoryReader</c>
/// whether or not a page cache exists, so <c>Assert.NotSame</c> is satisfied either way
/// (§13.11).
/// </remarks>
internal sealed class CountingMemory : IMemoryReader
{
    private readonly IMemoryReader _inner;

    public CountingMemory(IMemoryReader inner) => _inner = inner;

    public bool Is64Bit => _inner.Is64Bit;

    /// <summary>Every read that reached the inner reader, successful or not.</summary>
    public int Reads { get; private set; }

    public bool TryRead(ulong address, Span<byte> buffer)
    {
        Reads++;
        return _inner.TryRead(address, buffer);
    }

    public void Dispose()
    {
        // The inner reader is owned by the fixture.
    }
}
