namespace LiveClr.Tests.Fixtures;

using LiveClr.Fixtures;

/// <summary>
/// The fixture provider of analysis doc §8.8. These tests are the ones that must hold for
/// every other test in this project to be runnable without a game attached (§12.4e).
/// </summary>
public class RecordedMemoryTests
{
    private const ulong Base = 0x7ff6_0000_1000;

    [Fact]
    public void Recording_replays_what_the_live_reader_served()
    {
        var payload = FakeTargetMemory.Junk(0x400, seed: 7);
        using var live = new FakeTargetMemory(Base, payload);
        using var recorder = new RecordingMemoryReader(live, "unit test");

        Span<byte> served = stackalloc byte[64];
        Assert.True(recorder.TryRead(Base + 0x100, served));

        var replay = recorder.ToRecordedMemory();
        Span<byte> replayed = stackalloc byte[64];
        Assert.True(replay.TryRead(Base + 0x100, replayed));
        Assert.True(served.SequenceEqual(replayed));
        Assert.True(payload.AsSpan(0x100, 64).SequenceEqual(replayed));
    }

    [Fact]
    public void Unrecorded_addresses_fail_closed()
    {
        var fixture = new RecordedMemoryBuilder()
            .Add(Base, FakeTargetMemory.Junk(0x40, seed: 1))
            .Build();

        var buffer = new byte[8];

        Assert.False(fixture.TryRead(Base - 8, buffer));       // before
        Assert.False(fixture.TryRead(Base + 0x40, buffer));    // after
        Assert.False(fixture.TryRead(Base + 0x3c, buffer));    // straddling the end: partial is failure
        Assert.True(fixture.TryRead(Base + 0x38, buffer));     // last fully-covered read
        Assert.False(fixture.Covers(Base + 0x3c, 8));
    }

    [Fact]
    public void Adjacent_and_overlapping_captures_coalesce_so_a_spanning_read_works()
    {
        var payload = FakeTargetMemory.Junk(0x300, seed: 11);
        using var live = new FakeTargetMemory(Base, payload);
        using var recorder = new RecordingMemoryReader(live, leaveOpen: true);

        // Three separate reads that between them cover [0, 0x180): the replay must serve a
        // single read spanning all three, or a fixture would only replay the exact call
        // sequence that produced it.
        Assert.True(recorder.TryRead(Base, new byte[0x80]));
        Assert.True(recorder.TryRead(Base + 0x80, new byte[0x80]));
        Assert.True(recorder.TryRead(Base + 0x40, new byte[0x140]));

        var replay = recorder.ToRecordedMemory();
        Assert.Equal(1, replay.RegionCount);
        Assert.Equal(0x180, replay.RecordedByteCount);

        var spanning = new byte[0x180];
        Assert.True(replay.TryRead(Base, spanning));
        Assert.True(payload.AsSpan(0, 0x180).SequenceEqual(spanning));
    }

    [Fact]
    public void Failed_reads_are_not_recorded()
    {
        using var live = new FakeTargetMemory(Base, FakeTargetMemory.Junk(0x20, seed: 3));
        using var recorder = new RecordingMemoryReader(live);

        Assert.False(recorder.TryRead(Base + 0x1000, new byte[8]));
        Assert.Equal(1, recorder.FailedReads);
        Assert.Equal(0, recorder.RegionCount);

        // Replay reproduces the failure by omission rather than inventing zeroes.
        Assert.False(recorder.ToRecordedMemory().TryRead(Base + 0x1000, new byte[8]));
    }

    [Fact]
    public void Re_reading_a_mutated_address_keeps_the_latest_bytes()
    {
        using var live = new FakeTargetMemory(Base, FakeTargetMemory.Junk(0x20, seed: 5));
        using var recorder = new RecordingMemoryReader(live);

        Assert.True(recorder.TryRead(Base, new byte[0x20]));
        live.Poke(Base, new byte[] { 0xAA, 0xBB, 0xCC, 0xDD });
        Assert.True(recorder.TryRead(Base, new byte[0x20]));

        var replayed = new byte[4];
        Assert.True(recorder.ToRecordedMemory().TryRead(Base, replayed));
        Assert.Equal(new byte[] { 0xAA, 0xBB, 0xCC, 0xDD }, replayed);
    }

    [Fact]
    public void Round_trips_through_a_stream_byte_for_byte()
    {
        var builder = new RecordedMemoryBuilder(is64Bit: false, description: "sts2 build 1.0, 2026-08-16");
        var expected = new List<(ulong Address, byte[] Bytes)>();

        // Disjoint regions at awkward addresses, including one above 4 GiB and one large enough
        // to catch a chunking bug.
        ulong[] addresses = { 0x1000, 0x2_0000, 0x7ff6_dead_0000, 0xffff_ffff_ffff_0000 };
        for (int i = 0; i < addresses.Length; i++)
        {
            var bytes = FakeTargetMemory.Junk(0x1000 + i * 0x321, seed: 100 + i);
            builder.Add(addresses[i], bytes);
            expected.Add((addresses[i], bytes));
        }

        var original = builder.Build();

        using var stream = new MemoryStream();
        original.Save(stream);
        stream.Position = 0;
        var loaded = RecordedMemory.Load(stream);

        Assert.Equal(original.Is64Bit, loaded.Is64Bit);
        Assert.False(loaded.Is64Bit);
        Assert.Equal("sts2 build 1.0, 2026-08-16", loaded.Description);
        Assert.Equal(original.RegionCount, loaded.RegionCount);
        Assert.Equal(original.RecordedByteCount, loaded.RecordedByteCount);

        foreach (var (address, bytes) in expected)
        {
            var replayed = new byte[bytes.Length];
            Assert.True(loaded.TryRead(address, replayed));
            Assert.Equal(bytes, replayed);
        }

        // And the container itself is stable: saving the loaded copy reproduces the same file.
        using var second = new MemoryStream();
        loaded.Save(second);
        Assert.Equal(stream.ToArray(), second.ToArray());
    }

    [Fact]
    public void Round_trips_through_a_file()
    {
        string path = Path.Combine(Path.GetTempPath(), $"liveclr-{Guid.NewGuid():N}.fixture");
        try
        {
            new RecordedMemoryBuilder(description: "file round-trip")
                .Add(Base, FakeTargetMemory.Junk(0x800, seed: 42))
                .Build()
                .Save(path);

            var loaded = RecordedMemory.Load(path);
            var replayed = new byte[0x800];
            Assert.True(loaded.TryRead(Base, replayed));
            Assert.Equal(FakeTargetMemory.Junk(0x800, seed: 42), replayed);
            Assert.True(loaded.Is64Bit);
        }
        finally
        {
            if (File.Exists(path)) File.Delete(path);
        }
    }

    [Fact]
    public void Rejects_a_file_that_is_not_a_fixture()
    {
        using var junk = new MemoryStream(FakeTargetMemory.Junk(256, seed: 9));
        var ex = Assert.Throws<InvalidDataException>(() => RecordedMemory.Load(junk));
        Assert.Contains("magic", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Rejects_a_truncated_fixture()
    {
        using var stream = new MemoryStream();
        new RecordedMemoryBuilder().Add(Base, FakeTargetMemory.Junk(0x400, seed: 13)).Build().Save(stream);

        // InvalidDataException specifically, not "some exception": end-of-stream, overflow and
        // argument failures from deep in the parser must not escape, or callers end up catching
        // Exception around Load and swallowing real bugs with it.
        var truncated = new MemoryStream(stream.ToArray()[..^0x100]);
        Assert.Throws<InvalidDataException>(() => RecordedMemory.Load(truncated));
    }

    [Fact]
    public void Rejects_a_non_canonical_region_table()
    {
        var a = FakeTargetMemory.Junk(0x40, seed: 61);
        var b = FakeTargetMemory.Junk(0x40, seed: 62);

        // Overlapping. Coalescing on load would accept this and then re-serialise to DIFFERENT
        // bytes, so the encoding would no longer be a function of the content.
        AssertRejected(FixtureFile.Build(new[] { (Base, a), (Base + 0x20, b) }), "canonical");

        // Descending.
        AssertRejected(FixtureFile.Build(new[] { (Base + 0x100, a), (Base, b) }), "canonical");

        // Exactly adjacent: the writer always merges these, so their presence means "not ours".
        AssertRejected(FixtureFile.Build(new[] { (Base, a), (Base + 0x40, b) }), "canonical");

        // Duplicate address.
        AssertRejected(FixtureFile.Build(new[] { (Base, a), (Base, b) }), "canonical");
    }

    [Fact]
    public void Rejects_a_header_that_disagrees_with_its_contents()
    {
        var region = new[] { (Base, FakeTargetMemory.Junk(0x40, seed: 63)) };

        AssertRejected(FixtureFile.Build(region, totalBytesOverride: 0x41), "disagrees");
        AssertRejected(FixtureFile.Build(region, totalBytesOverride: -1), "Negative byte count");
        AssertRejected(FixtureFile.Build(region, regionCountOverride: 2), "malformed");
        AssertRejected(FixtureFile.Build(region, regionCountOverride: -1), "Negative region count");
    }

    [Fact]
    public void Rejects_unknown_header_flags()
    {
        var region = new[] { (Base, FakeTargetMemory.Junk(0x10, seed: 64)) };
        AssertRejected(FixtureFile.Build(region, flags: 0b1101), "unknown header flags");
    }

    [Fact]
    public void Rejects_a_region_that_wraps_the_address_space()
    {
        var region = new[] { (ulong.MaxValue - 4, FakeTargetMemory.Junk(0x20, seed: 65)) };
        AssertRejected(FixtureFile.Build(region), "wraps");
    }

    [Fact]
    public void Zero_length_reads_succeed_anywhere()
    {
        // Pinned deliberately: nothing was requested, so nothing is invented. The alternative
        // (false) would make an empty read look like a mapping failure.
        var fixture = new RecordedMemoryBuilder().Add(Base, new byte[16]).Build();

        Assert.True(fixture.TryRead(Base, Span<byte>.Empty));
        Assert.True(fixture.TryRead(Base + 0xdead_0000, Span<byte>.Empty));
        Assert.True(fixture.Covers(Base + 0xdead_0000, 0));
        Assert.False(fixture.Covers(Base, -1));
    }

    [Fact]
    public void Reads_at_the_end_of_the_address_space_fail_closed()
    {
        // The region ends AT ulong.MaxValue: one byte further would need an unrepresentable end.
        var fixture = new RecordedMemoryBuilder().Add(ulong.MaxValue - 0x20, new byte[0x20]).Build();

        Assert.True(fixture.TryRead(ulong.MaxValue - 8, new byte[8]));   // last 8 bytes, exactly
        Assert.False(fixture.TryRead(ulong.MaxValue - 3, new byte[8]));  // would wrap
        Assert.False(fixture.Covers(ulong.MaxValue, 2));
        Assert.Throws<ArgumentException>(
            () => new RecordedMemoryBuilder().Add(ulong.MaxValue - 4, new byte[8]));
    }

    [Fact]
    public void Using_a_disposed_recorder_throws()
    {
        var recorder = new RecordingMemoryReader(new FakeTargetMemory(Base, new byte[16]));
        recorder.Dispose();

        Assert.Throws<ObjectDisposedException>(() => recorder.TryRead(Base, new byte[8]));
        Assert.Throws<ObjectDisposedException>(() => recorder.ToRecordedMemory());
        Assert.Throws<ObjectDisposedException>(() => recorder.Save(new MemoryStream()));
    }

    [Fact]
    public void Sequential_page_capture_coalesces_into_one_region()
    {
        // How a page cache actually fills (§4.7). Merging by reallocate-and-copy each time is
        // O(n^2) in the region size, and a module blob is megabytes (§7b.3).
        const int pageSize = 0x1000;
        const int pages = 512;

        var image = FakeTargetMemory.Junk(pageSize * pages, seed: 71);
        using var live = new FakeTargetMemory(Base, image);
        using var recorder = new RecordingMemoryReader(live, leaveOpen: true);

        for (int i = 0; i < pages; i++)
            Assert.True(recorder.TryRead(Base + (ulong)(i * pageSize), new byte[pageSize]));

        Assert.Equal(1, recorder.RegionCount);
        Assert.Equal(pageSize * pages, recorder.RecordedByteCount);

        var replayed = new byte[pageSize * pages];
        Assert.True(recorder.ToRecordedMemory().TryRead(Base, replayed));
        Assert.Equal(image, replayed);
    }

    private static void AssertRejected(byte[] file, string expectedInMessage)
    {
        var ex = Assert.Throws<InvalidDataException>(() => RecordedMemory.Load(new MemoryStream(file)));
        Assert.Contains(expectedInMessage, ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Rejects_a_future_format_version()
    {
        using var stream = new MemoryStream();
        new RecordedMemoryBuilder().Add(Base, new byte[16]).Build().Save(stream);

        var bytes = stream.ToArray();
        bytes[8] = 99; // version field, immediately after the 8-byte magic
        var ex = Assert.Throws<InvalidDataException>(() => RecordedMemory.Load(new MemoryStream(bytes)));
        Assert.Contains("99", ex.Message);
    }

    [Fact]
    public void Decorator_owns_the_inner_reader_unless_told_otherwise()
    {
        var owned = new FakeTargetMemory(Base, new byte[16]);
        new RecordingMemoryReader(owned).Dispose();
        Assert.True(owned.Disposed);

        var borrowed = new FakeTargetMemory(Base, new byte[16]);
        new RecordingMemoryReader(borrowed, leaveOpen: true).Dispose();
        Assert.False(borrowed.Disposed);
    }

    [Fact]
    public void Pointer_width_of_the_target_survives_replay()
    {
        using var live32 = new FakeTargetMemory(Base, new byte[16], is64Bit: false);
        using var recorder = new RecordingMemoryReader(live32);
        Assert.False(recorder.Is64Bit);
        Assert.False(recorder.ToRecordedMemory().Is64Bit);
    }
}
