namespace LiveClr.Tests.Memory;

using System.ComponentModel;
using System.Runtime.InteropServices;
using LiveClr.Memory;

/// <summary>
/// PSS is the §8.8 correctness oracle, so its failure modes matter as much as
/// its success path: a snapshot that cannot be captured must say so, never
/// degrade into an incoherent reader that looks like it worked.
/// </summary>
public class PssSnapshotMemoryTests
{
    [Fact]
    public void Capturing_a_nonexistent_process_throws_rather_than_returning_a_dead_reader()
    {
        Assert.Throws<Win32Exception>(() => PssSnapshotMemory.Capture(0));
        Assert.False(PssSnapshotMemory.TryCapture(0, out var snapshot));
        Assert.Null(snapshot);
    }

    /// <summary>
    /// Self-capture is the only target available in CI. If VA cloning is refused
    /// here the test asserts on the refusal instead — an unavailable oracle is a
    /// documented outcome (§8.8), a silently wrong one is not.
    /// </summary>
    [Fact]
    public void A_captured_snapshot_reads_the_same_bytes_as_the_live_process()
    {
        var pattern = new byte[] { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };
        var pinned = GCHandle.Alloc(pattern, GCHandleType.Pinned);
        try
        {
            ulong address = (ulong)pinned.AddrOfPinnedObject();

            PssSnapshotMemory? snapshot = CaptureOrAssertRefusal(Environment.ProcessId);
            if (snapshot is null) return;

            using (snapshot)
            {
                Assert.Equal(Environment.Is64BitProcess, snapshot!.Is64Bit);
                Assert.Equal(Environment.ProcessId, snapshot.ProcessId);

                var buffer = new byte[pattern.Length];
                Assert.True(snapshot.TryRead(address, buffer));
                Assert.Equal(pattern, buffer);

                // The clone is a copy of a moment: mutating the original after
                // capture must not be visible through the snapshot. This is the
                // property that makes it usable as a §12.4e tearing oracle.
                pattern[0] = 0xFF;
                Assert.True(snapshot.TryRead(address, buffer));
                Assert.Equal(0x11, buffer[0]);

                Assert.False(snapshot.TryRead(0, buffer));
                Assert.False(snapshot.TryRead(0x100, buffer));
                Assert.True(snapshot.Modules.Count > 0);
                Assert.True(snapshot.Modules.TryGet("kernel32", out _));
            }

            Assert.Throws<ObjectDisposedException>(() => { snapshot!.TryRead(address, new byte[8]); });
        }
        finally
        {
            pinned.Free();
        }
    }

    /// <summary>
    /// Capture, or — when VA cloning is genuinely unavailable in this environment — assert
    /// that the refusal is the documented one and return null.
    /// </summary>
    /// <remarks>
    /// <b>There is no silent branch.</b> Every test below used to open with
    /// <c>if (!TryCapture(...)) return;</c>, which reports green having checked nothing:
    /// forcing <c>TryCapture</c> to refuse unconditionally left four of five tests passing,
    /// and they guard a bug this class's own remarks say already shipped once. §13.11's rule
    /// is that a check whose output is constant across every input may not be measuring, and
    /// a skip that cannot be told apart from a pass is the same failure wearing a different
    /// hat. So the unavailable case asserts on the refusal — <c>Capture</c> must throw
    /// <see cref="NotSupportedException"/> naming the PSS call that declined — which means a
    /// refusal that is not genuine fails here instead of being waved through.
    /// <para>
    /// xunit 2.x has no runtime <c>Assert.Skip</c>; asserting the refusal is both the stronger
    /// option and the one already used by
    /// <see cref="A_captured_snapshot_reads_the_same_bytes_as_the_live_process"/>.
    /// </para>
    /// </remarks>
    private static PssSnapshotMemory? CaptureOrAssertRefusal(int processId)
    {
        if (PssSnapshotMemory.TryCapture(processId, out PssSnapshotMemory? snapshot)) return snapshot;

        var refusal = Assert.Throws<NotSupportedException>(() => PssSnapshotMemory.Capture(processId));
        Assert.Contains("Pss", refusal.Message, StringComparison.Ordinal);
        Assert.IsType<Win32Exception>(refusal.InnerException);
        return null;
    }

    /// <summary>
    /// The regression test for the <c>PssFreeSnapshot</c> handle bug.
    /// </summary>
    /// <remarks>
    /// It has to run against a <b>separate</b> process. Under self-capture the
    /// target handle and the current-process handle name the same process, the
    /// free succeeds either way, and the bug is invisible — which is precisely
    /// how it shipped. With a real target, passing the target handle returns
    /// ERROR_PARTIAL_COPY and leaves the clone running, once per capture.
    /// </remarks>
    [Fact]
    public void Disposing_a_snapshot_terminates_its_va_clone()
    {
        using var child = ChildProcess.StartIdle();

        PssSnapshotMemory? snapshot = CaptureOrAssertRefusal(child.Id);
        if (snapshot is null) return;

        int clonePid;
        using (snapshot)
        {
            clonePid = snapshot.CloneProcessId;
            Assert.NotEqual(0, clonePid);
            Assert.NotEqual(child.Id, clonePid);
            Assert.True(ChildProcess.IsAlive(clonePid), "the VA clone should exist while the snapshot is held");
        }

        Assert.True(snapshot.ReleasedCleanly, "PssFreeSnapshot must succeed; a non-zero rc means the wrong process handle was passed");
        Assert.True(ChildProcess.WaitUntilGone(clonePid), $"VA clone {clonePid} outlived its snapshot — leaked clone process");
        Assert.True(ChildProcess.IsAlive(child.Id), "the target must survive the snapshot untouched");
    }

    /// <summary>
    /// §8.8 wants PSS benchmarked at 4 Hz. Repeated capture/dispose must not
    /// accumulate clones; ten cycles of the old code left ten zombies.
    /// </summary>
    [Fact]
    public void Repeated_capture_and_dispose_leaks_nothing()
    {
        using var child = ChildProcess.StartIdle();
        var clonePids = new List<int>();

        // Availability is decided ONCE, before the loop. The refusal check used to be inside
        // it, where a failure on iteration 3 abandoned the leak check for three clones that
        // had already been created — and reported success (§13.11). Every later iteration
        // uses the throwing form, so a mid-loop failure is a failure.
        PssSnapshotMemory? first = CaptureOrAssertRefusal(child.Id);
        if (first is null) return;

        for (int i = 0; i < 6; i++)
        {
            PssSnapshotMemory snapshot = i == 0 ? first : PssSnapshotMemory.Capture(child.Id);
            using (snapshot)
            {
                clonePids.Add(snapshot.CloneProcessId);
            }
            Assert.True(snapshot.ReleasedCleanly);
        }

        Assert.Equal(6, clonePids.Count);

        var leaked = clonePids.Where(pid => !ChildProcess.WaitUntilGone(pid)).ToArray();
        Assert.True(leaked.Length == 0, $"leaked {leaked.Length} of {clonePids.Count} VA clones: {string.Join(", ", leaked)}");
        Assert.True(ChildProcess.IsAlive(child.Id));
    }

    /// <summary>
    /// The snapshot is a moment, so its module list is captured with it rather
    /// than enumerated from the live target on first access.
    /// </summary>
    [Fact]
    public void Modules_are_captured_with_the_snapshot_and_outlive_the_target()
    {
        using var child = ChildProcess.StartIdle();

        PssSnapshotMemory? snapshot = CaptureOrAssertRefusal(child.Id);
        if (snapshot is null) return;

        using (snapshot)
        {
            Assert.True(snapshot.Modules.Count > 0);
            Assert.True(snapshot.Modules.TryGet("kernel32", out _));

            // Kill the target: an eagerly captured list still answers.
            child.Kill();
            Assert.True(snapshot.Modules.TryGet("kernel32", out var kernel32));
            Assert.NotEqual(0UL, kernel32.BaseAddress);
        }
    }
}
