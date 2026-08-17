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

            if (!PssSnapshotMemory.TryCapture(Environment.ProcessId, out var snapshot))
            {
                var refusal = Assert.Throws<NotSupportedException>(() => PssSnapshotMemory.Capture(Environment.ProcessId));
                Assert.Contains("PssCaptureSnapshot", refusal.Message);
                Assert.IsType<Win32Exception>(refusal.InnerException);
                return;
            }

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

        if (!PssSnapshotMemory.TryCapture(child.Id, out var snapshot)) return;

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

        for (int i = 0; i < 6; i++)
        {
            if (!PssSnapshotMemory.TryCapture(child.Id, out var snapshot)) return;
            using (snapshot)
            {
                clonePids.Add(snapshot.CloneProcessId);
            }
            Assert.True(snapshot.ReleasedCleanly);
        }

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

        if (!PssSnapshotMemory.TryCapture(child.Id, out var snapshot)) return;

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
