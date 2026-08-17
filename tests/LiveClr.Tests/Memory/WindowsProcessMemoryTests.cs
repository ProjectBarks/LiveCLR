namespace LiveClr.Tests.Memory;

using System.ComponentModel;
using System.Runtime.InteropServices;
using LiveClr.Memory;

/// <summary>
/// Exercises the real Win32 reader against the test process itself. No game and
/// no fixture required: the test host is a live .NET process with a known
/// address space, which makes it a fair stand-in for everything this layer does.
/// </summary>
public class WindowsProcessMemoryTests
{
    [Fact]
    public void Reads_a_known_pattern_out_of_this_process()
    {
        var pattern = new byte[] { 0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04 };
        var pinned = GCHandle.Alloc(pattern, GCHandleType.Pinned);
        try
        {
            using var memory = WindowsProcessMemory.Open(Environment.ProcessId);
            ulong address = (ulong)pinned.AddrOfPinnedObject();

            var buffer = new byte[pattern.Length];
            Assert.True(memory.TryRead(address, buffer));
            Assert.Equal(pattern, buffer);
        }
        finally
        {
            pinned.Free();
        }
    }

    [Fact]
    public void Bitness_matches_the_host()
    {
        using var memory = WindowsProcessMemory.Open(Environment.ProcessId);
        Assert.Equal(Environment.Is64BitProcess, memory.Is64Bit);
        Assert.Equal(Environment.ProcessId, memory.ProcessId);
    }

    /// <summary>
    /// The §4.8 / §6.4 fail-closed contract against the real API: a read that
    /// runs off the end of a mapped region must report failure and hand back
    /// zeroes, not the readable prefix.
    /// </summary>
    [Fact]
    public void A_read_straddling_the_end_of_mapped_memory_fails_closed()
    {
        using var memory = WindowsProcessMemory.Open(Environment.ProcessId);

        ulong straddle = FindReadableToUnreadableBoundary(memory);
        Assert.NotEqual(0UL, straddle);

        var buffer = new byte[64];
        buffer.AsSpan().Fill(0xCC);

        // Half the read lies in a readable region and half does not.
        // ReadProcessMemory returns ERROR_PARTIAL_COPY having filled the prefix.
        Assert.False(memory.TryRead(straddle, buffer));
        Assert.All(buffer, b => Assert.Equal(0, b));

        // The readable half on its own still works, so the failure above is the
        // boundary and not a bad address.
        Assert.True(memory.TryRead(straddle, buffer.AsSpan(0, 32)));
    }

    [Fact]
    public void Null_and_wraparound_addresses_fail_without_a_syscall()
    {
        using var memory = WindowsProcessMemory.Open(Environment.ProcessId);

        Assert.False(memory.TryRead(0, new byte[8]));
        Assert.False(memory.TryRead(ulong.MaxValue - 3, new byte[8]));
        Assert.True(memory.TryRead(0x1000, Span<byte>.Empty));
    }

    [Fact]
    public void Unmapped_addresses_fail()
    {
        using var memory = WindowsProcessMemory.Open(Environment.ProcessId);

        // The bottom 64 KiB is permanently reserved on Windows, and the top of
        // user space is never mapped.
        Assert.False(memory.TryRead(0x100, new byte[8]));
        Assert.False(memory.TryRead(0x7FFF_FFFF_0000, new byte[8]));
    }

    [Fact]
    public void Enumerates_its_own_modules()
    {
        using var memory = WindowsProcessMemory.Open(Environment.ProcessId);
        var modules = memory.Modules;

        Assert.True(modules.Count > 0);
        Assert.True(modules.TryGet("kernel32", out var kernel32));
        Assert.NotEqual(0UL, kernel32.BaseAddress);
        Assert.True(kernel32.Size > 0);

        // The base address really is the image base: PE images start with "MZ".
        var mz = new byte[2];
        Assert.True(memory.TryRead(kernel32.BaseAddress, mz));
        Assert.Equal(new byte[] { 0x4D, 0x5A }, mz);

        Assert.Same(modules, memory.Modules); // process-tier cache (§8.8)
    }

    [Fact]
    public void The_reader_composes_with_the_page_cache()
    {
        using var memory = WindowsProcessMemory.Open(Environment.ProcessId);
        using var cache = new PageCache(memory);

        var module = memory.Modules["kernel32"];
        var direct = new byte[64];
        var cached = new byte[64];

        Assert.True(memory.TryRead(module.BaseAddress, direct));
        Assert.True(cache.TryRead(module.BaseAddress, cached));
        Assert.Equal(direct, cached);
        Assert.Equal(1L, cache.Misses);

        Assert.True(cache.TryRead(module.BaseAddress + 8, cached.AsSpan(0, 8)));
        Assert.Equal(1L, cache.Misses); // same 4 KiB page
        Assert.Equal(1L, cache.Hits);
    }

    [Fact]
    public void Opening_a_nonexistent_process_throws_rather_than_returning_a_dead_reader()
    {
        // PID 0 is the idle process; it can never be opened for VM read.
        Assert.Throws<Win32Exception>(() => WindowsProcessMemory.Open(0));
        Assert.False(WindowsProcessMemory.TryOpen(0, out var memory));
        Assert.Null(memory);
    }

    /// <summary>
    /// A failed enumeration must not masquerade as "no modules loaded". An empty
    /// table is impossible for a live process, and caching one in the
    /// process-lifetime tier would poison every later lookup with a misleading
    /// "module is not loaded".
    /// </summary>
    [Fact]
    public void A_failed_first_enumeration_throws_every_time_rather_than_caching_emptiness()
    {
        var child = ChildProcess.StartIdle();
        using var memory = WindowsProcessMemory.Open(child.Id);

        // Kill before the first access, so nothing good was ever cached. The
        // handle stays valid; the enumeration does not.
        child.Kill();
        child.Dispose();

        Assert.IsType<Win32Exception>(Record.Exception(() => memory.Modules));

        // Still throwing, i.e. the failure was not cached as an empty table.
        Assert.IsType<Win32Exception>(Record.Exception(() => memory.Modules));
    }

    /// <summary>
    /// A failed <em>refresh</em> keeps the last good table. §8.8 puts module info
    /// in the process tier precisely because it is stable, so a transient failure
    /// should not destroy a working answer — but it must still be reported.
    /// </summary>
    [Fact]
    public void A_failed_refresh_reports_the_failure_and_keeps_the_last_good_table()
    {
        var child = ChildProcess.StartIdle();
        using var memory = WindowsProcessMemory.Open(child.Id);

        var before = memory.Modules;
        Assert.True(before.Count > 0);

        child.Kill();
        child.Dispose();

        Assert.IsType<Win32Exception>(Record.Exception(() => memory.RefreshModules()));
        Assert.Same(before, memory.Modules);
    }

    [Fact]
    public void Failed_reads_expose_the_win32_error_behind_them()
    {
        using var memory = WindowsProcessMemory.Open(Environment.ProcessId);

        var module = memory.Modules["kernel32"];
        Assert.True(memory.TryRead(module.BaseAddress, new byte[8]));
        Assert.Equal(0, memory.LastNativeErrorCode);

        // A straddling read is ERROR_PARTIAL_COPY (299) — the case §4.8's
        // classifier treats as retryable, and the one a generic message hides.
        ulong straddle = FindReadableToUnreadableBoundary(memory);
        Assert.NotEqual(0UL, straddle);
        Assert.False(memory.TryRead(straddle, new byte[64]));
        Assert.Equal(299, memory.LastNativeErrorCode);
        Assert.Contains("Only part of a Read", memory.ReadFailure(straddle, 64).Message);

        // MEASURED, and worth knowing: ReadProcessMemory also reports
        // ERROR_PARTIAL_COPY for a wholly unmapped address, so the Win32 error
        // does NOT separate "torn read" from "bad pointer". Both are retryable
        // as far as §4.8 is concerned; the address-zero rule in §6.4 is what
        // actually carries the never-retry case.
        Assert.False(memory.TryRead(0x100, new byte[8]));
        Assert.Equal(299, memory.LastNativeErrorCode);

        // Rejections made before any syscall are the one case we can label
        // precisely, because no Win32 error exists to misreport.
        Assert.False(memory.TryRead(0, new byte[8]));
        Assert.Equal(998, memory.LastNativeErrorCode);
        Assert.Contains("Invalid access to memory location", memory.ReadFailure(0, 8).Message);
    }

    [Fact]
    public void Use_after_dispose_throws()
    {
        var memory = WindowsProcessMemory.Open(Environment.ProcessId);
        memory.Dispose();
        memory.Dispose(); // idempotent

        Assert.Throws<ObjectDisposedException>(() => { memory.TryRead(0x1000, new byte[4]); });
    }

    /// <summary>
    /// Walks VirtualQueryEx forward for the first readable region immediately
    /// followed by an unreadable one, and returns an address 32 bytes before the
    /// seam. Regions returned by VirtualQueryEx tile the address space with no
    /// gaps, so consecutive queries really are neighbours.
    /// </summary>
    private static ulong FindReadableToUnreadableBoundary(WindowsProcessMemory memory)
    {
        ulong address = 0x10000;
        MemoryRegion previous = default;

        for (int i = 0; i < 20_000; i++)
        {
            if (!memory.TryQueryRegion(address, out var region) || region.Size == 0) break;

            if (previous.IsReadable && !region.IsReadable && previous.Size >= 32)
                return region.BaseAddress - 32;

            ulong next = region.BaseAddress + region.Size;
            if (next <= address) break;

            previous = region;
            address = next;
        }

        return 0;
    }
}
