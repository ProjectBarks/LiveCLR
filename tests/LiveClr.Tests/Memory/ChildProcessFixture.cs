namespace LiveClr.Tests.Memory;

using System.Diagnostics;

/// <summary>
/// A short-lived child process to attach to.
/// </summary>
/// <remarks>
/// Testing against a separate process is not optional for this layer. Every
/// distinction between "the target" and "ourselves" collapses under self-capture,
/// which is exactly how the <c>PssFreeSnapshot</c> handle bug survived its first
/// round of tests: passing the target handle is indistinguishable from passing
/// the current-process handle when the target <em>is</em> the current process.
/// </remarks>
internal sealed class ChildProcess : IDisposable
{
    private readonly Process _process;

    private ChildProcess(Process process) => _process = process;

    public int Id => _process.Id;

    public static ChildProcess StartIdle()
    {
        var process = Process.Start(new ProcessStartInfo("powershell.exe", "-NoProfile -Command Start-Sleep 120")
        {
            UseShellExecute = false,
            CreateNoWindow = true,
        })!;

        // Wait for the loader to finish so module enumeration has something to see.
        var deadline = DateTime.UtcNow.AddSeconds(15);
        while (DateTime.UtcNow < deadline)
        {
            try
            {
                process.Refresh();
                if (!process.HasExited && process.Modules.Count > 2) break;
            }
            catch (InvalidOperationException)
            {
                // Modules not readable yet.
            }
            Thread.Sleep(50);
        }

        return new ChildProcess(process);
    }

    public void Kill()
    {
        try
        {
            if (!_process.HasExited)
            {
                _process.Kill();
                _process.WaitForExit(5000);
            }
        }
        catch (InvalidOperationException)
        {
            // Already gone.
        }
    }

    public static bool IsAlive(int processId)
    {
        if (processId == 0) return false;
        try
        {
            return !Process.GetProcessById(processId).HasExited;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    /// <summary>
    /// Waits for a process to disappear. Termination is asynchronous — the
    /// kernel returns from the terminating call before the process object is
    /// gone — so a leak check has to be "gone promptly", not "gone instantly".
    /// </summary>
    public static bool WaitUntilGone(int processId, int timeoutMs = 5000)
    {
        var deadline = DateTime.UtcNow.AddMilliseconds(timeoutMs);
        while (IsAlive(processId))
        {
            if (DateTime.UtcNow > deadline) return false;
            Thread.Sleep(25);
        }
        return true;
    }

    public void Dispose()
    {
        Kill();
        _process.Dispose();
    }
}
