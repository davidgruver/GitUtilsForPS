# Worker Monitor v1 — Windows PowerShell 5.1

Read-only process, CLR, and system-memory monitor. Run in a **separate 64-bit Windows PowerShell 5.1 process** from the target. Does not restart, kill, or force GC in the target.

## Quick start

1. Start the account-processing script and obtain its PID (inside it: `$PID`; or use `Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" | Select ProcessId,CommandLine`).
2. Open a second 64-bit Windows PowerShell 5.1 console in this folder.
3. Run:

```powershell
.\Start-Monitor.ps1 -ProcessId 12345 -IntervalSeconds 5 -WarningPrivateMB 1500
```

Stop with Ctrl+C. A timestamped CSV is saved in the monitor folder. For a short test:

```powershell
.\Start-Monitor.ps1 -ProcessId 12345 -MaxSamples 60
```

Or import the module directly:

```powershell
Import-Module .\WorkerMonitor.psm1
Get-WorkerProcessMetrics -ProcessId 12345
Get-WorkerGcMetrics -ProcessId 12345
Get-SystemMemoryMetrics
```

## Interpretation

- `PrivateMB`: private committed bytes, **not** the same as RAM usage.
- `WorkingSetMB`: resident physical memory for the process.
- `ManagedHeapMB`: .NET Framework CLR counter `# Bytes in all Heaps`; not total managed allocations, and not the entire private commit.
- `GcCommittedMB`: .NET GC committed memory, when supported by the installed Framework counters.
- `Gen0/1/2Collections`: cumulative counts. Compare differences between samples.
- `GcTimePercent`: initial reading may be 0 and may not be representative because the counter is recreated each sample; use Performance Monitor or a persistent counter session for reliable GC time analysis.
- `SystemCommitPercent`: committed bytes divided by commit limit.
- `SystemPageReadsPerSec`, `SystemPageWritesPerSec`: page-file/storage activity indicators, not direct measures of swap volume.
- `CpuPercent`: share of total logical-processor capacity, not percentage of one CPU core.
- `Warning`: threshold alerts only; **no enforcement**.

## Limitations

- `.NET CLR Memory` is a .NET Framework counter category. CLR instance names are matched to the PID through the category's `Process ID` counter. If unavailable, GC columns remain blank. Run the monitor at comparable privilege to the target process.
- `Get-Counter` names used here assume English Windows performance counter names. On localized Windows, system performance counters may be unavailable; process metrics still work.
- A missing counter is not evidence of zero usage.
- `Win32_OperatingSystem.FreePhysicalMemory` is a system-available-memory approximation. Hypervisor host-side ballooning/swapping requires hypervisor-specific metrics.
- Windows PowerShell 5.1 and its AD module should be monitored with 64-bit PowerShell for best parity.
- The monitor makes repeated CIM/performance counter calls; measure its overhead on the heavily loaded VM before increasing sample frequency.
- PID reuse is possible if the target exits and a new process is created between samples. Use dedicated short-lived monitoring sessions.
