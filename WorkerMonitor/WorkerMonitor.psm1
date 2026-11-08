Set-StrictMode -Version 2.0

function Get-WorkerProcessMetrics {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][int]$ProcessId)
    $p = [System.Diagnostics.Process]::GetProcessById($ProcessId)
    try {
        $p.Refresh()
        [pscustomobject]@{
            ProcessId=$p.Id; ProcessName=$p.ProcessName
            PrivateMB=[math]::Round($p.PrivateMemorySize64 / 1MB,2)
            WorkingSetMB=[math]::Round($p.WorkingSet64 / 1MB,2)
            VirtualMB=[math]::Round($p.VirtualMemorySize64 / 1MB,2)
            PagedMB=[math]::Round($p.PagedMemorySize64 / 1MB,2)
            UserCpuSeconds=$p.UserProcessorTime.TotalSeconds
            KernelCpuSeconds=$p.PrivilegedProcessorTime.TotalSeconds
            TotalCpuSeconds=$p.TotalProcessorTime.TotalSeconds
            ThreadCount=$p.Threads.Count; HandleCount=$p.HandleCount
        }
    } finally { $p.Dispose() }
}

function Get-SystemMemoryMetrics {
    [CmdletBinding()]
    param()
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $total = [double]$os.TotalVisibleMemorySize * 1KB
    $free = [double]$os.FreePhysicalMemory * 1KB
    $result = [ordered]@{
        SystemTotalPhysicalMB=[math]::Round($total/1MB,2)
        SystemAvailableMB=[math]::Round($free/1MB,2)
        SystemPhysicalUsedPercent=if($total -gt 0){[math]::Round((1-$free/$total)*100,2)}else{$null}
        SystemCommittedMB=$null
        SystemCommitLimitMB=$null
        SystemCommitPercent=$null
        SystemPageReadsPerSec=$null
        SystemPageWritesPerSec=$null
    }
    try {
        $samples = (Get-Counter -Counter @('\Memory\Committed Bytes','\Memory\Commit Limit','\Memory\Page Reads/sec','\Memory\Page Writes/sec') -ErrorAction Stop).CounterSamples
        $map = @{}
        foreach($s in $samples){ $map[$s.Path.Substring($s.Path.LastIndexOf('\')+1).ToLowerInvariant()] = [double]$s.CookedValue }
        if($map.ContainsKey('committed bytes')){$result.SystemCommittedMB=[math]::Round($map['committed bytes']/1MB,2)}
        if($map.ContainsKey('commit limit')){$result.SystemCommitLimitMB=[math]::Round($map['commit limit']/1MB,2)}
        if($result.SystemCommitLimitMB -gt 0){$result.SystemCommitPercent=[math]::Round(100*$result.SystemCommittedMB/$result.SystemCommitLimitMB,2)}
        if($map.ContainsKey('page reads/sec')){$result.SystemPageReadsPerSec=[math]::Round($map['page reads/sec'],2)}
        if($map.ContainsKey('page writes/sec')){$result.SystemPageWritesPerSec=[math]::Round($map['page writes/sec'],2)}
    } catch { Write-Verbose "System performance counters unavailable: $($_.Exception.Message)" }
    [pscustomobject]$result
}

function Get-WorkerGcMetrics {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][int]$ProcessId)
    $result = [ordered]@{
        GcInstance=$null; ManagedHeapMB=$null; GcCommittedMB=$null; Gen0Collections=$null
        Gen1Collections=$null; Gen2Collections=$null; GcTimePercent=$null
        LargeObjectHeapMB=$null; GcHandles=$null; PinnedObjects=$null
    }
    try {
        $category = New-Object System.Diagnostics.PerformanceCounterCategory('.NET CLR Memory')
        foreach($instance in $category.GetInstanceNames()) {
            $idCounter = $null
            try {
                $idCounter = New-Object System.Diagnostics.PerformanceCounter('.NET CLR Memory','Process ID',$instance,$true)
                if([int]$idCounter.RawValue -ne $ProcessId){ continue }
                $result.GcInstance = $instance
                $counterNames = @{
                    '# Bytes in all Heaps'='ManagedHeapMB'; '# Total committed Bytes'='GcCommittedMB'
                    '# Gen 0 Collections'='Gen0Collections'; '# Gen 1 Collections'='Gen1Collections'
                    '# Gen 2 Collections'='Gen2Collections'; '% Time in GC'='GcTimePercent'
                    'Large Object Heap size'='LargeObjectHeapMB'; '# GC Handles'='GcHandles'
                    '# of Pinned Objects'='PinnedObjects'
                }
                foreach($name in $counterNames.Keys){
                    $c=$null
                    try {
                        $c=New-Object System.Diagnostics.PerformanceCounter('.NET CLR Memory',$name,$instance,$true)
                        # % Time in GC is sampled; NextValue may be zero for the first sample.
                        $value=if($name -eq '% Time in GC'){$c.NextValue()}else{[double]$c.RawValue}
                        if($name -in @('# Bytes in all Heaps','# Total committed Bytes','Large Object Heap size')){$value=[math]::Round($value/1MB,2)}
                        elseif($name -eq '% Time in GC'){$value=[math]::Round($value,2)}
                        $result[$counterNames[$name]]=$value
                    } catch { Write-Verbose "CLR counter '$name' unavailable: $($_.Exception.Message)" }
                    finally {if($null -ne $c){$c.Dispose()}}
                }
                break
            } catch { Write-Verbose "CLR instance '$instance' unavailable: $($_.Exception.Message)" }
            finally {if($null -ne $idCounter){$idCounter.Dispose()}}
        }
    } catch { Write-Verbose "CLR performance counter category unavailable: $($_.Exception.Message)" }
    [pscustomobject]$result
}

function Start-WorkerMonitoring {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][int]$ProcessId,
        [Parameter(Mandatory=$true)][string]$OutputPath,
        [ValidateRange(1,3600)][int]$IntervalSeconds=5,
        [ValidateRange(0,2147483647)][int]$WarningPrivateMB=1500,
        [ValidateRange(0,100)][int]$WarningCommitPercent=85,
        [ValidateRange(0,2147483647)][int]$WarningAvailableMB=2048,
        [ValidateRange(0,2147483647)][int]$MaxSamples=0,
        [switch]$SkipGc,
        [switch]$SkipSystem
    )
    $parent=Split-Path -Parent $OutputPath
    if($parent -and -not (Test-Path -LiteralPath $parent)){New-Item -ItemType Directory -Path $parent -Force | Out-Null}
    $previous=$null
    $count=0
    $logicalProcessors=[Environment]::ProcessorCount
    while($true){
        $started=Get-Date
        try { $process=Get-WorkerProcessMetrics -ProcessId $ProcessId }
        catch [System.ArgumentException] { Write-Warning "Process $ProcessId has exited. Stopping monitor."; break }
        catch { Write-Warning "Unable to read process $ProcessId`: $($_.Exception.Message)"; break }
        $gc=if($SkipGc){$null}else{Get-WorkerGcMetrics -ProcessId $ProcessId}
        $system=if($SkipSystem){$null}else{Get-SystemMemoryMetrics}
        $elapsed=if($null -ne $previous){($started-$previous.Timestamp).TotalSeconds}else{0}
        $cpuPercent=$null
        $privateGrowthMBPerMin=$null
        if($elapsed -gt 0){
            $cpuPercent=[math]::Round(100*($process.TotalCpuSeconds-$previous.TotalCpuSeconds)/($elapsed*$logicalProcessors),2)
            $privateGrowthMBPerMin=[math]::Round(60*($process.PrivateMB-$previous.PrivateMB)/$elapsed,2)
        }
        $warnings=New-Object 'System.Collections.Generic.List[string]'
        if($WarningPrivateMB -gt 0 -and $process.PrivateMB -ge $WarningPrivateMB){$warnings.Add('PrivateMemory')}
        if($null -ne $system){
            if($WarningCommitPercent -gt 0 -and $null -ne $system.SystemCommitPercent -and $system.SystemCommitPercent -ge $WarningCommitPercent){$warnings.Add('SystemCommit')}
            if($WarningAvailableMB -gt 0 -and $system.SystemAvailableMB -le $WarningAvailableMB){$warnings.Add('LowAvailableRAM')}
        }
        $row=[ordered]@{Timestamp=$started.ToString('o'); ProcessId=$ProcessId; ProcessName=$process.ProcessName
            PrivateMB=$process.PrivateMB; WorkingSetMB=$process.WorkingSetMB; VirtualMB=$process.VirtualMB; PagedMB=$process.PagedMB
            PrivateGrowthMBPerMin=$privateGrowthMBPerMin; CpuPercent=$cpuPercent
            UserCpuSeconds=$process.UserCpuSeconds; KernelCpuSeconds=$process.KernelCpuSeconds; TotalCpuSeconds=$process.TotalCpuSeconds
            ThreadCount=$process.ThreadCount; HandleCount=$process.HandleCount
            GcInstance=if($gc){$gc.GcInstance}else{$null}
            ManagedHeapMB=if($gc){$gc.ManagedHeapMB}else{$null}
            GcCommittedMB=if($gc){$gc.GcCommittedMB}else{$null}
            Gen0Collections=if($gc){$gc.Gen0Collections}else{$null}
            Gen1Collections=if($gc){$gc.Gen1Collections}else{$null}
            Gen2Collections=if($gc){$gc.Gen2Collections}else{$null}
            GcTimePercent=if($gc){$gc.GcTimePercent}else{$null}
            LargeObjectHeapMB=if($gc){$gc.LargeObjectHeapMB}else{$null}
            GcHandles=if($gc){$gc.GcHandles}else{$null}
            PinnedObjects=if($gc){$gc.PinnedObjects}else{$null}
            SystemTotalPhysicalMB=if($system){$system.SystemTotalPhysicalMB}else{$null}
            SystemAvailableMB=if($system){$system.SystemAvailableMB}else{$null}
            SystemPhysicalUsedPercent=if($system){$system.SystemPhysicalUsedPercent}else{$null}
            SystemCommittedMB=if($system){$system.SystemCommittedMB}else{$null}
            SystemCommitLimitMB=if($system){$system.SystemCommitLimitMB}else{$null}
            SystemCommitPercent=if($system){$system.SystemCommitPercent}else{$null}
            SystemPageReadsPerSec=if($system){$system.SystemPageReadsPerSec}else{$null}
            SystemPageWritesPerSec=if($system){$system.SystemPageWritesPerSec}else{$null}
            Warning=($warnings -join ';')
        }
        [pscustomobject]$row | Export-Csv -LiteralPath $OutputPath -Append -NoTypeInformation -Encoding UTF8
        $count++
        Write-Host ("{0:HH:mm:ss} PID={1} Private={2}MB Heap={3}MB Available={4}MB CPU={5}% {6}" -f $started,$ProcessId,$process.PrivateMB,$row.ManagedHeapMB,$row.SystemAvailableMB,$cpuPercent,$row.Warning)
        $previous=[pscustomobject]@{Timestamp=$started; TotalCpuSeconds=$process.TotalCpuSeconds; PrivateMB=$process.PrivateMB}
        if($MaxSamples -gt 0 -and $count -ge $MaxSamples){break}
        $wait=[math]::Max(0,$IntervalSeconds-((Get-Date)-$started).TotalSeconds)
        if($wait -gt 0){Start-Sleep -Milliseconds ([int]($wait*1000))}
    }
}
Export-ModuleMember -Function Get-WorkerProcessMetrics,Get-WorkerGcMetrics,Get-SystemMemoryMetrics,Start-WorkerMonitoring
