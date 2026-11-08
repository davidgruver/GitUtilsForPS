[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][int]$ProcessId,
    [string]$OutputPath=(Join-Path $PSScriptRoot ('monitor-{0}-{1}.csv' -f $ProcessId,(Get-Date -Format 'yyyyMMdd-HHmmss'))),
    [int]$IntervalSeconds=5,
    [int]$WarningPrivateMB=1500,
    [int]$WarningCommitPercent=85,
    [int]$WarningAvailableMB=2048,
    [int]$MaxSamples=0,
    [switch]$SkipGc,
    [switch]$SkipSystem
)
Import-Module (Join-Path $PSScriptRoot 'WorkerMonitor.psm1') -Force
$monitorParams = @{
    ProcessId = $ProcessId
    OutputPath = $OutputPath
    IntervalSeconds = $IntervalSeconds
    WarningPrivateMB = $WarningPrivateMB
    WarningCommitPercent = $WarningCommitPercent
    WarningAvailableMB = $WarningAvailableMB
    MaxSamples = $MaxSamples
    SkipGc = [bool]$SkipGc
    SkipSystem = [bool]$SkipSystem
}
Start-WorkerMonitoring @monitorParams
