Param(
    [string]$CliPath = "build-windows\bin\Release\dynamic_analysis_cli.exe",
    [string]$TargetPath = "build-windows\bin\Release\openssl_aes_lib_test.exe"
)

$repoRoot = Split-Path -Parent $PSScriptRoot
$cli      = Join-Path $repoRoot $CliPath
$target   = Join-Path $repoRoot $TargetPath
$logsDir  = Join-Path $repoRoot "logs"

if (-not (Test-Path $cli)) {
    Write-Error "dynamic_analysis_cli not found at '$cli'"
    exit 1
}
if (-not (Test-Path $target)) {
    Write-Error "Test binary not found at '$target'"
    exit 1
}

New-Item -ItemType Directory -Force -Path $logsDir | Out-Null

$timestamp   = Get-Date -Format "yyyyMMdd_HHmmss"
$hookedName  = [IO.Path]::GetFileNameWithoutExtension($target)
$logFileName = "$hookedName" + "_$timestamp.ndjson"
$logFile     = Join-Path $logsDir $logFileName

$env:HOOK_VERBOSE = "1"
$env:HOOK_NDJSON  = $logFile

& $cli $target

Write-Host "`n=== Captured Events ($logFileName) ===`n"
if (Test-Path $logFile) {
    Get-Content $logFile
} else {
    Write-Host "No log file generated"
}

Remove-Item Env:HOOK_VERBOSE -ErrorAction SilentlyContinue
Remove-Item Env:HOOK_NDJSON  -ErrorAction SilentlyContinue
