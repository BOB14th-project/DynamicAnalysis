# Windows hooking test script
$env:HOOK_NDJSON = "D:\git\DynamicAnalysis\logs\windows_test.ndjson"
$env:HOOK_VERBOSE = "1"

# Create logs directory if it doesn't exist
New-Item -ItemType Directory -Force -Path logs | Out-Null

# Run the test
.\build-windows\bin\Release\dynamic_analysis_cli.exe .\build-windows\bin\Release\openssl_aes_lib_test.exe

# Show results
Write-Host "`n=== Captured Events ===`n"
if (Test-Path $env:HOOK_NDJSON) {
    Get-Content $env:HOOK_NDJSON
} else {
    Write-Host "No log file generated"
}
