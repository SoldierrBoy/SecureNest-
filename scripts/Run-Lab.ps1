$ErrorActionPreference = 'Stop'
Set-Location (Split-Path -Parent $PSScriptRoot)
if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
    Write-Host 'NET 10 SDK not found. Install from https://dotnet.microsoft.com/download/dotnet/10.0' -ForegroundColor Red
    exit 1
}
Write-Host 'Restoring project packages ...' -ForegroundColor Cyan
dotnet restore
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Host 'Compiling project ...' -ForegroundColor Cyan
dotnet build --no-restore
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Host 'Starting https://localhost:7080 ...' -ForegroundColor Green
dotnet run --no-build --launch-profile SecureAccountsLab6
