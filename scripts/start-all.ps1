# start-all.ps1 - One-click start: PostgreSQL 5433 + SunnyRegister (backend + python-worker)
$ErrorActionPreference = "Continue"

$Root = Split-Path -Parent $PSScriptRoot
$PgCtl = "E:\sunny_tools\pgsql\bin\pg_ctl.exe"
$PgData = "E:\sunny_tools\pgdata"
$PgLog = "E:\sunny_tools\pg.log"

$pgUp = $false
try { $pgUp = (Test-NetConnection 127.0.0.1 -Port 5433 -WarningAction SilentlyContinue).TcpTestSucceeded } catch { $pgUp = $false }
if (-not $pgUp) {
  Write-Host "[1/3] Starting PostgreSQL on 5433 ..."
  & $PgCtl -D $PgData -l $PgLog -o "-p 5433 -h 127.0.0.1" start
  Start-Sleep -Seconds 4
} else {
  Write-Host "[1/3] PostgreSQL 5433 already running."
}

Write-Host "[2/3] Starting SunnyRegister backend + worker ..."
& (Join-Path $Root "scripts\start-windows.ps1")
$code = $LASTEXITCODE

if ($code -ne 0) {
  Write-Host "[3/3] FAILED to start SunnyRegister. See logs\backend.err.log / logs\python-worker.err.log"
  exit 1
}

Write-Host "[3/3] Opening http://127.0.0.1:8088 ..."
Start-Process "http://127.0.0.1:8088"
exit 0
