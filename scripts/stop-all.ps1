# stop-all.ps1 - One-click stop: SunnyRegister (backend + python-worker) + PostgreSQL 5433
$ErrorActionPreference = "Continue"

$Root = Split-Path -Parent $PSScriptRoot

Write-Host "[1/2] Stopping SunnyRegister backend + worker ..."
& (Join-Path $Root "scripts\stop-windows.ps1")

$PgCtl = "E:\sunny_tools\pgsql\bin\pg_ctl.exe"
$PgData = "E:\sunny_tools\pgdata"
$pgUp = $false
try { $pgUp = (Test-NetConnection 127.0.0.1 -Port 5433 -WarningAction SilentlyContinue).TcpTestSucceeded } catch { $pgUp = $false }
if ($pgUp) {
  Write-Host "[2/2] Stopping PostgreSQL 5433 ..."
  & $PgCtl -D $PgData stop -m fast
} else {
  Write-Host "[2/2] PostgreSQL 5433 not running, skip."
}
exit 0
