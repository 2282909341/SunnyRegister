# start-all.ps1 - One-click start: PostgreSQL 5433 + SunnyRegister (backend + python-worker)
$ErrorActionPreference = "Continue"

$Root = Split-Path -Parent $PSScriptRoot
$PgCtl = "E:\sunny_tools\pgsql\bin\pg_ctl.exe"
$PgData = "E:\sunny_tools\pgdata"
$PgLog = "E:\sunny_tools\pg.log"

function Test-TcpPort([string]$HostName, [int]$Port) {
  try {
    $client = New-Object System.Net.Sockets.TcpClient
    $async = $client.BeginConnect($HostName, $Port, $null, $null)
    $ok = $async.AsyncWaitHandle.WaitOne(1200)
    if ($ok) { $client.EndConnect($async) }
    $client.Close()
    return [bool]$ok
  } catch { return $false }
}

$pgUp = Test-TcpPort "127.0.0.1" 5433
if (-not $pgUp) {
  Write-Host "[1/3] Starting PostgreSQL on 5433 ..."
  & $PgCtl -D $PgData -l $PgLog -o "-p 5433 -h 127.0.0.1" start
  Start-Sleep -Seconds 4
} else {
  Write-Host "[1/3] PostgreSQL 5433 already running."
}

Write-Host "[2/3] Starting SunnyRegister backend + worker ..."
try {
  & (Join-Path $Root "scripts\start-windows.ps1")
  if ($LASTEXITCODE -ne 0) { throw "start-windows.ps1 exited with code $LASTEXITCODE" }
} catch {
  $errorMessage = $_.Exception.Message
  Write-Host "[3/3] FAILED: $errorMessage" -ForegroundColor Red
  try {
    $logDir = Join-Path $Root "logs"
    New-Item -ItemType Directory -Force -Path $logDir | Out-Null
    [System.IO.File]::WriteAllText(
      (Join-Path $logDir "startup-error.txt"),
      "[$(Get-Date -Format o)] $errorMessage`r`n$($_.ScriptStackTrace)`r`n")
  } catch { }
  try {
    Add-Type -AssemblyName System.Windows.Forms
    [System.Windows.Forms.MessageBox]::Show(
      "SunnyRegister failed to start:`r`n$errorMessage`r`n`r`nSee logs\startup-error.txt for details.",
      "SunnyRegister", "OK", "Error") | Out-Null
  } catch { }
  exit 1
}

Write-Host "[3/3] Opening http://127.0.0.1:8088 ..."
Start-Process "http://127.0.0.1:8088"
exit 0
