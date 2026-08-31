$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$RuntimeDir = Join-Path $Root ".runtime"
$LogDir = Join-Path $Root "logs"
$DataDir = Join-Path $Root "data"
$BackendExe = Join-Path $Root "bin\SunnyRegister.exe"
$WorkerPython = Join-Path $Root "python-worker\.venv\Scripts\python.exe"
$EnvFile = Join-Path $Root ".env"

if (-not (Test-Path -LiteralPath $EnvFile)) {
  Copy-Item -LiteralPath (Join-Path $Root ".env.example") -Destination $EnvFile
}
foreach ($line in [System.IO.File]::ReadAllLines($EnvFile)) {
  $value = $line.Trim()
  if (-not $value -or $value.StartsWith("#") -or -not $value.Contains("=")) { continue }
  $separator = $value.IndexOf("=")
  $key = $value.Substring(0, $separator).Trim()
  $setting = $value.Substring($separator + 1).Trim().Trim('"', "'")
  if ($key -and -not [Environment]::GetEnvironmentVariable($key, "Process")) {
    [Environment]::SetEnvironmentVariable($key, $setting, "Process")
  }
}

$env:PORT = if ($env:SUNNYREGISTER_PORT) { $env:SUNNYREGISTER_PORT } else { "8000" }

function Test-RunningPid([string]$File) {
  if (-not (Test-Path -LiteralPath $File)) { return $false }
  $value = [System.IO.File]::ReadAllText($File).Trim()
  if ($value -notmatch '^\d+$') { return $false }
  return $null -ne (Get-Process -Id ([int]$value) -ErrorAction SilentlyContinue)
}

$workerPidFile = Join-Path $RuntimeDir "python-worker.pid"
$backendPidFile = Join-Path $RuntimeDir "backend.pid"
if (Test-RunningPid $workerPidFile -or Test-RunningPid $backendPidFile) {
  $readyUrl = "http://127.0.0.1:$($env:PORT)/api/ready"
  $healthy = $false
  try {
    $response = Invoke-WebRequest -UseBasicParsing -Uri $readyUrl -TimeoutSec 3
    $healthy = $response.StatusCode -eq 200
  } catch { $healthy = $false }
  if ($healthy) {
    Write-Host "SunnyRegister is already running and healthy: http://127.0.0.1:$($env:PORT)" -ForegroundColor Green
    exit 0
  }
  throw "SunnyRegister appears to be running but is not healthy. Run scripts\stop-windows.ps1 first, then retry."
}

if (-not (Test-Path -LiteralPath $BackendExe) -or -not (Test-Path -LiteralPath $WorkerPython)) {
  & (Join-Path $PSScriptRoot "setup-windows.ps1")
}

function Get-NewestWriteTime([string[]]$Paths) {
  $latest = [DateTime]::MinValue
  foreach ($path in $Paths) {
    if (-not (Test-Path -LiteralPath $path)) { continue }
    $item = Get-Item -LiteralPath $path
    if ($item.PSIsContainer) {
      $files = Get-ChildItem -LiteralPath $path -Recurse -File
      foreach ($file in $files) {
        if ($file.LastWriteTimeUtc -gt $latest) { $latest = $file.LastWriteTimeUtc }
      }
    } elseif ($item.LastWriteTimeUtc -gt $latest) {
      $latest = $item.LastWriteTimeUtc
    }
  }
  return $latest
}

# Keep native starts in sync with source changes. This prevents a stale backend
# executable from serving an older authentication contract after the UI rebuilds.
$frontendStamp = Join-Path $Root "backend\static\index.html"
$frontendSources = @(
  (Join-Path $Root "frontend\src"),
  (Join-Path $Root "frontend\package.json"),
  (Join-Path $Root "frontend\package-lock.json"),
  (Join-Path $Root "frontend\vite.config.ts")
)
if (-not (Test-Path -LiteralPath $frontendStamp) -or
    (Get-NewestWriteTime $frontendSources) -gt (Get-Item -LiteralPath $frontendStamp).LastWriteTimeUtc) {
  Write-Host "Building frontend (npm run build, first start can take a few minutes) ..." -ForegroundColor Cyan
  Push-Location (Join-Path $Root "frontend")
  try {
    # Capture stderr (vite warnings) so PS 5.1 + ErrorActionPreference=Stop
    # does not treat native stderr as a terminating NativeCommandError.
    $buildOutput = & npm run build 2>&1
    $buildExit = $LASTEXITCODE
    $buildOutput | Out-Host
    if ($buildExit -ne 0) { throw "frontend build failed (exit $buildExit)" }
  } finally {
    Pop-Location
  }
}

$backendSources = @(
  (Join-Path $Root "backend"),
  (Join-Path $Root "go.work")
)
if ((Get-NewestWriteTime $backendSources) -gt (Get-Item -LiteralPath $BackendExe).LastWriteTimeUtc) {
  Write-Host "Building backend (go build) ..." -ForegroundColor Cyan
  Push-Location (Join-Path $Root "backend")
  try {
    $goOutput = & go build -trimpath -ldflags="-s -w" -o $BackendExe . 2>&1
    $goExit = $LASTEXITCODE
    $goOutput | Out-Host
    if ($goExit -ne 0) { throw "Go build failed (exit $goExit)" }
  } finally {
    Pop-Location
  }
}
try {
  & $WorkerPython -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 12) else 1)" *> $null
  if ($LASTEXITCODE -ne 0) { throw "invalid worker venv" }
} catch {
  & (Join-Path $PSScriptRoot "setup-python-worker.ps1") -Force
}

New-Item -ItemType Directory -Force -Path $RuntimeDir, $LogDir, $DataDir | Out-Null

$env:PYTHONUTF8 = "1"
if (-not $env:DATABASE_URL) {
  throw "DATABASE_URL is required. Configure PostgreSQL in .env before starting SunnyRegister."
}
$env:PYTHON_WORKER_URL = "http://127.0.0.1:8765"
$env:PYTHON_TASK_TYPES = "sunny_register,sunny_login,sunny_refresh_session,sunny_acquire_rt,sunny_rebind"
$env:TZ = if ($env:TZ) { $env:TZ } else { "Asia/Shanghai" }
$env:SUNNY_TIMEZONE = $env:TZ
$env:SUNNY_HEALTHCHECK_ENABLED = if ($env:SUNNY_HEALTHCHECK_ENABLED) { $env:SUNNY_HEALTHCHECK_ENABLED } else { "true" }
$env:SUNNY_HEALTHCHECK_TIME = if ($env:SUNNY_HEALTHCHECK_TIME) { $env:SUNNY_HEALTHCHECK_TIME } else { "06:00" }
$env:SUNNY_HEALTHCHECK_CONCURRENCY = if ($env:SUNNY_HEALTHCHECK_CONCURRENCY) { $env:SUNNY_HEALTHCHECK_CONCURRENCY } else { "2" }

Write-Host "Starting python worker (127.0.0.1:8765) ..." -ForegroundColor Cyan
$worker = Start-Process -FilePath $WorkerPython `
  -ArgumentList @("-m", "uvicorn", "worker:app", "--host", "127.0.0.1", "--port", "8765") `
  -WorkingDirectory (Join-Path $Root "python-worker") `
  -RedirectStandardOutput (Join-Path $LogDir "python-worker.out.log") `
  -RedirectStandardError (Join-Path $LogDir "python-worker.err.log") `
  -WindowStyle Hidden -PassThru
[System.IO.File]::WriteAllText($workerPidFile, [string]$worker.Id)

$workerReady = $false
for ($i = 0; $i -lt 60; $i++) {
  if ($worker.HasExited) { break }
  try {
    $response = Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:8765/health" -TimeoutSec 2
    if ($response.StatusCode -eq 200) { $workerReady = $true; break }
  } catch { Start-Sleep -Seconds 1 }
}
if (-not $workerReady) {
  & (Join-Path $PSScriptRoot "stop-windows.ps1")
  throw "Python Worker failed to become ready. Check logs\python-worker.err.log."
}

Write-Host "Starting backend (http://127.0.0.1:$($env:PORT)) ..." -ForegroundColor Cyan
$backend = Start-Process -FilePath $BackendExe `
  -WorkingDirectory $Root `
  -RedirectStandardOutput (Join-Path $LogDir "backend.out.log") `
  -RedirectStandardError (Join-Path $LogDir "backend.err.log") `
  -WindowStyle Hidden -PassThru
[System.IO.File]::WriteAllText($backendPidFile, [string]$backend.Id)

$readyUrl = "http://127.0.0.1:$($env:PORT)/api/ready"
$ready = $false
for ($i = 0; $i -lt 60; $i++) {
  try {
    $response = Invoke-WebRequest -UseBasicParsing -Uri $readyUrl -TimeoutSec 2
    if ($response.StatusCode -eq 200) { $ready = $true; break }
  } catch { Start-Sleep -Seconds 1 }
}
if (-not $ready) {
  & (Join-Path $PSScriptRoot "stop-windows.ps1")
  throw "SunnyRegister failed to become ready. Check logs\backend.err.log and logs\python-worker.err.log."
}

$passwordFile = if ($env:ADMIN_PASSWORD_FILE) { $env:ADMIN_PASSWORD_FILE } else { Join-Path $DataDir "admin_password.txt" }
Write-Host "SunnyRegister is ready: http://127.0.0.1:$($env:PORT)" -ForegroundColor Green
$username = if ($env:ADMIN_USERNAME) { $env:ADMIN_USERNAME } else { "admin" }
Write-Host "Username: $username"
Write-Host "Password: stored in $passwordFile or ADMIN_PASSWORD; it is not printed for security"
Write-Host "Logs: $LogDir"
