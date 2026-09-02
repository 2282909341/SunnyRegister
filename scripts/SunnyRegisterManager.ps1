param(
    [ValidateSet("Gui", "Start", "Stop", "Restart", "Status")]
    [string]$Action = "Gui"
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
$RuntimeDir = Join-Path $RepoRoot ".runtime"

function Test-Http([string]$Url) {
    try { return (Invoke-WebRequest -UseBasicParsing -Uri $Url -TimeoutSec 3).StatusCode -eq 200 } catch { return $false }
}

function Test-Port([int]$Port) {
    $client = New-Object Net.Sockets.TcpClient
    try { $client.Connect("127.0.0.1", $Port); return $true } catch { return $false } finally { $client.Dispose() }
}

function Read-Pid([string]$Name) {
    $path = Join-Path $RuntimeDir $Name
    if (Test-Path -LiteralPath $path) { return ([IO.File]::ReadAllText($path)).Trim() }
    return "-"
}

function Get-ServiceState {
    [pscustomobject]@{
        Backend = Test-Http "http://127.0.0.1:8088/api/ready"
        Worker = Test-Http "http://127.0.0.1:8765/health"
        Database = Test-Port 5433
        BackendPid = Read-Pid "backend.pid"
        WorkerPid = Read-Pid "python-worker.pid"
    }
}

function Format-ServiceState($State) {
    $backend = if ($State.Backend) { "运行中" } else { "已停止" }
    $worker = if ($State.Worker) { "运行中" } else { "已停止" }
    $database = if ($State.Database) { "运行中" } else { "已停止" }
    return "后台服务：$backend（PID $($State.BackendPid)）`r`nPython Worker：$worker（PID $($State.WorkerPid)）`r`nPostgreSQL：$database（端口 5433）"
}

function Stop-TrackedTrees {
    foreach ($name in @("backend.pid", "python-worker.pid")) {
        $pidText = Read-Pid $name
        if ($pidText -match "^\d+$") { & taskkill.exe /PID $pidText /T /F *> $null }
    }
}

function Invoke-ExistingScript([string]$Name) {
    $scriptPath = Join-Path $PSScriptRoot $Name
    $arguments = '-NoProfile -ExecutionPolicy Bypass -File "' + $scriptPath + '"'
    Start-Process -FilePath "powershell.exe" -ArgumentList $arguments -WorkingDirectory $RepoRoot -WindowStyle Hidden | Out-Null
}

function Wait-ServiceState([bool]$ShouldRun, [int]$TimeoutSeconds) {
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        Start-Sleep -Seconds 2
        $state = Get-ServiceState
        $allRunning = $state.Backend -and $state.Worker -and $state.Database
        $allStopped = -not $state.Backend -and -not $state.Worker -and -not $state.Database
        if (($ShouldRun -and $allRunning) -or (-not $ShouldRun -and $allStopped)) { return $state }
    } while ((Get-Date) -lt $deadline)
    throw "等待服务状态超时。`r`n$(Format-ServiceState $state)"
}

function Invoke-ManagerAction([string]$RequestedAction) {
    switch ($RequestedAction) {
        "Start" { Invoke-ExistingScript "start-all.ps1"; return Wait-ServiceState $true 240 }
        "Stop" { Stop-TrackedTrees; Invoke-ExistingScript "stop-all.ps1"; return Wait-ServiceState $false 90 }
        "Restart" {
            Stop-TrackedTrees
            Invoke-ExistingScript "stop-all.ps1"
            [void](Wait-ServiceState $false 90)
            Invoke-ExistingScript "start-all.ps1"
            return Wait-ServiceState $true 240
        }
        "Status" { return Get-ServiceState }
    }
}

if ($Action -ne "Gui") {
    try {
        $state = Invoke-ManagerAction $Action
        Write-Output "ACTION=$Action"
        Write-Output (Format-ServiceState $state)
        Write-Output "RESULT=OK"
        exit 0
    } catch {
        Write-Output "ACTION=$Action"
        Write-Output "RESULT=ERROR"
        Write-Output $_.Exception.Message
        exit 1
    }
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[Windows.Forms.Application]::EnableVisualStyles()

$form = New-Object Windows.Forms.Form
$form.Text = "SunnyRegister 管理器"
$form.Size = New-Object Drawing.Size(570, 340)
$form.StartPosition = "CenterScreen"
$form.FormBorderStyle = "FixedDialog"
$form.MaximizeBox = $false
$form.Font = New-Object Drawing.Font("Microsoft YaHei UI", 10)

$title = New-Object Windows.Forms.Label
$title.Text = "SunnyRegister 服务管理"
$title.Font = New-Object Drawing.Font("Microsoft YaHei UI", 16, [Drawing.FontStyle]::Bold)
$title.Location = New-Object Drawing.Point(24, 20)
$title.AutoSize = $true
$form.Controls.Add($title)

$statusBox = New-Object Windows.Forms.TextBox
$statusBox.Location = New-Object Drawing.Point(28, 70)
$statusBox.Size = New-Object Drawing.Size(500, 105)
$statusBox.Multiline = $true
$statusBox.ReadOnly = $true
$statusBox.BackColor = [Drawing.Color]::White
$form.Controls.Add($statusBox)

$hint = New-Object Windows.Forms.Label
$hint.Text = "启动后访问：http://127.0.0.1:8088"
$hint.Location = New-Object Drawing.Point(28, 185)
$hint.AutoSize = $true
$form.Controls.Add($hint)

function Refresh-Ui {
    $statusBox.Text = Format-ServiceState (Get-ServiceState)
}

function Invoke-UiAction([string]$RequestedAction) {
    $statusBox.Text = "正在执行，请稍候……"
    $form.Refresh()
    try {
        [void](Invoke-ManagerAction $RequestedAction)
        Refresh-Ui
        [Windows.Forms.MessageBox]::Show("操作成功。", "SunnyRegister", "OK", "Information") | Out-Null
    } catch {
        Refresh-Ui
        [Windows.Forms.MessageBox]::Show("操作失败：`r`n$($_.Exception.Message)", "SunnyRegister", "OK", "Error") | Out-Null
    }
}

$buttons = @(
    @{ Text = "启动"; Action = "Start"; X = 28 },
    @{ Text = "停止"; Action = "Stop"; X = 199 },
    @{ Text = "重启"; Action = "Restart"; X = 370 }
)
foreach ($item in $buttons) {
    $button = New-Object Windows.Forms.Button
    $button.Text = $item.Text
    $button.Tag = $item.Action
    $button.Location = New-Object Drawing.Point($item.X, 225)
    $button.Size = New-Object Drawing.Size(158, 48)
    $button.Add_Click({ Invoke-UiAction ([string]$this.Tag) })
    $form.Controls.Add($button)
}

$form.Add_Shown({ Refresh-Ui })
[void]$form.ShowDialog()
