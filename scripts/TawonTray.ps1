# ============================================================
#  Tawon Monitor - System Tray
#  Filosofi: diam kalau tidak yakin. Hanya berisik saat BAHAYA.
#  ============================================================
#  KONFIGURASI (edit di C:\Users\XCODE\.tawon\monitor.conf):
#    interval = 30          (menit antar scan otomatis)
#    satu folder per baris  (folder yang dipantau)
#  ============================================================

$ErrorActionPreference = 'SilentlyContinue'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# ---------- Lokasi ----------
$tawon    = 'C:\Users\XCODE\sec-tools\tawon.exe'
$cfgDir   = Join-Path $env:USERPROFILE '.tawon'
$logFile  = Join-Path $cfgDir 'monitor.log'
$confFile = Join-Path $cfgDir 'monitor.conf'
$icoGood  = 'C:\Users\XCODE\sec-tools\tawon.ico'
$icoWarn  = 'C:\Users\XCODE\sec-tools\tawon-warn.ico'

if (-not (Test-Path $cfgDir)) { New-Item -ItemType Directory -Path $cfgDir | Out-Null }

# ---------- Konfigurasi ----------
$intervalMin = 30
$watchPaths  = @()

if (Test-Path $confFile) {
    Get-Content $confFile | ForEach-Object {
        $line = $_.Trim()
        if (-not $line -or $line.StartsWith('#')) { return }
        if ($line -match '^interval\s*=\s*(\d+)') { $intervalMin = [int]$Matches[1]; return }
        $watchPaths += $line
    }
}
if ($watchPaths.Count -eq 0) {
    $watchPaths = @(
        (Join-Path $env:USERPROFILE 'Downloads'),
        (Join-Path $env:USERPROFILE 'Desktop')
    )
    $defaultConf = @(
        '# Tawon Monitor - konfigurasi',
        '# interval = menit antar scan otomatis (default 30)',
        "interval = $intervalMin",
        '',
        '# Folder yang dipantau (satu per baris):',
        $watchPaths[0],
        $watchPaths[1]
    )
    $defaultConf | Set-Content -Path $confFile -Encoding UTF8
}

# Cegah instance ganda
$existing = Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" |
    Where-Object { $_.CommandLine -match 'TawonTray\.ps1' -and $_.ProcessId -ne $PID }
if ($existing) { exit }

# ---------- Log ----------
function Write-Log([string]$msg) {
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    "$ts  $msg" | Out-File -FilePath $logFile -Append -Encoding UTF8
}

# ---------- Ikon ----------
$iconGood = [System.Drawing.SystemIcons]::Shield
$iconWarn = [System.Drawing.SystemIcons]::Warning
if (Test-Path $icoGood) {
    try {
        $tmpGood = New-Object System.Drawing.Icon($icoGood)
        $tmpWarn = New-Object System.Drawing.Icon($icoWarn)
        $iconGood = $tmpGood
        $iconWarn = $tmpWarn
    } catch { }
}

# ---------- NotifyIcon ----------
$notify = New-Object System.Windows.Forms.NotifyIcon
$notify.Icon  = $iconGood
$notify.Text  = 'Tawon Monitor - diam kalau tidak yakin'
$notify.Visible = $true

# ---------- Fungsi scan ----------
function Invoke-TawonScan([string[]]$Paths, [bool]$Manual) {
    $tmpOut  = Join-Path $env:TEMP "tawon_scan_$PID.txt"
    $found   = New-Object System.Collections.ArrayList

    foreach ($p in $Paths) {
        if (-not (Test-Path $p)) { continue }
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName               = $tawon
        $psi.Arguments              = "scan --quiet `"$p`""
        $psi.UseShellExecute        = $false
        $psi.CreateNoWindow         = $true
        $psi.RedirectStandardOutput = $true
        $proc = [System.Diagnostics.Process]::Start($psi)
        $out  = $proc.StandardOutput.ReadToEnd()
        $proc.WaitForExit()
        foreach ($line in ($out -split "`r?`n")) {
            if ($line -match '\[BAHAYA\]') { [void]$found.Add($line.Trim()) }
        }
    }

    if (Test-Path $tmpOut) { Remove-Item $tmpOut -Force }

    if ($found.Count -gt 0) {
        $notify.Icon = $iconWarn
        $notify.BalloonTipTitle = "Tawon: $($found.Count) ancaman ditemukan!"
        $notify.BalloonTipText  = ($found[0..([Math]::Min(4, $found.Count-1))] -join "`n")
        $notify.BalloonTipIcon  = [System.Windows.Forms.ToolTipIcon]::Warning
        $notify.ShowBalloonTip(8000)
        Write-Log "SCAN: $($found.Count) BAHAYA -> $($found -join ' | ')"
    } else {
        if ($Manual) {
            $notify.BalloonTipTitle = 'Tawon: scan selesai'
            $notify.BalloonTipText  = "Tidak ada ancaman. Semua aman. (diam...)"
            $notify.BalloonTipIcon  = [System.Windows.Forms.ToolTipIcon]::Info
            $notify.ShowBalloonTip(4000)
        }
        Write-Log 'SCAN: bersih'
    }
    $notify.Icon = $iconGood
}

# ---------- Menu konteks ----------
$menu = New-Object System.Windows.Forms.ContextMenuStrip

function Add-MenuItem([string]$text, [scriptblock]$action) {
    $item = New-Object System.Windows.Forms.ToolStripMenuItem
    $item.Text = $text
    $item.Add_Click($action)
    [void]$menu.Items.Add($item)
}

Add-MenuItem 'Scan sekarang (folder pantauan)' { Invoke-TawonScan -Paths $watchPaths -Manual $true }
Add-MenuItem 'Scan cepat (Downloads/Temp/Startup)' { Start-Process $tawon -ArgumentList 'quick' }
Add-MenuItem 'Diagnosa PC (forensik)'              { Start-Process $tawon -ArgumentList 'forensik' }
Add-MenuItem 'Audit startup & proses'              { Start-Process $tawon -ArgumentList 'startup' }

[void]$menu.Items.Add((New-Object System.Windows.Forms.ToolStripSeparator))

Add-MenuItem 'Buka karantina'      { Start-Process explorer.exe (Join-Path $cfgDir 'quarantine') }
Add-MenuItem 'Buka folder .tawon'   { Start-Process explorer.exe $cfgDir }
Add-MenuItem 'Edit folder pantauan' { Start-Process notepad.exe $confFile }

[void]$menu.Items.Add((New-Object System.Windows.Forms.ToolStripSeparator))

Add-MenuItem 'Keluar' {
    $notify.Visible = $false
    Write-Log 'Monitor dihentikan'
    [System.Windows.Forms.Application]::Exit()
}

$notify.ContextMenuStrip = $menu

# Klik ganda = scan sekarang
$notify.Add_MouseDoubleClick({ Invoke-TawonScan -Paths $watchPaths -Manual $true })

# ---------- Timer berkala ----------
$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = $intervalMin * 60 * 1000
$timer.Add_Tick({ Invoke-TawonScan -Paths $watchPaths -Manual $false })
$timer.Start()

# ---------- Loop tersembunyi ----------
$form = New-Object System.Windows.Forms.Form
$form.Text = 'Tawon Monitor'
$form.ShowInTaskbar = $false
$form.WindowState   = 'Minimized'
$form.Add_Shown({ $form.Hide() })

Write-Log "Monitor dimulai. Interval: $intervalMin menit. Folder: $($watchPaths -join ', ')"
$form.Show()
[System.Windows.Forms.Application]::Run($form)
