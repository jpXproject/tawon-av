# ============================================================
#  Tawon Monitor - System Tray
#  Filosofi: diam kalau tidak yakin. Hanya berisik saat BAHAYA.
#  ============================================================
#  KONFIGURASI (edit di C:\Users\XCODE\.tawon\monitor.conf):
#    interval = 30              (default menit antar scan otomatis)
#    satu folder per baris      (pakai interval default)
#    folder = N                 (folder dengan interval khusus, menit)
#    contoh:
#      interval = 30
#      C:\Users\XCODE\Downloads
#      C:\Users\XCODE\Desktop = 10
#      C:\Users\XCODE\Documents = 60
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
# $watchList: array [PSCustomObject]{ Path, IntervalMin, LastScan }
$defaultInterval = 30
$watchList = New-Object System.Collections.ArrayList

if (Test-Path $confFile) {
    Get-Content $confFile | ForEach-Object {
        $line = $_.Trim()
        if (-not $line -or $line.StartsWith('#')) { return }
        if ($line -match '^interval\s*=\s*(\d+)') { $defaultInterval = [int]$Matches[1]; return }
        # Format "path = N" (interval khusus per folder)
        if ($line -match '^(.+?)\s*=\s*(\d+)\s*$') {
            $p = $Matches[1].Trim().Trim('"')
            [void]$watchList.Add([PSCustomObject]@{ Path = $p; IntervalMin = [int]$Matches[2]; LastScan = (Get-Date 0) })
            return
        }
        # Format polos: folder, pakai interval default
        $p = $line.Trim().Trim('"')
        if ($p) { [void]$watchList.Add([PSCustomObject]@{ Path = $p; IntervalMin = $defaultInterval; LastScan = (Get-Date 0) }) }
    }
}

# Fallback: buat konfigurasi default bila kosong
if ($watchList.Count -eq 0) {
    $watchList.Add([PSCustomObject]@{ Path = (Join-Path $env:USERPROFILE 'Downloads'); IntervalMin = $defaultInterval; LastScan = (Get-Date 0) }) | Out-Null
    $watchList.Add([PSCustomObject]@{ Path = (Join-Path $env:USERPROFILE 'Desktop');   IntervalMin = $defaultInterval; LastScan = (Get-Date 0) }) | Out-Null
    $defaultConf = @(
        '# Tawon Monitor - konfigurasi',
        '# interval = default menit antar scan otomatis (default 30)',
        "interval = $defaultInterval",
        '',
        '# Folder pantauan. Bisa beda interval per folder:',
        '#   C:\Users\Kamu\Downloads',
        '#   C:\Users\Kamu\Desktop = 10',
        ($watchList[0].Path),
        ($watchList[1].Path)
    )
    $defaultConf | Set-Content -Path $confFile -Encoding UTF8
}

# Interval minimal 1 menit (cegah 0/negatif)
foreach ($w in $watchList) {
    if ($w.IntervalMin -lt 1) { $w.IntervalMin = 1 }
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
    $found   = New-Object System.Collections.ArrayList
    $scanned = New-Object System.Collections.ArrayList

    foreach ($p in $Paths) {
        if (-not (Test-Path $p)) { continue }
        [void]$scanned.Add($p)
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

    $label = if ($scanned.Count -gt 0) { ($scanned -join ', ') } else { '(tidak ada)' }

    if ($found.Count -gt 0) {
        $notify.Icon = $iconWarn
        $notify.BalloonTipTitle = "Tawon: $($found.Count) ancaman ditemukan!"
        $notify.BalloonTipText  = ($found[0..([Math]::Min(4, $found.Count-1))] -join "`n")
        $notify.BalloonTipIcon  = [System.Windows.Forms.ToolTipIcon]::Warning
        $notify.ShowBalloonTip(8000)
        Write-Log "SCAN [$label]: $($found.Count) BAHAYA -> $($found -join ' | ')"
    } else {
        if ($Manual) {
            $notify.BalloonTipTitle = 'Tawon: scan selesai'
            $notify.BalloonTipText  = "Tidak ada ancaman. Semua aman. (diam...)"
            $notify.BalloonTipIcon  = [System.Windows.Forms.ToolTipIcon]::Info
            $notify.ShowBalloonTip(4000)
        }
        Write-Log "SCAN [$label]: bersih"
    }
    $notify.Icon = $iconGood
}

# Scan otomatis: folder yang sudah lewat interval-nya
function Invoke-DueScans {
    $due = New-Object System.Collections.ArrayList
    foreach ($w in $watchList) {
        if (-not (Test-Path $w.Path)) { continue }
        $dueMin = $w.IntervalMin
        $elapsed = ((Get-Date) - $w.LastScan).TotalMinutes
        if ($elapsed -ge $dueMin) {
            [void]$due.Add($w.Path)
            $w.LastScan = Get-Date
        }
    }
    if ($due.Count -gt 0) {
        Invoke-TawonScan -Paths $due -Manual $false
    }
}

# ---------- Menu konteks ----------
$menu = New-Object System.Windows.Forms.ContextMenuStrip

function Add-MenuItem([string]$text, [scriptblock]$action) {
    $item = New-Object System.Windows.Forms.ToolStripMenuItem
    $item.Text = $text
    $item.Add_Click($action)
    [void]$menu.Items.Add($item)
}

Add-MenuItem 'Scan sekarang (folder pantauan)' { Invoke-TawonScan -Paths ($watchList | ForEach-Object { $_.Path }) -Manual $true }
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

# Klik ganda = scan sekarang (semua folder pantauan)
$notify.Add_MouseDoubleClick({ Invoke-TawonScan -Paths ($watchList | ForEach-Object { $_.Path }) -Manual $true })

# ---------- Timer berkala (1 menit; tiap folder punya interval sendiri) ----------
$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 60 * 1000  # detak tiap 60 detik
$timer.Add_Tick({ Invoke-DueScans })
$timer.Start()

# ---------- Loop tersembunyi ----------
$form = New-Object System.Windows.Forms.Form
$form.Text = 'Tawon Monitor'
$form.ShowInTaskbar = $false
$form.WindowState   = 'Minimized'
$form.Add_Shown({ $form.Hide() })

$desc = ($watchList | ForEach-Object { "$($_.Path) ($($_.IntervalMin)m)" }) -join ', '
Write-Log "Monitor dimulai. Default: ${defaultInterval}m. Folder: $desc"
$form.Show()
[System.Windows.Forms.Application]::Run($form)
