// Tawon - laporan forensik & kesehatan sistem
use std::process::Command;

fn ps(script: &str) -> String {
    Command::new("powershell.exe")
        .args(["-NoProfile", "-Command", script])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default()
}

pub fn run_report() {
    println!("==================== LAPORAN FORENSIK & KESEHATAN ====================");
    println!("--- SISTEM (OS / RAM / uptime / disk) ---");
    print!(
        "{}",
        ps("Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,LastBootUpTime,@{N='FreeRAM_MB';E={[math]::Round($_.FreePhysicalMemory/1024,0)}},@{N='TotalRAM_MB';E={[math]::Round($_.TotalVisibleMemorySize/1024,0)}} | Format-List")
    );
    print!(
        "{}",
        ps("Get-PSDrive -PSProvider FileSystem | Select-Object Name,@{N='Free_GB';E={[math]::Round($_.Free/1GB,1)}} | Format-Table -AutoSize")
    );

    println!("--- CRASH: KERNEL-POWER 41 (45 hari) ---");
    println!("(Bugcheck=0 & PowerButton=0 = mati mendadak/kehilangan daya, bukan BSOD)");
    print!(
        "{}",
        ps("Get-WinEvent -FilterHashtable @{LogName='System'; Id=41; StartTime=(Get-Date).AddDays(-45)} -ErrorAction SilentlyContinue | ForEach-Object { $x=[xml]$_.ToXml(); $d=@{}; foreach($i in $x.Event.EventData.Data){$d[$i.Name]=$i.InnerText}; '{0}  Bugcheck={1}  PowerButton={2}  Sleep={3}' -f $_.TimeCreated.ToString('yyyy-MM-dd HH:mm'), $d['BugcheckCode'], $d['PowerButtonTimestamp'], $d['SleepInProgress'] }")
    );

    println!("--- CRASH: SHUTDOWN TAK TERDUGA (6008) ---");
    print!(
        "{}",
        ps("Get-WinEvent -FilterHashtable @{LogName='System'; Id=6008} -MaxEvents 5 -ErrorAction SilentlyContinue | ForEach-Object { $_.Message }")
    );

    println!("--- HARDWARE: WHEA ERRORS (45 hari) ---");
    print!(
        "{}",
        ps("Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-WHEA-Logger'; StartTime=(Get-Date).AddDays(-45)} -ErrorAction SilentlyContinue | Select-Object TimeCreated,Id | Format-Table -AutoSize")
    );

    println!("--- CRASH DUMP ---");
    check_dumps();

    println!("--- PROSES TOP RAM ---");
    print!(
        "{}",
        ps("Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First 15 Name,Id,@{N='RAM_MB';E={[math]::Round($_.WorkingSet64/1MB,0)}} | Format-Table -AutoSize")
    );

    println!("--- PROSES TOP CPU (kumulatif) ---");
    print!(
        "{}",
        ps("Get-Process | Sort-Object CPU -Descending | Select-Object -First 10 Name,Id,@{N='CPU_dtk';E={[math]::Round($_.CPU,1)}} | Format-Table -AutoSize")
    );

    println!("--- KONEKSI JARINGAN AKTIF (top 10 per proses) ---");
    print!(
        "{}",
        ps("Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Group-Object OwningProcess | Sort-Object Count -Descending | Select-Object -First 10 @{N='Koneksi';E={$_.Count}},@{N='Proses';E={(Get-Process -Id ([int]$_.Name) -ErrorAction SilentlyContinue).ProcessName}} | Format-Table -AutoSize")
    );

    println!("--- ERROR SISTEM 3 HARI (per provider, top 8) ---");
    print!(
        "{}",
        ps("Get-WinEvent -FilterHashtable @{LogName='System'; Level=1,2; StartTime=(Get-Date).AddDays(-3)} -ErrorAction SilentlyContinue | Group-Object ProviderName | Sort-Object Count -Descending | Select-Object -First 8 @{N='Jumlah';E={$_.Count}},Name | Format-Table -AutoSize")
    );

    println!("==========================================================================");
}

fn check_dumps() {
    let targets = [
        ("Minidump", r"C:\Windows\Minidump"),
        ("MEMORY.DMP", r"C:\Windows\MEMORY.DMP"),
        ("LiveKernelReports", r"C:\Windows\LiveKernelReports"),
    ];
    for (label, d) in targets {
        let p = std::path::Path::new(d);
        if p.is_dir() {
            let mut count = 0usize;
            if let Ok(rd) = std::fs::read_dir(p) {
                for e in rd.flatten() {
                    if e.path()
                        .extension()
                        .map(|x| x.to_string_lossy().to_lowercase() == "dmp")
                        .unwrap_or(false)
                    {
                        count += 1;
                    }
                }
            }
            println!("{}: {} file .dmp", label, count);
        } else if p.exists() {
            println!(
                "{}: ada ({} byte)",
                label,
                p.metadata().map(|m| m.len()).unwrap_or(0)
            );
        } else {
            println!("{}: tidak ada", label);
        }
    }
}
