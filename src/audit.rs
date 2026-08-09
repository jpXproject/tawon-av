// Tawon - audit startup (persistence) dan proses berjalan
use std::env;
use std::path::PathBuf;
use std::process::Command;

fn run(args: &[&str]) -> String {
    Command::new("powershell.exe")
        .args(["-NoProfile", "-Command"])
        .arg(args.join(" "))
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default()
}

fn run_raw(prog: &str, args: &[&str]) -> String {
    Command::new(prog)
        .args(args)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default()
}

fn is_suspicious_entry(value: &str) -> bool {
    let p = value.to_lowercase();
    p.contains("\\temp\\")
        || p.contains("\\downloads\\")
        || p.contains("\\programdata\\")
        || p.contains("\\users\\public\\")
        || p.contains("-enc")
        || p.contains("frombase64")
        || p.starts_with("powershell")
        || p.starts_with("cmd.exe")
}

pub fn audit_startup() {
    println!("=================== AUDIT STARTUP ===================");
    let keys = [
        (
            "HKCU Run",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        ),
        (
            "HKLM Run",
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
        ),
        (
            "HKLM WOW64 Run",
            r"HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        ),
    ];
    for (label, key) in keys {
        println!("--- {} ---", label);
        let out = run_raw("reg", &["query", key]);
        for line in out.lines() {
            let l = line.trim();
            if l.is_empty() {
                continue;
            }
            if l.contains("REG_SZ") {
                println!("{}", l);
                if let Some(v) = l.split_whitespace().last() {
                    if is_suspicious_entry(v) {
                        println!("     ^^^ RISIKO: lokasi/target tidak biasa");
                    }
                }
            }
        }
    }

    let username = env::var("USERNAME").unwrap_or_else(|_| "XCODE".to_string());
    let user_folder = PathBuf::from(env::var("USERPROFILE").unwrap_or_else(|_| ".".to_string()))
        .join("AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup");
    let all_folder = PathBuf::from(r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp");

    println!("--- Startup folder (user: {}) ---", username);
    if let Ok(rd) = std::fs::read_dir(&user_folder) {
        for e in rd.flatten() {
            println!("{}", e.path().display());
        }
    }
    println!("--- Startup folder (semua user) ---");
    if let Ok(rd) = std::fs::read_dir(&all_folder) {
        for e in rd.flatten() {
            println!("{}", e.path().display());
        }
    }
    println!("=====================================================");
}

pub fn audit_procs() {
    println!("================ PROSES BERJALAN (TOP RAM) ================");
    let out = run(&[
        "Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First 25 Name,Id,@{N='RAM_MB';E={[math]::Round($_.WorkingSet64/1MB,0)}},Path | Format-Table -AutoSize",
    ]);
    println!("{}", out);

    let bad_names = [
        "mimikatz",
        "psexec",
        "xmr",
        "xmrig",
        "minerd",
        "cryptominer",
        "crack",
        "keygen",
        "meterpreter",
        "njrat",
        "darkcomet",
        "quasar",
        "remcos",
        "rat",
    ];
    let names = run(&["(Get-Process).Name"]);
    let lower = names.to_lowercase();
    let mut found = false;
    for b in bad_names {
        if lower.contains(b) {
            println!("[!] PROSES MENCURIGAKAN TERDETEKSI: {}", b);
            found = true;
        }
    }
    if !found {
        println!("[+] Tidak ada proses dengan nama mencurigakan yang dikenal.");
    }
    println!("==========================================================");
}
