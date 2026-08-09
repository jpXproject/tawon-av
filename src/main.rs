// Tawon - AV ringan tapi sakti (Rust)
mod allowlist;
mod audit;
mod forensik;
mod heuristics;
mod quarantine;
mod rules;
mod scanner;
mod watch;

use std::env;
use std::path::PathBuf;

use crate::rules::RuleSet;
use crate::scanner::{scan_path, ScanOptions, Verdict};

const VERSION: &str = "0.1.1";
const EICAR: &str = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

fn main() {
    let args: Vec<String> = env::args().collect();
    let cmd = args.get(1).map(|s| s.as_str()).unwrap_or("help");
    let rest = &args[2..];
    match cmd {
        "scan" => cmd_scan(rest),
        "quick" => cmd_quick(rest),
        "watch" => cmd_watch(rest),
        "startup" => audit::audit_startup(),
        "proc" => audit::audit_procs(),
        "forensik" | "report" | "laporan" => forensik::run_report(),
        "quarantine" => cmd_quarantine(rest),
        "allow" => cmd_allow(rest),
        "eicar" => cmd_eicar(rest),
        "rules" => rules::print_rules_path(),
        "version" | "--version" | "-V" => println!("tawon {} - AV ringan tapi sakti", VERSION),
        "help" | "-h" | "--help" => print_help(),
        _ => {
            println!("Perintah tidak dikenal: {}\n", cmd);
            print_help();
        }
    }
}

fn load_rules() -> RuleSet {
    RuleSet::load(Some(&rules::rules_path()))
}

fn cmd_scan(args: &[String]) {
    let (quarantine, quiet, max_mb, target) = parse_scan_args(args);
    let path = target.unwrap_or_else(|| ".".to_string());
    println!(
        "[tawon] Scan: {} (maks {} MB/file, karantina: {}, senyap: {}) ...",
        path, max_mb, quarantine, quiet
    );
    let rules = load_rules();
    let opts = ScanOptions {
        max_file_mb: max_mb,
        quarantine,
    };
    let rep = scan_path(std::path::Path::new(&path), &rules, &opts);
    print_report(&rep, quiet);
}

fn cmd_quick(args: &[String]) {
    let (_, quiet, _, _) = parse_scan_args(args);
    println!("[tawon] Quick scan lokasi berisiko (laporan saja, tidak karantina otomatis) ...");
    let rules = load_rules();
    let opts = ScanOptions {
        max_file_mb: 20,
        quarantine: false,
    };
    let username = env::var("USERPROFILE").unwrap_or_else(|_| ".".to_string());
    let targets = vec![
        PathBuf::from(&username).join("Downloads"),
        PathBuf::from(&username).join("AppData/Local/Temp"),
        PathBuf::from(&username)
            .join("AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"),
        PathBuf::from(r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"),
        PathBuf::from(&username).join("Desktop"),
    ];
    let mut total = scanner::ScanReport {
        findings: Vec::new(),
        files: 0,
        bytes: 0,
        skipped: 0,
    };
    for t in &targets {
        if !t.exists() {
            continue;
        }
        println!("  -> {}", t.display());
        let rep = scan_path(t, &rules, &opts);
        total.files += rep.files;
        total.bytes += rep.bytes;
        total.skipped += rep.skipped;
        total.findings.extend(rep.findings);
    }
    print_report(&total, quiet);
}

fn parse_scan_args(args: &[String]) -> (bool, bool, u64, Option<String>) {
    let mut quarantine = false;
    let mut quiet = false;
    let mut max_mb: u64 = 30;
    let mut target: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--quarantine" | "-q" => quarantine = true,
            "--quiet" | "-s" => quiet = true,
            "--max-mb" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    max_mb = v.parse().unwrap_or(30);
                }
            }
            s if s.starts_with('-') => {
                eprintln!("Opsi tidak dikenal: {}", s);
            }
            _ => {
                if target.is_none() {
                    target = Some(args[i].clone());
                }
            }
        }
        i += 1;
    }
    (quarantine, quiet, max_mb, target)
}

fn cmd_watch(args: &[String]) {
    let target = args.first().cloned().unwrap_or_else(|| ".".to_string());
    let interval: u64 = args.get(1).and_then(|v| v.parse().ok()).unwrap_or(10);
    let rules = load_rules();
    watch::watch(std::path::Path::new(&target), interval, &rules);
}

fn cmd_quarantine(args: &[String]) {
    let sub = args.first().map(|s| s.as_str()).unwrap_or("list");
    match sub {
        "list" | "ls" => {
            let items = quarantine::list();
            if items.is_empty() {
                println!("[tawon] Karantina kosong.");
            } else {
                println!("ID              | Asal");
                println!("----------------+--------------------------------------");
                for (id, orig, _q) in &items {
                    println!("{:<15} | {}", id, orig);
                }
            }
        }
        "restore" => {
            if let Some(id) = args.get(1) {
                match quarantine::restore(id) {
                    Ok(msg) => println!("[+] {}", msg),
                    Err(e) => eprintln!("[!] {}", e),
                }
            } else {
                eprintln!("Gunakan: tawon quarantine restore <ID>");
            }
        }
        other => {
            eprintln!("Sub-perintah karantina tidak dikenal: {}", other);
            eprintln!("Gunakan: tawon quarantine [list|restore <ID>]");
        }
    }
}

fn cmd_allow(args: &[String]) {
    if args.is_empty() {
        let items = allowlist::list();
        if items.is_empty() {
            println!("[tawon] Allowlist kosong. Tambahkan: tawon allow <path/namafile>");
        } else {
            println!("[tawon] Allowlist ({} entri):", items.len());
            for i in items {
                println!("  - {}", i);
            }
        }
    } else {
        match allowlist::add(&args.join(" ")) {
            Ok(msg) => println!("[+] {}", msg),
            Err(e) => eprintln!("[!] {}", e),
        }
    }
}

fn cmd_eicar(args: &[String]) {
    let path = args.first().cloned().unwrap_or_else(|| {
        env::var("USERPROFILE").unwrap_or_else(|_| ".".to_string()) + "\\eicar_test.txt"
    });
    match std::fs::write(&path, EICAR) {
        Ok(_) => {
            println!("[+] File uji EICAR dibuat: {}", path);
            println!("    Jalankan: tawon scan {}", path);
        }
        Err(e) => eprintln!("[!] Gagal menulis: {}", e),
    }
}

fn print_report(rep: &scanner::ScanReport, quiet: bool) {
    let mut threats = 0;
    let mut suspicious = 0;
    for f in &rep.findings {
        match f.verdict {
            Verdict::Threat => threats += 1,
            Verdict::Suspicious => suspicious += 1,
            Verdict::Clean => {}
        }
        // Mode senyap: hanya tampilkan ancaman (BAHAYA)
        if quiet && f.verdict != Verdict::Threat {
            continue;
        }
        let tag = match f.verdict {
            Verdict::Threat => "[BAHAYA]",
            Verdict::Suspicious => "[CURIGA]",
            Verdict::Clean => "[OK]",
        };
        println!("{} {} (skor {})", tag, f.path, f.score);
        for r in &f.reasons {
            println!("      - {}", r);
        }
        if f.verdict == Verdict::Suspicious {
            println!("      (Heuristik saja - verifikasi manual. Kalau ini software tepercaya:");
            println!("       tawon allow {})", f.path);
        }
    }
    if !quiet {
        println!(
            "\nSelesai: {} file dipindai, {} ancaman, {} mencurigakan, {} dilewati.",
            rep.files, threats, suspicious, rep.skipped
        );
    }
}

fn print_help() {
    println!(
        r#"Tawon {} - AV ringan tapi sakti (filosofi: diam kalau tidak yakin)

PENGGUNAAN:
  tawon scan [--quarantine] [--quiet] [--max-mb N] <path>   Scan folder/file
  tawon quick [--quiet]                                     Scan cepat lokasi berisiko (laporan saja)
  tawon watch <path> [interval_detik]                       Pantau folder (laporan, tidak karantina)
  tawon forensik                                            Laporan forensik & kesehatan sistem
  tawon startup                                             Audit entri startup (persistence)
  tawon proc                                                Audit proses berjalan
  tawon quarantine [list|restore <ID>]                      Kelola karantina
  tawon allow <path/namafile>                               Percaya file/folder (tidak dilaporkan lagi)
  tawon allow                                                Lihat allowlist
  tawon eicar [path]                                        Buat file uji EICAR (self-test)
  tawon rules                                               Lokasi file rules kustom
  tawon version                                             Versi

RULES: {} (HASH|sha256|d | HEX|4D 5A ??|d | TEXT!|pola|d | TEXT|pola|d)
"#,
        VERSION,
        rules::rules_path().display()
    );
}
