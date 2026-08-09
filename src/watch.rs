// Tawon - pemantau folder ringan (polling, bukan kernel event)
use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

use walkdir::WalkDir;

use crate::rules::RuleSet;
use crate::scanner::{scan_path, ScanOptions};

pub fn watch(root: &Path, interval: u64, rules: &RuleSet) {
    println!(
        "[tawon] Memantau {} (interval {} detik). Tekan Ctrl+C untuk berhenti.",
        root.display(),
        interval.max(1)
    );
    let mut known: HashMap<std::path::PathBuf, (u64, u64)> = HashMap::new();
    loop {
        let mut current: HashMap<std::path::PathBuf, (u64, u64)> = HashMap::new();
        for entry in WalkDir::new(root).follow_links(false) {
            if let Ok(e) = entry {
                if e.file_type().is_file() {
                    if let Ok(m) = e.metadata() {
                        let mtime = m
                            .modified()
                            .ok()
                            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                            .map(|d| d.as_secs())
                            .unwrap_or(0);
                        current.insert(e.path().to_path_buf(), (m.len(), mtime));
                    }
                }
            }
        }
        for (p, &(len, mtime)) in &current {
            match known.get(p) {
                None => {
                    println!("[+] File baru: {}", p.display());
                    check(p, rules);
                }
                Some(&(ol, om)) => {
                    if ol != len || om != mtime {
                        println!("[~] File berubah: {}", p.display());
                        check(p, rules);
                    }
                }
            }
        }
        for p in known.keys() {
            if !current.contains_key(p) {
                println!("[-] File hilang: {}", p.display());
            }
        }
        known = current;
        std::thread::sleep(Duration::from_secs(interval.max(1)));
    }
}

fn check(p: &Path, rules: &RuleSet) {
    // Watch hanya melaporkan, tidak mengkarantina otomatis (file bisa sedang ditulis)
    let opts = ScanOptions {
        max_file_mb: 30,
        quarantine: false,
    };
    let rep = scan_path(p, rules, &opts);
    for f in rep.findings {
        println!(
            "   [!] {} (skor {}) : {}",
            f.path,
            f.score,
            f.reasons.join("; ")
        );
    }
}
