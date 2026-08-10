// Tawon - scanner rekursif
use std::fs;
use std::path::Path;

use sha2::{Digest, Sha256};
use walkdir::WalkDir;

use crate::allowlist;
use crate::heuristics;
use crate::quarantine;
use crate::rules::RuleSet;

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum Verdict {
    Clean,
    Suspicious,
    Threat,
}

pub struct Finding {
    pub path: String,
    pub verdict: Verdict,
    pub score: u32,
    pub reasons: Vec<String>,
}

pub struct ScanOptions {
    pub max_file_mb: u64,
    pub quarantine: bool,
}

pub struct ScanReport {
    pub findings: Vec<Finding>,
    pub files: u64,
    pub bytes: u64,
    pub skipped: u64,
}

pub fn scan_path(root: &Path, rules: &RuleSet, opts: &ScanOptions) -> ScanReport {
    let mut report = ScanReport {
        findings: Vec::new(),
        files: 0,
        bytes: 0,
        skipped: 0,
    };
    let cap = opts.max_file_mb * 1024 * 1024;
    let allow = allowlist::load();

    for entry in WalkDir::new(root).follow_links(false) {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        let path_str = path.to_string_lossy().to_string();
        let path_norm = allowlist::normalize(&path_str); // separators -> '/' supaya cocok allowlist
        let name_lower = heuristics::file_name(&path_str).to_lowercase();
        if is_skip_path(&path_norm) {
            continue;
        }
        // Allowlist: file tepercaya -> dilewati (tidak pernah dilaporkan)
        if allowlist::is_allowed(&allow, &path_norm, &name_lower) {
            report.skipped += 1;
            continue;
        }
        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        let len = meta.len();
        if len > cap {
            report.skipped += 1;
            continue;
        }
        report.files += 1;
        report.bytes += len;

        let data = match fs::read(path) {
            Ok(d) => d,
            Err(_) => {
                report.skipped += 1;
                continue;
            }
        };

        let mut hasher = Sha256::new();
        hasher.update(&data);
        let sha = format!("{:x}", hasher.finalize());

        let hits = rules.match_file(&data, &sha);
        let pe = heuristics::pe_info(&data);
        let (mut score, mut reasons) = heuristics::score_file(&path_str, &data, &pe);

        let hash_hit = hits.iter().any(|h| h.hash);
        if hash_hit {
            score = score.max(80);
            for h in hits.iter().filter(|h| h.hash) {
                reasons.push(format!("HASH (PASTI): {}", h.desc));
            }
        }
        let critical: Vec<String> = hits
            .iter()
            .filter(|h| h.critical && !h.hash)
            .map(|h| h.desc.clone())
            .collect();
        if !critical.is_empty() {
            score = score.max(75);
            reasons.extend(critical);
        }
        let medium: Vec<String> = hits
            .iter()
            .filter(|h| !h.critical && !h.hash)
            .map(|h| h.desc.clone())
            .collect();
        if !medium.is_empty() {
            score += 35;
            reasons.extend(medium);
        }

        // Filosofi: diam kalau tidak yakin.
        // BAHAYA hanya jika hash cocok atau skor >= 70 (sangat yakin).
        // Heuristik ringan -> CURIGA (informasional, tidak pernah otomatis dihapus).
        let verdict = if hash_hit || score >= 70 {
            Verdict::Threat
        } else if score >= 30 {
            Verdict::Suspicious
        } else {
            Verdict::Clean
        };

        if verdict != Verdict::Clean {
            if opts.quarantine && verdict == Verdict::Threat {
                match quarantine::quarantine_file(path, &sha) {
                    Ok(id) => reasons.push(format!("DIKARANTINA (id {})", id)),
                    Err(e) => reasons.push(format!("gagal karantina: {}", e)),
                }
            }
            report.findings.push(Finding {
                path: path_str,
                verdict,
                score,
                reasons,
            });
        }
    }
    report
}

fn is_skip_path(normalized: &str) -> bool {
    if normalized.contains("/.tawon/") {
        return true; // folder kerja sendiri
    }
    // Build artifacts Cargo (target/debug, target/release, target/incremental):
    // berisi string rules bawaan Tawon di dalam binary debug -> self false-positive.
    // Folder ini selalu di-generate ulang, bukan area risiko.
    if normalized.contains("/target/debug/")
        || normalized.contains("/target/release/")
        || normalized.contains("/target/incremental/")
    {
        return true;
    }
    // Jangan pindai biner Tawon sendiri (berisi string rules -> false positive)
    if let Some(name) = normalized.rsplit('/').next() {
        if name == "tawon.exe" {
            return true;
        }
    }
    false
}
