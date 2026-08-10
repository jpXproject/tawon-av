// Tawon - mesin rules dengan tingkat keyakinan:
//   HASH  = hash sha256 (PASTI berbahaya)
//   HEX   = pola byte signature (keyakinan tinggi)
//   TEXT! = pola teks kritis (keyakinan tinggi, contoh: EICAR, encoded command)
//   TEXT  = pola teks medium (bisa jadi false positive, contoh: nama API injeksi)
use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub struct RuleHit {
    pub desc: String,
    pub critical: bool,
    pub hash: bool,
}

pub struct RuleSet {
    pub hashes: HashMap<String, String>,
    pub hex: Vec<(Vec<Option<u8>>, String)>,
    pub text: Vec<(String, String)>, // medium
    pub text_critical: Vec<(String, String)>,
}

impl RuleSet {
    pub fn load(user_rules: Option<&Path>) -> RuleSet {
        let mut rs = RuleSet {
            hashes: HashMap::new(),
            hex: Vec::new(),
            text: Vec::new(),
            text_critical: Vec::new(),
        };
        for line in BUILTIN_RULES.lines() {
            rs.parse_line(line);
        }
        if let Some(p) = user_rules {
            if p.exists() {
                if let Ok(content) = fs::read_to_string(p) {
                    for line in content.lines() {
                        rs.parse_line(line);
                    }
                } else {
                    eprintln!("[!] Tidak bisa membaca file rules: {}", p.display());
                }
            }
        }
        rs
    }

    fn parse_line(&mut self, raw: &str) {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            return;
        }
        let mut parts = line.splitn(3, '|');
        let kind = parts.next().unwrap_or("").trim().to_uppercase();
        let body = parts.next().unwrap_or("").trim();
        let desc = parts.next().unwrap_or("").trim();
        if body.is_empty() {
            return;
        }
        match kind.as_str() {
            "HASH" => {
                let b = body.to_lowercase();
                if b.len() == 64 && b.chars().all(|c| c.is_ascii_hexdigit()) {
                    self.hashes.insert(b, desc.to_string());
                }
            }
            "HEX" => {
                if let Some(v) = parse_hex_pattern(body) {
                    self.hex.push((v, desc.to_string()));
                }
            }
            "TEXT!" => {
                self.text_critical
                    .push((body.to_lowercase(), desc.to_string()));
            }
            "TEXT" => {
                self.text.push((body.to_lowercase(), desc.to_string()));
            }
            _ => {}
        }
    }

    /// Kembalikan daftar rule yang cocok pada file.
    /// Rule teks (TEXT/TEXT!) HANYA dicocokkan pada file teks: pola pendek
    /// seperti "-enc " atau API injection bisa muncul kebetulan di binary
    /// (string library DLL/EXE) -> anti false positive.
    pub fn match_file(&self, data: &[u8], sha: &str) -> Vec<RuleHit> {
        let mut hits = Vec::new();
        if let Some(d) = self.hashes.get(sha) {
            hits.push(RuleHit {
                desc: d.clone(),
                critical: true,
                hash: true,
            });
        }
        let limit = data.len().min(4 * 1024 * 1024);
        let hay = &data[..limit];
        let is_text = crate::heuristics::looks_like_text(hay);
        for (pat, d) in &self.hex {
            if match_hex(hay, pat) {
                hits.push(RuleHit {
                    desc: d.clone(),
                    critical: true,
                    hash: false,
                });
            }
        }
        // Rule kritis (TEXT!): pola panjang & spesifik -> aman cocok di semua file,
        // termasuk binary (dropper EXE berisi string ini tetap kena). Cari di data
        // mentah (ASCII tertanam di binary) DAN di stream teks (menangkap UTF-16).
        let text_low = crate::heuristics::text_stream(hay);
        for (pat, d) in &self.text_critical {
            let hit_binary = contains_ci(hay, pat.as_bytes());
            let hit_text = text_low
                .as_deref()
                .map_or(false, |t| contains_ci(t, pat.as_bytes()));
            if hit_binary || hit_text {
                hits.push(RuleHit {
                    desc: d.clone(),
                    critical: true,
                    hash: false,
                });
            }
        }
        // Rule medium (TEXT): pola pendek berisiko false positive di binary
        // (string library DLL/EXE) -> HANYA untuk file teks.
        if is_text {
            for (pat, d) in &self.text {
                if contains_ci(hay, pat.as_bytes()) {
                    hits.push(RuleHit {
                        desc: d.clone(),
                        critical: false,
                        hash: false,
                    });
                }
            }
        }
        hits
    }
}

fn parse_hex_pattern(s: &str) -> Option<Vec<Option<u8>>> {
    let mut out: Vec<Option<u8>> = Vec::new();
    for tok in s.split_whitespace() {
        if tok == "??" || tok == "?" {
            out.push(None);
            continue;
        }
        if tok.len() == 2 && tok.bytes().all(|c| c.is_ascii_hexdigit()) {
            out.push(Some(u8::from_str_radix(tok, 16).ok()?));
        } else {
            return None;
        }
    }
    if out.is_empty() || out.len() > 512 {
        None
    } else {
        Some(out)
    }
}

fn match_hex(hay: &[u8], pat: &[Option<u8>]) -> bool {
    if pat.is_empty() || hay.len() < pat.len() {
        return false;
    }
    'outer: for i in 0..=(hay.len() - pat.len()) {
        for (j, p) in pat.iter().enumerate() {
            if let Some(b) = p {
                if hay[i + j] != *b {
                    continue 'outer;
                }
            }
        }
        return true;
    }
    false
}

fn contains_ci(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || hay.len() < needle.len() {
        return false;
    }
    'outer: for i in 0..=(hay.len() - needle.len()) {
        for (j, n) in needle.iter().enumerate() {
            if hay[i + j].to_ascii_lowercase() != *n {
                continue 'outer;
            }
        }
        return true;
    }
    false
}

pub fn rules_path() -> PathBuf {
    home_dir().join(".tawon").join("rules.txt")
}

fn home_dir() -> PathBuf {
    env::var_os("USERPROFILE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

pub fn print_rules_path() {
    println!("{}", rules_path().display());
}

/// Rules bawaan. Format: KIND|isi|deskripsi
/// KIND: HASH | HEX | TEXT! (kritis) | TEXT (medium)
pub const BUILTIN_RULES: &str = r#"
# ==== Tawon builtin rules ====
# EICAR (file uji AV standar) - KRITIS
TEXT!|X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*|EICAR test file (AV self-test)
# API injeksi (MEDIUM: bisa muncul di tool keamanan yang sah)
TEXT|CreateRemoteThread|PE injection API
TEXT|VirtualAllocEx|PE injection API
TEXT|WriteProcessMemory|proses memory write (injection)
TEXT|NtUnmapViewOfSection|process hollowing primitive
TEXT|QueueUserAPC|APC injection primitive
# PowerShell abuse
# -EncodedCommand penuh = KRITIS (tidak muncul kebetulan di binary)
# -enc pendek = MEDIUM (bisa muncul di script sah; cukup CURIGA, BAHAYA butuh bukti lain)
TEXT!|-EncodedCommand|PowerShell encoded command
TEXT|-enc |PowerShell encoded command (short)
TEXT!|IEX(New-Object Net.WebClient).DownloadString|PowerShell download cradle
TEXT|FromBase64String|base64 decoding in script
TEXT|powershell.exe -w hidden|hidden PowerShell execution
TEXT|-windowstyle hidden|hidden window execution
# Credential dumping - KRITIS
TEXT!|sekurlsa::logonpasswords|credential dumping (mimikatz)
TEXT!|Invoke-Mimikatz|credential dumping toolkit
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_pattern_with_wildcards() {
        let pat = parse_hex_pattern("4D 5A ?? 00").unwrap();
        assert!(match_hex(b"\x00\x4D\x5A\x90\x00\x00", &pat));
        assert!(!match_hex(b"\x4D\x5A\x90\x01\x00", &pat));
    }

    #[test]
    fn hex_pattern_too_long_rejected() {
        let long = (0..600).map(|_| "4D").collect::<Vec<_>>().join(" ");
        assert!(parse_hex_pattern(&long).is_none());
    }

    #[test]
    fn eicar_rule_detects() {
        let rs = RuleSet::load(None);
        let eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        let hits = rs.match_file(eicar, &"0".repeat(64));
        assert!(hits.iter().any(|h| h.critical && h.desc.contains("EICAR")));
    }

    #[test]
    fn hash_rule_match() {
        let mut rs = RuleSet::load(None);
        let sha = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
        rs.hashes.insert(sha.to_string(), "test hash".to_string());
        let hits = rs.match_file(b"data", sha);
        assert!(hits.iter().any(|h| h.hash));
    }

    #[test]
    fn hash_rule_ignored_when_wrong_length() {
        let mut rs = RuleSet::load(None);
        rs.parse_line("HASH|zzz|pendek");
        assert!(rs.hashes.is_empty());
    }

    #[test]
    fn contains_ci_works() {
        assert!(contains_ci(b"Hello WORLD", b"world"));
        assert!(!contains_ci(b"Hello", b"world"));
    }

    #[test]
    fn binary_with_short_enc_not_flagged() {
        // DLL/binary berisi "-enc " secara kebetulan -> TIDAK boleh terflag
        let rs = RuleSet::load(None);
        let mut data = vec![0u8; 4096];
        // isi dengan byte binary acak-ish + selipkan string pendek
        for (i, b) in data.iter_mut().enumerate() {
            *b = ((i * 31 + 7) % 251) as u8;
        }
        data[100..105].copy_from_slice(b"-enc ");
        let hits = rs.match_file(&data, &"0".repeat(64));
        assert!(
            !hits.iter().any(|h| h.critical),
            "binary dengan '-enc ' tidak boleh kritis: {:?}",
            hits
        );
    }

    #[test]
    fn text_script_with_enc_medium_only() {
        // Script teks dengan "-enc " = hanya CURIGA (medium), bukan BAHAYA
        let rs = RuleSet::load(None);
        let script = b"$cmd = powershell -enc SQBFAFgA \n";
        let hits = rs.match_file(script, &"0".repeat(64));
        let enc = hits.iter().find(|h| h.desc.contains("encoded"));
        assert!(enc.is_some(), "-enc di script teks harus terdeteksi");
        assert!(!enc.unwrap().critical, "-enc pendek = medium, bukan kritis");
    }

    #[test]
    fn eicar_still_critical_in_text() {
        let rs = RuleSet::load(None);
        let hits = rs.match_file(
            b"prefix X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H* suffix",
            &"0".repeat(64),
        );
        assert!(hits.iter().any(|h| h.critical && h.desc.contains("EICAR")));
    }

    #[test]
    fn critical_rule_matches_in_binary() {
        // Dropper EXE berisi string -EncodedCommand penuh (pola panjang, tidak
        // mungkin false positive) -> TETAP kritis meski file binary.
        let rs = RuleSet::load(None);
        let mut data = vec![0u8; 8192];
        for (i, b) in data.iter_mut().enumerate() {
            *b = ((i * 31 + 7) % 251) as u8;
        }
        data[500..515].copy_from_slice(b"-EncodedCommand");
        let hits = rs.match_file(&data, &"0".repeat(64));
        assert!(
            hits.iter()
                .any(|h| h.critical && h.desc.contains("encoded")),
            "TEXT! di binary harus tetap kritis: {:?}",
            hits
        );
    }

    #[test]
    fn utf16_script_still_matches_rules() {
        let rs = RuleSet::load(None);
        let ascii = b"powershell -EncodedCommand abcdef";
        let mut utf16 = Vec::with_capacity(ascii.len() * 2);
        for &b in ascii {
            utf16.push(b);
            utf16.push(0);
        }
        let hits = rs.match_file(&utf16, &"0".repeat(64));
        assert!(
            hits.iter()
                .any(|h| h.critical && h.desc.contains("encoded")),
            "UTF-16 dengan -EncodedCommand harus kritis: {:?}",
            hits
        );
    }
}
