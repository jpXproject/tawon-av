// Tawon - allowlist: file/folder tepercaya yang tidak pernah dilaporkan
use std::env;
use std::fs;
use std::path::PathBuf;

fn home() -> PathBuf {
    env::var_os("USERPROFILE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

pub fn path() -> PathBuf {
    home().join(".tawon").join("allowlist.txt")
}

pub fn load() -> Vec<String> {
    fs::read_to_string(path())
        .map(|c| {
            c.lines()
                .map(|l| normalize(l))
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .collect()
        })
        .unwrap_or_default()
}

/// Normalisasi: huruf kecil + separators jadi '/' supaya cocok dengan path hasil scan.
pub fn normalize(entry: &str) -> String {
    entry.trim().to_lowercase().replace('\\', "/")
}

/// Cocokkan path/nama terhadap daftar allowlist (substring, case-insensitive).
/// Daftar dimuat sekali per scan (bukan per file) demi performa.
/// Entri < 4 karakter diabaikan untuk mencegah over-match (mis. "exe" / "temp").
pub fn is_allowed(list: &[String], path_lower: &str, name_lower: &str) -> bool {
    for e in list {
        if e.len() < 4 {
            continue;
        }
        if path_lower.contains(e.as_str()) || name_lower.contains(e.as_str()) {
            return true;
        }
    }
    false
}

pub fn add(entry: &str) -> Result<String, String> {
    let e = normalize(entry);
    if e.is_empty() {
        return Err("Entri kosong.".to_string());
    }
    let p = path();
    if let Some(parent) = p.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let content = fs::read_to_string(&p).unwrap_or_default();
    for line in content.lines() {
        if line.trim().eq_ignore_ascii_case(&e) {
            return Ok(format!("Sudah ada di allowlist: {}", e));
        }
    }
    let mut new_content = content;
    new_content.push_str(&format!("{}\n", e));
    fs::write(&p, new_content).map_err(|err| err.to_string())?;
    Ok(format!("Ditambahkan ke allowlist: {}", e))
}

pub fn list() -> Vec<String> {
    load()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_handles_separators() {
        assert_eq!(normalize(r"C:\Users\X\test.exe"), "c:/users/x/test.exe");
        assert_eq!(normalize("C:/Users/X/Test.EXE"), "c:/users/x/test.exe");
    }

    #[test]
    fn short_entries_ignored() {
        let list = vec!["exe".to_string()];
        assert!(!is_allowed(&list, "c:/users/x/app.exe", "app.exe"));
    }

    #[test]
    fn path_entries_match() {
        let list = vec!["c:/users/x".to_string()];
        assert!(is_allowed(&list, "c:/users/x/app.exe", "app.exe"));
        assert!(!is_allowed(&list, "c:/users/y/app.exe", "app.exe"));
    }

    #[test]
    fn name_substring_match() {
        let list = vec!["coolinstaller".to_string()];
        assert!(is_allowed(
            &list,
            "c:/downloads/coolinstaller-v2.exe",
            "coolinstaller-v2.exe"
        ));
    }
}
