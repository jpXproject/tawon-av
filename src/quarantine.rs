// Tawon - karantina: pindahkan file berbahaya ke folder aman + manifest untuk restore
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

fn home() -> PathBuf {
    std::env::var_os("USERPROFILE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

pub fn qdir() -> PathBuf {
    home().join(".tawon").join("quarantine")
}

pub fn manifest() -> PathBuf {
    home().join(".tawon").join("index.tsv")
}

/// Pindahkan file ke karantina. Kembalikan ID karantina.
pub fn quarantine_file(src: &Path, sha: &str) -> Result<String, String> {
    let dir = qdir();
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let name = src
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "file".to_string());
    let id = format!("{}_{}", &sha[..sha.len().min(12)], std::process::id());
    let dest = dir.join(format!("{}_{}", id, name));

    // rename dulu; kalau beda drive, copy + hapus
    fs::rename(src, &dest)
        .or_else(|_| {
            fs::copy(src, &dest)?;
            fs::remove_file(src)
        })
        .map_err(|e| e.to_string())?;

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let line = format!(
        "{}\t{}\t{}\t{}\t{}\n",
        id,
        src.to_string_lossy(),
        dest.to_string_lossy(),
        ts,
        sha
    );
    let _ = fs::create_dir_all(home().join(".tawon"));
    let mut content = fs::read_to_string(manifest()).unwrap_or_default();
    content.push_str(&line);
    fs::write(manifest(), content).map_err(|e| e.to_string())?;
    Ok(id)
}

/// Daftar isi karantina: (id, path_original, path_karantina)
pub fn list() -> Vec<(String, String, String)> {
    fs::read_to_string(manifest())
        .map(|c| {
            c.lines()
                .filter_map(|l| {
                    let p: Vec<&str> = l.split('\t').collect();
                    if p.len() >= 3 {
                        Some((p[0].to_string(), p[1].to_string(), p[2].to_string()))
                    } else {
                        None
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Kembalikan file dari karantina ke lokasi asal.
pub fn restore(id: &str) -> Result<String, String> {
    let items = list();
    if let Some((_, orig, q)) = items.into_iter().find(|(i, _, _)| i == id) {
        if !Path::new(&q).exists() {
            return Err(format!("File karantina tidak ditemukan: {}", q));
        }
        if let Some(parent) = Path::new(&orig).parent() {
            let _ = fs::create_dir_all(parent);
        }
        fs::rename(&q, &orig).map_err(|e| e.to_string())?;
        let content = fs::read_to_string(manifest()).unwrap_or_default();
        let kept: Vec<&str> = content
            .lines()
            .filter(|l| !l.starts_with(&format!("{}\t", id)))
            .collect();
        fs::write(manifest(), kept.join("\n") + "\n").map_err(|e| e.to_string())?;
        Ok(format!("{} dipulihkan ke {}", id, orig))
    } else {
        Err(format!("ID karantina tidak ditemukan: {}", id))
    }
}
