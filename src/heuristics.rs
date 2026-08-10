// Tawon - heuristik deteksi tanpa signature
pub const SUSPICIOUS_APIS: &[&str] = &[
    "VirtualAllocEx",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "NtUnmapViewOfSection",
    "QueueUserAPC",
    "SetWindowsHookExA",
    "SetWindowsHookExW",
    "AdjustTokenPrivileges",
    "CryptUnprotectData",
];

pub struct PeInfo {
    pub is_pe: bool,
    pub imports: Vec<String>,
    pub has_overlay: bool,
    pub signed: bool,    // punya tabel sertifikat (Authenticode)
    pub installer: bool, // installer self-extracting (NSIS/Inno/InstallShield/WinRAR/CAB)
}

/// Marker format installer self-extracting yang dikenal. Installer seperti ini
/// WAJAR punya entropy tinggi + overlay besar (payload terkompresi di akhir
/// file) — bukan tanda malware.
pub const INSTALLER_MARKERS: &[(&str, &str)] = &[
    ("NullsoftInst", "NSIS installer"),
    ("Inno Setup Setup Data", "Inno Setup installer"),
    ("InstallShield", "InstallShield installer"),
    ("WinRAR SFX", "WinRAR SFX"),
    ("MSCF", "CAB self-extracting"),
    ("7-Zip SFX", "7-Zip SFX"),
];

/// Deteksi marker installer di 256 KB awal + 256 KB akhir (payload installer
/// biasanya di overlay/akhir file).
pub fn detect_installer(data: &[u8]) -> Option<&'static str> {
    let head = &data[..data.len().min(256 * 1024)];
    let tail_start = data.len().saturating_sub(256 * 1024);
    let tail = &data[tail_start..];
    for &(m, name) in INSTALLER_MARKERS {
        if contains(head, m.as_bytes()) || contains(tail, m.as_bytes()) {
            return Some(name);
        }
    }
    None
}

pub fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let sample = if data.len() > 256 * 1024 {
        &data[..256 * 1024]
    } else {
        data
    };
    let mut counts = [0u64; 256];
    for &b in sample {
        counts[b as usize] += 1;
    }
    let n = sample.len() as f64;
    let mut h = 0.0f64;
    for c in counts.iter() {
        if *c == 0 {
            continue;
        }
        let p = *c as f64 / n;
        h -= p * p.log2();
    }
    h
}

/// Analisa PE (Windows executable) minimal: header, import table, overlay.
pub fn pe_info(data: &[u8]) -> PeInfo {
    let mut info = PeInfo {
        is_pe: false,
        imports: Vec::new(),
        has_overlay: false,
        signed: false,
        installer: false,
    };
    if data.len() < 0x40 || data[0] != b'M' || data[1] != b'Z' {
        return info;
    }
    let e_lfanew = u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]]) as usize;
    if e_lfanew + 24 > data.len() {
        return info;
    }
    if &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return info;
    }
    info.is_pe = true;
    let coff = e_lfanew + 4;
    if coff + 20 > data.len() {
        return info;
    }
    let n_sections = u16::from_le_bytes([data[coff + 2], data[coff + 3]]) as usize;
    let opt_size = u16::from_le_bytes([data[coff + 16], data[coff + 17]]) as usize;
    let opt = coff + 20;
    let magic = if opt + 2 <= data.len() {
        u16::from_le_bytes([data[opt], data[opt + 1]])
    } else {
        0
    };
    let is_64 = magic == 0x20b;
    // Data directory[1] = Import table, [4] = Security (cert table)
    let dd_offset = if magic == 0x10b {
        Some(opt + 0x60)
    } else if magic == 0x20b {
        Some(opt + 0x70)
    } else {
        None
    };
    // Security directory (Authenticode cert table): data directory index 4
    if let Some(dd) = dd_offset {
        let sec_off = dd + 4 * 8; // index 4, tiap entry 8 byte
        if sec_off + 8 <= data.len() {
            let cert_rva = u32::from_le_bytes([
                data[sec_off],
                data[sec_off + 1],
                data[sec_off + 2],
                data[sec_off + 3],
            ]) as usize;
            let cert_size = u32::from_le_bytes([
                data[sec_off + 4],
                data[sec_off + 5],
                data[sec_off + 6],
                data[sec_off + 7],
            ]) as usize;
            // Cert table ditunjuk via offset file, bukan RVA; valid jika ada isi
            if cert_size > 0 && cert_rva + cert_size <= data.len() {
                info.signed = true;
            }
        }
    }
    let (imp_rva, _imp_size) = if let Some(dd) = dd_offset {
        if dd + 8 <= data.len() {
            (
                u32::from_le_bytes([data[dd], data[dd + 1], data[dd + 2], data[dd + 3]]) as usize,
                u32::from_le_bytes([data[dd + 4], data[dd + 5], data[dd + 6], data[dd + 7]])
                    as usize,
            )
        } else {
            (0, 0)
        }
    } else {
        (0, 0)
    };
    // Section table: (virtual_addr, virtual_size, raw_ptr, raw_size)
    let sec_table = opt + opt_size;
    let mut secs: Vec<(usize, usize, usize, usize)> = Vec::new();
    for i in 0..n_sections.min(96) {
        let off = sec_table + i * 40;
        if off + 40 > data.len() {
            break;
        }
        let va = u32::from_le_bytes([
            data[off + 12],
            data[off + 13],
            data[off + 14],
            data[off + 15],
        ]) as usize;
        let vs = u32::from_le_bytes([data[off + 8], data[off + 9], data[off + 10], data[off + 11]])
            as usize;
        let rp = u32::from_le_bytes([
            data[off + 20],
            data[off + 21],
            data[off + 22],
            data[off + 23],
        ]) as usize;
        let rs = u32::from_le_bytes([
            data[off + 16],
            data[off + 17],
            data[off + 18],
            data[off + 19],
        ]) as usize;
        secs.push((va, vs, rp, rs));
    }
    let rva_to_off = |rva: usize| -> Option<usize> {
        for &(va, vs, rp, _rs) in &secs {
            if rva >= va && rva < va + vs {
                return Some(rp + (rva - va));
            }
        }
        None
    };
    // Parse import descriptors
    if imp_rva != 0 {
        if let Some(off) = rva_to_off(imp_rva) {
            let mut idx = off;
            loop {
                if idx + 20 > data.len() {
                    break;
                }
                let oft =
                    u32::from_le_bytes([data[idx], data[idx + 1], data[idx + 2], data[idx + 3]])
                        as usize;
                let name_rva = u32::from_le_bytes([
                    data[idx + 12],
                    data[idx + 13],
                    data[idx + 14],
                    data[idx + 15],
                ]) as usize;
                let ft = u32::from_le_bytes([
                    data[idx + 16],
                    data[idx + 17],
                    data[idx + 18],
                    data[idx + 19],
                ]) as usize;
                if oft == 0 && name_rva == 0 && ft == 0 {
                    break;
                }
                let thunk = if oft != 0 { oft } else { ft };
                if let (Some(ft_off), Some(_name_off)) = (rva_to_off(thunk), rva_to_off(name_rva)) {
                    let step = if is_64 { 8usize } else { 4usize };
                    let mut t = ft_off;
                    loop {
                        if t + step > data.len() {
                            break;
                        }
                        // IMAGE_THUNK_DATA: 4 byte (PE32) atau 8 byte (PE32+); bit tinggi = ordinal
                        let (ordinal, rva) = if is_64 {
                            let raw = u64::from_le_bytes([
                                data[t],
                                data[t + 1],
                                data[t + 2],
                                data[t + 3],
                                data[t + 4],
                                data[t + 5],
                                data[t + 6],
                                data[t + 7],
                            ]);
                            (
                                (raw & 0x8000_0000_0000_0000) != 0,
                                (raw & 0x7FFF_FFFF) as usize,
                            )
                        } else {
                            let raw = u32::from_le_bytes([
                                data[t],
                                data[t + 1],
                                data[t + 2],
                                data[t + 3],
                            ]) as u64;
                            ((raw & 0x8000_0000) != 0, (raw & 0x7FFF_FFFF) as usize)
                        };
                        if rva == 0 {
                            break;
                        }
                        if ordinal {
                            t += step;
                            continue;
                        }
                        if let Some(foff) = rva_to_off(rva) {
                            if foff + 2 <= data.len() {
                                let mut fe = foff + 2;
                                while fe < data.len() && data[fe] != 0 {
                                    fe += 1;
                                }
                                if fe < data.len() {
                                    let name =
                                        String::from_utf8_lossy(&data[foff + 2..fe]).to_string();
                                    if !info.imports.contains(&name) {
                                        info.imports.push(name);
                                    }
                                }
                            }
                        }
                        t += step;
                    }
                }
                idx += 20;
            }
        }
    }
    // Overlay: data besar di luar seksi terakhir (tanda packing/append)
    let mut max_raw_end = 0usize;
    for &(_, _, rp, rs) in &secs {
        let e = rp + rs;
        if e > max_raw_end {
            max_raw_end = e;
        }
    }
    if data.len() > max_raw_end + 0x8000 {
        info.has_overlay = true;
    }
    // Installer self-extracting = overlay besar itu normal
    if detect_installer(data).is_some() {
        info.installer = true;
    }
    info
}

/// Deteksi PE lain yang disembunyikan di dalam file (offset > 0).
pub fn embedded_pe(data: &[u8]) -> bool {
    let limit = data.len().min(1024 * 1024);
    for i in 1..limit.saturating_sub(1) {
        if data[i] == b'M' && data[i + 1] == b'Z' {
            if i + 0x40 + 4 <= data.len() {
                let e = u32::from_le_bytes([
                    data[i + 0x3c],
                    data[i + 0x3d],
                    data[i + 0x3e],
                    data[i + 0x3f],
                ]) as usize;
                if e < 0x1000 && i + e + 4 <= data.len() && &data[i + e..i + e + 4] == b"PE\0\0" {
                    return true;
                }
            }
        }
    }
    false
}

/// Ekstensi ganda mencurigakan: file.exe.pdf, file.pdf.exe, dst.
pub fn double_extension(name: &str) -> bool {
    let exe_exts = [
        "exe", "scr", "bat", "cmd", "js", "vbs", "hta", "jar", "com", "pif", "lnk", "ps1",
    ];
    let benign_exts = [
        "pdf", "jpg", "jpeg", "png", "gif", "doc", "docx", "xls", "xlsx", "txt", "zip", "rar",
        "7z", "mp3", "mp4", "avi", "mov", "svg",
    ];
    let lower = name.to_lowercase();
    let parts: Vec<&str> = lower.split('.').collect();
    if parts.len() < 3 {
        return false;
    }
    let last = parts.last().unwrap_or(&"");
    let prev = parts[parts.len() - 2];
    (exe_exts.contains(&last) && benign_exts.contains(&prev))
        || (exe_exts.contains(&prev) && benign_exts.contains(&last))
}

fn printable_ratio(sample: &[u8]) -> f64 {
    if sample.is_empty() {
        return 1.0;
    }
    let mut printable = 0usize;
    for &b in sample {
        // printable ASCII, tab/newline/CR, atau byte UTF-8 multi-byte (>= 0x80)
        if (0x20..=0x7e).contains(&b)
            || matches!(b, b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)
            || b >= 0x80
        {
            printable += 1;
        }
    }
    printable as f64 / sample.len() as f64
}

/// Apakah konten terlihat seperti teks (script/plain) dan bukan data binary?
/// Rule/heuristik teks HANYA berlaku untuk file teks: pola pendek seperti
/// "-enc " atau "iex(" bisa muncul secara kebetulan di DLL/EXE (string library,
/// offset, dll) dan memicu false positive. Fungsi ini memblokir itu.
pub fn looks_like_text(data: &[u8]) -> bool {
    text_stream(data).is_some()
}

/// Ekstrak stream teks yang bisa dicari rule, atau None jika file binary.
/// Menangani ASCII/UTF-8 biasa DAN UTF-16LE/BE (script PowerShell sering
/// disimpan Unicode: tiap karakter diikuti byte 0x00).
pub fn text_stream(data: &[u8]) -> Option<Vec<u8>> {
    let sample = &data[..data.len().min(64 * 1024)];
    if sample.is_empty() {
        return Some(Vec::new());
    }
    if printable_ratio(sample) >= 0.92 {
        return Some(sample.to_ascii_lowercase());
    }
    // UTF-16: banyak byte 0x00 di posisi tetap. Coba de-interleave tiap 2 byte.
    let nuls = sample.iter().filter(|&&b| b == 0).count();
    if nuls * 4 >= sample.len() {
        for offset in 0usize..2 {
            let de: Vec<u8> = sample.iter().skip(offset).step_by(2).copied().collect();
            if printable_ratio(&de) >= 0.92 {
                return Some(de.to_ascii_lowercase());
            }
        }
    }
    None
}

/// Indikator script berbahaya (PowerShell/cmd) dalam konten.
/// Hanya berlaku untuk file teks (anti false-positive pada binary).
pub fn script_indicators(data: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let limit = data.len().min(1024 * 1024);
    let Some(low) = text_stream(&data[..limit]) else {
        return out;
    };
    let needles = [
        ("-encodedcommand", "encoded PowerShell command"),
        ("-enc ", "encoded PowerShell command (short)"),
        ("frombase64string", "base64 decoding in script"),
        (
            "iex(new-object net.webclient).downloadstring",
            "PowerShell download cradle",
        ),
        ("iex(", "iex (invoke-expression) execution"),
        ("powershell.exe -w hidden", "hidden PowerShell execution"),
        ("-windowstyle hidden", "hidden window execution"),
    ];
    for (n, d) in needles {
        if contains(&low, n.as_bytes()) {
            out.push(d.to_string());
        }
    }
    out
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || hay.len() < needle.len() {
        return false;
    }
    'outer: for i in 0..=(hay.len() - needle.len()) {
        for (j, n) in needle.iter().enumerate() {
            if hay[i + j] != *n {
                continue 'outer;
            }
        }
        return true;
    }
    false
}

pub fn suspicious_location(path: &str) -> bool {
    let p = path.to_lowercase();
    p.contains("\\temp\\")
        || p.contains("\\downloads\\")
        || p.contains("\\appdata\\local\\temp")
        || p.contains("\\recycle.bin")
}

pub fn file_name(path: &str) -> String {
    path.rsplit(['/', '\\']).next().unwrap_or(path).to_string()
}

/// Susun skor heuristik (0-100+) beserta alasan (tanpa signature rules).
pub fn score_file(path: &str, data: &[u8], pe: &PeInfo) -> (u32, Vec<String>) {
    let mut score: u32 = 0;
    let mut reasons: Vec<String> = Vec::new();

    // Installer self-extracting & file bertanda tangan digital WAJAR punya
    // entropy tinggi + overlay besar (payload terkompresi) -> bukan tanda malware.
    let benign_packed = pe.installer || pe.signed;

    let ent = entropy(data);
    if ent > 7.2 && !benign_packed {
        score += 20;
        reasons.push(format!(
            "entropy tinggi ({:.2}, kemungkinan terkompresi/terenkripsi)",
            ent
        ));
    }

    if pe.is_pe {
        let susp: Vec<&String> = pe
            .imports
            .iter()
            .filter(|i| SUSPICIOUS_APIS.contains(&i.as_str()))
            .collect();
        if !susp.is_empty() {
            let joined = susp
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<&str>>()
                .join(", ");
            score += 30;
            reasons.push(format!("API injeksi terdeteksi: {}", joined));
        }
        if pe.has_overlay && !pe.installer {
            score += 15;
            reasons.push("overlay/data tambahan besar (tanda packer/append)".to_string());
        }
        if embedded_pe(data) {
            score += 20;
            reasons.push("PE tersembunyi di dalam file".to_string());
        }
    }

    if double_extension(&file_name(path)) {
        score += 20;
        reasons.push("ekstensi ganda mencurigakan".to_string());
    }

    for s in script_indicators(data) {
        score += 10;
        reasons.push(s);
    }

    if suspicious_location(path) {
        score += 15;
        reasons.push("lokasi berisiko (temp/downloads)".to_string());
    }

    (score, reasons)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_high_for_random() {
        let mut data = Vec::new();
        let mut seed: u64 = 0x1234_5678_9abc_def0;
        for _ in 0..4096 {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            data.push((seed >> 32) as u8);
        }
        let e = entropy(&data);
        assert!(e > 7.9, "entropy {} harus dekat 8", e);
    }

    #[test]
    fn entropy_low_for_repeating() {
        let data = vec![b'A'; 4096];
        assert!(entropy(&data) < 0.01);
    }

    #[test]
    fn double_extension_detected() {
        assert!(double_extension("invoice.pdf.exe"));
        assert!(double_extension("setup.exe.png"));
        assert!(!double_extension("setup.exe"));
        assert!(!double_extension("report.pdf"));
    }

    #[test]
    fn pe_detection_valid() {
        let mut d = vec![0u8; 0x100];
        d[0] = b'M';
        d[1] = b'Z';
        d[0x3c] = 0x40; // e_lfanew = 0x40
        d[0x40] = b'P';
        d[0x41] = b'E';
        d[0x42] = 0;
        d[0x43] = 0;
        d[0x44] = 0x0b;
        d[0x45] = 0x01; // magic PE32 (0x10b)
        let info = pe_info(&d);
        assert!(info.is_pe);
    }

    #[test]
    fn pe_detection_malformed_no_panic() {
        let d = b"MZgarbage-bukan-pe-lengkap";
        assert!(!pe_info(d).is_pe);
        // magic tidak dikenal harus aman (regresi overflow usize::MAX)
        let mut d2 = vec![0u8; 0x200];
        d2[0] = b'M';
        d2[1] = b'Z';
        d2[0x3c] = 0x40;
        d2[0x40] = b'P';
        d2[0x41] = b'E';
        d2[0x42] = 0;
        d2[0x43] = 0;
        d2[0x44] = 0xff;
        d2[0x45] = 0xff; // magic tidak valid
                         // Tidak boleh panic & tidak boleh parse import dari data sampah (regresi overflow)
        let info = pe_info(&d2);
        assert!(info.imports.is_empty());
    }

    #[test]
    fn embedded_pe_detection() {
        let mut d = vec![0u8; 0x200];
        d[0x80] = b'M';
        d[0x81] = b'Z';
        d[0x80 + 0x3c] = 0x40;
        d[0xc0] = b'P';
        d[0xc1] = b'E';
        d[0xc2] = 0;
        d[0xc3] = 0;
        assert!(embedded_pe(&d));
    }

    #[test]
    fn binary_content_not_text() {
        let mut data = vec![0u8; 8192];
        for (i, b) in data.iter_mut().enumerate() {
            *b = ((i * 13 + 3) % 256) as u8;
        }
        assert!(!looks_like_text(&data));
        assert!(script_indicators(&data).is_empty());
    }
    #[test]
    fn text_content_is_text() {
        let script = b"$x = powershell -EncodedCommand abcdef\nWrite-Host hello\n";
        assert!(looks_like_text(script));
        assert!(script_indicators(script)
            .iter()
            .any(|s| s.contains("encoded")));
    }

    #[test]
    fn utf16_script_detected() {
        // Script UTF-16LE: tiap karakter ASCII diikuti 0x00
        let ascii = b"$x = powershell -EncodedCommand ABCDEF";
        let mut utf16 = Vec::with_capacity(ascii.len() * 2);
        for &b in ascii {
            utf16.push(b);
            utf16.push(0);
        }
        assert!(
            looks_like_text(&utf16),
            "script UTF-16 harus dikenali sebagai teks"
        );
        assert!(
            script_indicators(&utf16)
                .iter()
                .any(|s| s.contains("encoded")),
            "script UTF-16 dengan -EncodedCommand harus terdeteksi"
        );
    }

    #[test]
    fn short_enc_in_binary_does_not_raise_script_score() {
        let mut data = vec![0u8; 4096];
        for (i, b) in data.iter_mut().enumerate() {
            *b = ((i * 31 + 7) % 251) as u8;
        }
        data[100..105].copy_from_slice(b"-enc ");
        let pe = PeInfo {
            is_pe: false,
            imports: Vec::new(),
            has_overlay: false,
            signed: false,
            installer: false,
        };
        let (score, reasons) = score_file("C:/x/lib.dll", &data, &pe);
        // entropy tinggi boleh menambah skor, tapi TIDAK BOLEH ada alasan script
        assert!(
            !reasons
                .iter()
                .any(|r| r.contains("encoded") || r.contains("PowerShell")),
            "binary dengan '-enc ' tidak boleh terflag script: {:?}",
            reasons
        );
        assert!(
            score < 30,
            "tanpa alasan script, binary acak tidak boleh CURIGA: {:?}",
            reasons
        );
    }

    #[test]
    fn suspicious_api_imports_raise_score() {
        let data = b"some plain data";
        let pe_bad = PeInfo {
            is_pe: true,
            imports: vec!["CreateRemoteThread".to_string(), "Sleep".to_string()],
            has_overlay: false,
            signed: false,
            installer: false,
        };
        let (score, _) = score_file("C:/x/y.exe", data, &pe_bad);
        assert!(score >= 30);

        let pe_ok = PeInfo {
            is_pe: true,
            imports: vec!["Sleep".to_string()],
            has_overlay: false,
            signed: false,
            installer: false,
        };
        let (score2, _) = score_file("C:/x/y.exe", data, &pe_ok);
        assert!(score2 < 30);
    }

    #[test]
    fn installer_marker_detected() {
        let mut data = vec![0u8; 512 * 1024];
        for (i, b) in data.iter_mut().enumerate() {
            *b = ((i * 31 + 7) % 251) as u8;
        }
        let tail = data.len() - 50;
        data[tail..tail + 12].copy_from_slice(b"NullsoftInst");
        assert_eq!(detect_installer(&data), Some("NSIS installer"));
    }

    #[test]
    fn installer_no_entropy_overlay_penalty() {
        // Installer self-extracting: entropy tinggi + overlay = NORMAL, skor tetap rendah
        let mut data = vec![0u8; 512 * 1024];
        for (i, b) in data.iter_mut().enumerate() {
            *b = ((i * 31 + 7) % 251) as u8;
        }
        let tail = data.len() - 50;
        data[tail..tail + 12].copy_from_slice(b"NullsoftInst");
        let pe = PeInfo {
            is_pe: true,
            imports: Vec::new(),
            has_overlay: true,
            signed: false,
            installer: true,
        };
        let (score, reasons) = score_file("C:/x/setup.exe", &data, &pe);
        assert!(
            score < 30,
            "installer sah tidak boleh CURIGA: skor={} reasons={:?}",
            score,
            reasons
        );
        assert!(!reasons
            .iter()
            .any(|r| r.contains("entropy") || r.contains("overlay")));
    }

    #[test]
    fn signed_pe_no_entropy_penalty() {
        // File bertanda tangan digital: entropy tinggi wajar (payload terkompresi)
        let mut data = vec![0u8; 4096];
        for (i, b) in data.iter_mut().enumerate() {
            *b = ((i * 31 + 7) % 251) as u8;
        }
        let pe = PeInfo {
            is_pe: true,
            imports: Vec::new(),
            has_overlay: false,
            signed: true,
            installer: false,
        };
        let (score, reasons) = score_file("C:/x/app.exe", &data, &pe);
        assert!(
            score < 30,
            "file signed tidak boleh CURIGA dari entropy saja: skor={} reasons={:?}",
            score,
            reasons
        );
    }

    #[test]
    fn unsigned_packed_pe_still_suspicious() {
        // Malware packed: unsigned + entropy tinggi + overlay -> tetap CURIGA
        let mut data = vec![0u8; 4096];
        for (i, b) in data.iter_mut().enumerate() {
            *b = ((i * 31 + 7) % 251) as u8;
        }
        let pe = PeInfo {
            is_pe: true,
            imports: Vec::new(),
            has_overlay: true,
            signed: false,
            installer: false,
        };
        let (score, _) = score_file("C:/x/packed.exe", &data, &pe);
        assert!(
            score >= 30,
            "packed unsigned harus tetap mencurigakan: {}",
            score
        );
    }
}
