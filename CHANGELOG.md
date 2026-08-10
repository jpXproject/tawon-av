# Changelog

## [0.1.2] - 2026-08-10
### Added
- **Anti-false-positive by design**: rule teks (`TEXT`/`TEXT!`) hanya
  dicocokkan pada file teks (`looks_like_text()`: rasio byte printable 64 KB),
  sehingga DLL/EXE sah tidak lagi salah terflag.
- **Deteksi installer self-extracting** (NSIS/Inno Setup/InstallShield/WinRAR
  SFX/CAB/7-Zip SFX): entropy tinggi + overlay besar adalah normal untuk
  installer — tidak lagi dihitung sebagai mencurigakan.
- **Deteksi tanda tangan digital (Authenticode)**: parse PE Security Directory
  (validasi `NumberOfRvaAndSizes > 4`, `rva != 0`, `size >= 512`) — file
  bertanda tangan tidak dihitung entropy.
- **Dukungan script UTF-16** (LE/BE): script PowerShell malware ber-encoding
  Unicode kini terdeteksi (de-interleave byte `0x00`).
- **Monitor system tray**: `scripts/TawonTray.ps1` + launcher tersembunyi
  `scripts/Start Tawon Monitor.vbs` + ikon `docs/tawon.ico` — scan background
  berkala (default 30 menit), notifikasi hanya saat BAHAYA, auto-start saat
  login opsional.

### Changed
- Rule `-enc ` (pendek) turun dari kritis ke medium — script dengan `-enc`
  cukup CURIGA; BAHAYA butuh bukti lain (mis. `-EncodedCommand` penuh).
- Rule kritis panjang (`TEXT!`, mis. `-EncodedCommand`, download cradle)
  tetap aktif di binary — dropper EXE berisi string PowerShell tetap kena.
- Title & istilah README: "AV" → "ANTI VIRUS" (ramah orang awam).
- README/README.id: dokumentasi tray monitor + anti-false-positive.

### Fixed
- False positive `NotepadNext.dll` / `Qt6Network.dll` / `libcrypto`
  (heuristik "PowerShell encoded" di binary) — sekarang bersih.
- False positive `GoogleCloudSDKInstaller.exe` (installer NSIS) — sekarang bersih.
- Self false-positive pada build artifacts (`target/debug`, `target/release`,
  `target/incremental`) — sekarang dilewati.
- `installer` hanya di-set untuk PE (file teks yang menyebut "NullsoftInst"
  bukan installer).

### Tests
- 32 test (bertambah 6): binary berisi `-enc ` tidak terflag, script UTF-16
  terdeteksi, installer/signed tidak kena penalti entropy+overlay, packed
  unsigned tetap CURIGA, PE Security Directory signed flag.

## [0.1.1] - 2026-08-10
### Added
- `tawon forensik` — laporan forensik & kesehatan sistem (Event 41/6008, WHEA,
  crash dump, proses top RAM/CPU, koneksi jaringan, disk, error sistem).
- Allowlist: `tawon allow <path>` — file/folder tepercaya tidak pernah dilaporkan.
- Mode senyap: `scan --quiet` — hanya menampilkan ancaman (BAHAYA).
- Tingkat keyakinan rules: `TEXT!` (kritis) vs `TEXT` (medium) vs `HASH` (pasti).

### Changed
- Verdict baru: BAHAYA hanya untuk hash match / skor >= 70. Heuristik ringan
  menjadi CURIGA (informasional, tidak pernah otomatis dihapus).
- `quick` dan `watch` tidak lagi mengkarantina otomatis (laporan saja).
- Rules medium tidak lagi bisa menaikkan skor tanpa batas.

### Fixed
- Parser import PE32+ (64-bit) membaca thunk 8-byte dengan benar.
- Overflow `usize::MAX + 8` pada PE dengan magic rusak.
- Allowlist normalisasi separator path (`\` vs `/`).
- Allowlist dibaca sekali per scan (bukan per file).

## [0.1.0] - 2026-08-10
### Added
- Scanner signature: HASH sha256, pola HEX (wildcard), pola TEXT.
- Heuristik: entropy, parse PE (32/64-bit) & API injeksi, overlay/packer,
  PE tersembunyi, ekstensi ganda, PowerShell encoded, lokasi berisiko.
- Karantina dengan restore.
- `tawon watch` — pemantau folder ringan (polling).
- `tawon startup` / `tawon proc` — audit persistence & proses.
- `tawon eicar` — self-test.
