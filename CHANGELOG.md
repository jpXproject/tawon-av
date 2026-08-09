# Changelog

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
