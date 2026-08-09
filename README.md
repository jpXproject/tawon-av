# 🐝 Tawon — AV ringan tapi sakti

> *"Diam, tapi menyengat."*

![Rust](https://img.shields.io/badge/Rust-1.97%2B-orange?style=flat-square&logo=rust&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)
![CI](https://img.shields.io/badge/CI-GitHub%20Actions-2088FF?style=flat-square&logo=githubactions&logoColor=white)
![Tests](https://img.shields.io/badge/Tests-17%20passed-brightgreen?style=flat-square)
![Size](https://img.shields.io/badge/Size-%7E500%20KB-brightgreen?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Windows-informational?style=flat-square&logo=windows&logoColor=white)

<!-- Setelah repo di-push ke GitHub, ganti badge CI & License dengan versi dinamis (ganti <user>):
![CI](https://img.shields.io/github/actions/workflow/status/<user>/tawon-av/ci.yml?style=flat-square)
![License](https://img.shields.io/github/license/<user>/tawon-av?style=flat-square)
-->

![Logo](docs/logo.png)

Antivirus pribadi berbasis **Rust**: satu biner ~500 KB, tanpa ketergantungan
runtime, memory-safe, minim resource — nyaman dijalankan bahkan di PC berusia
15 tahun.

**Filosofi: *diam kalau tidak yakin*.** Tidak berisik, tidak salah tangkap
software yang tidak berbahaya:
- **BAHAYA** hanya untuk: hash cocok (pasti) atau signature kritis / skor ≥ 70 (sangat yakin)
- **CURIGA** = heuristik ringan → hanya informasi, **tidak pernah dihapus/karantina otomatis**
- **Allowlist** → file/folder tepercaya tidak pernah dilaporkan lagi

## ✨ Fitur

| Fitur | Deskripsi |
|---|---|
| 🔬 **Scan signature bertingkat** | `HASH` (pasti) · `HEX` (tinggi, wildcard `??`) · `TEXT!` (kritis) · `TEXT` (medium) |
| 🧠 **Heuristik** | Parse PE asli (32 & **64-bit**) → API injeksi (`CreateRemoteThread`, `VirtualAllocEx`, …), overlay/packer, PE tersembunyi, entropy, PowerShell encoded, ekstensi ganda, lokasi berisiko |
| 🗄️ **Karantina** | Manual + restore (`--quarantine` eksplisit) |
| 👁️ **Pemantau folder** | `tawon watch` (polling ringan, laporan saja) |
| 🩺 **Forensik sistem** | `tawon forensik` — Event 41/6008, WHEA, crash dump, proses top RAM/CPU, koneksi jaringan, disk, error sistem |
| 🧹 **Audit startup & proses** | `tawon startup` / `tawon proc` |
| 🛡️ **Allowlist** | `tawon allow <path>` — file tepercaya diam selamanya |
| 🧪 **Self-test** | `tawon eicar` |

## 🚀 Install / Build

```bash
git clone https://github.com/<kamu>/tawon-av.git
cd tawon-av
cargo build --release          # butuh Rust (stable)
# hasil: target/release/tawon.exe → salin ke PATH (mis. C:\Users\kamu\sec-tools\)
```

## 📖 Penggunaan

```bash
tawon scan C:\Users\kamu\Downloads             # scan (laporan saja)
tawon scan --quiet <path>                      # hanya tampilkan BAHAYA
tawon scan --quarantine <path>                 # scan + karantina ancaman
tawon quick                                    # scan cepat lokasi berisiko
tawon watch <folder> 10                        # pantau tiap 10 detik
tawon forensik                                 # laporan forensik & kesehatan
tawon startup / tawon proc                     # audit persistence & proses
tawon quarantine list | restore <ID>           # kelola karantina
tawon allow <path>                             # percaya file/folder
tawon eicar                                    # buat file uji EICAR
```

## 🔧 Rules kustom

Edit `%USERPROFILE%\.tawon\rules.txt`:

```
HASH|9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08|deskripsi
HEX|4D 5A 90 00 ?? 00|deskripsi
TEXT!|sangat-jahat|deskripsi     # kritis → BAHAYA
TEXT|agak-curiga|deskripsi       # medium → hanya menaikkan skor
```

## ⚖️ Perbandingan

Lihat [COMPARISON.md](COMPARISON.md) untuk perbandingan jujur dengan
**Smadav** (AV Indonesia) dan **ClamAV** (AV open-source internasional).

## 🗺️ Roadmap

- [x] Scanner signature + heuristik + karantina
- [x] Forensik sistem, audit startup/proses, allowlist, mode senyap
- [ ] Deteksi anti-rootkit / proses tersembunyi
- [ ] Mode real-time (ReadDirectoryChangesW) tanpa polling
- [ ] GUI kecil (tray) — kontributor dipersilakan
- [ ] Database signature publik (community-driven)

## ⚠️ Disclaimer

Tawon adalah alat keamanan **pribadi/edukasi**, bukan pengganti AV komersial
(tanpa cloud/ML/tim peneliti). Gunakan sebagai pelengkap, bukan satu-satunya
pertahanan. Selalu verifikasi file sebelum restore dari karantina.

## 📄 Lisensi

[MIT](LICENSE)
