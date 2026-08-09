# 🐝 Tawon — A lightweight yet potent AV

> *"Quiet, but it stings."*

![Rust](https://img.shields.io/badge/Rust-1.97%2B-orange?style=flat-square&logo=rust&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)
![CI](https://img.shields.io/badge/CI-GitHub%20Actions-2088FF?style=flat-square&logo=githubactions&logoColor=white)
![Tests](https://img.shields.io/badge/Tests-17%20passed-brightgreen?style=flat-square)
![Size](https://img.shields.io/badge/Size-%7E500%20KB-brightgreen?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Windows-informational?style=flat-square&logo=windows&logoColor=white)

<!-- After pushing to GitHub, swap the CI & License badges for dynamic ones (replace <user>):
![CI](https://img.shields.io/github/actions/workflow/status/<user>/tawon-av/ci.yml?style=flat-square)
![License](https://img.shields.io/github/license/<user>/tawon-av?style=flat-square)
-->

![Logo](docs/logo.png)

![Demo scan](docs/demo-scan.png)

*A real scan: EICAR test file detected (`[BAHAYA]`), system forensics and quarantine in action.*

A personal antivirus written in **Rust**: a single ~500 KB binary, no runtime
dependencies, memory-safe, minimal resource usage — comfortable even on a
15-year-old PC.

**Philosophy: *stay quiet unless sure.*** No noise, no false-flagging of
innocent software:
- **DANGER** only for: matching hash (certain) or critical signature / score ≥ 70 (high confidence)
- **SUSPICIOUS** = light heuristic → informational only, **never auto-deleted or quarantined**
- **Allowlist** → trusted files/folders are never reported again

## ✨ Features

| Feature | Description |
|---|---|
| 🔬 **Tiered signature scanning** | `HASH` (certain) · `HEX` (high, `??` wildcards) · `TEXT!` (critical) · `TEXT` (medium) |
| 🧠 **Heuristics** | Parses real PE (32 & **64-bit**) → API injection (`CreateRemoteThread`, `VirtualAllocEx`, …), overlay/packer, embedded PE, entropy, encoded PowerShell, double extensions, risky locations |
| 🗄️ **Quarantine** | Manual + restore (explicit `--quarantine`) |
| 👁️ **Folder watch** | `tawon watch` (lightweight polling, report-only) |
| 🩺 **System forensics** | `tawon forensik` — Event 41/6008, WHEA, crash dumps, top RAM/CPU processes, network connections, disk, system errors |
| 🧹 **Startup & process audit** | `tawon startup` / `tawon proc` |
| 🛡️ **Allowlist** | `tawon allow <path>` — trusted files stay quiet forever |
| 🧪 **Self-test** | `tawon eicar` |

## 🚀 Install / Build

```bash
git clone https://github.com/<you>/tawon-av.git
cd tawon-av
cargo build --release          # requires Rust (stable)
# result: target/release/tawon.exe → copy to a PATH folder (e.g. C:\Users\you\sec-tools\)
```

## 📖 Usage

```bash
tawon scan C:\Users\you\Downloads             # scan (report only)
tawon scan --quiet <path>                      # show only DANGER
tawon scan --quarantine <path>                 # scan + quarantine threats
tawon quick                                    # quick scan of risky locations
tawon watch <folder> 10                        # watch every 10 seconds
tawon forensik                                 # forensics & health report
tawon startup / tawon proc                     # audit persistence & processes
tawon quarantine list | restore <ID>           # manage quarantine
tawon allow <path>                             # trust a file/folder
tawon eicar                                    # create an EICAR test file
```

## 🔧 Custom rules

Edit `%USERPROFILE%\.tawon\rules.txt`:

```
HASH|9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08|description
HEX|4D 5A 90 00 ?? 00|description
TEXT!|very-evil|description     # critical → DANGER
TEXT|somewhat-suspicious|description       # medium → only raises the score
```

## ⚖️ Comparison

See [COMPARISON.md](COMPARISON.md) for an honest comparison with
**Smadav** (Indonesian AV) and **ClamAV** (international open-source AV).

## 🗺️ Roadmap

- [x] Signature + heuristic scanner + quarantine
- [x] System forensics, startup/process audit, allowlist, quiet mode
- [ ] Anti-rootkit / hidden process detection
- [ ] Real-time mode (ReadDirectoryChangesW) without polling
- [ ] Small GUI (tray) — contributors welcome
- [ ] Public signature database (community-driven)

## ⚠️ Disclaimer

Tawon is a **personal/educational** security tool, not a replacement for
commercial AV (no cloud/ML/research team). Use it as a complement, not as your
only line of defense. Always verify files before restoring from quarantine.

## 📄 License

[MIT](LICENSE)

---

**🇮🇩 Bahasa Indonesia:** [README.id.md](README.id.md)

---

*Demo screenshot generated from the real `tawon` CLI output.*
