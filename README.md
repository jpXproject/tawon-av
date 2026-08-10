# 🐝 Tawon — A lightweight yet potent ANTI VIRUS

> *"Quiet, but it stings."*

![Rust](https://img.shields.io/badge/Rust-1.97%2B-orange?style=flat-square&logo=rust&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)
![CI](https://img.shields.io/badge/CI-GitHub%20Actions-2088FF?style=flat-square&logo=githubactions&logoColor=white)
![Tests](https://img.shields.io/badge/Tests-26%20passed-brightgreen?style=flat-square)
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
| 🐝 **System tray monitor** | `scripts/TawonTray.ps1` — quiet background scans + notifications (DANGER only) |
| 🚫 **Anti-false-positive by design** | Text rules only apply to text files; short patterns (`-enc `) are medium, not critical; UTF-16 scripts still detected |

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

## 🐝 System Tray Monitor (optional)

For people who want background monitoring without opening a terminal — a
lightweight tray icon at the bottom-right, true to the *"quiet unless sure"*
philosophy:

- **Auto-scans** your watched folders (default: `Downloads`, `Desktop`) every **30 min** (configurable)
- **Icons**: wasp 🐝 (yellow = healthy) → red ⚠️ (threat found) with a notification
- **Double-click** → scan now · **right-click menu** → quick scan, forensics, startup audit, quarantine, edit watched folders, exit
- **No console window**, minimal RAM (starts `tawon.exe` per interval)

```powershell
# 1. Start it (via the hidden launcher, no console flash):
wscript.exe "scripts\Start Tawon Monitor.vbs"

# 2. Auto-start at login: place "Start Tawon Monitor.vbs" (or a shortcut to it)
#    in the Startup folder:
#    shell:startup
```

**Config** (`%USERPROFILE%\.tawon\monitor.conf`) — per-folder intervals:

```ini
interval = 30                        # default interval (minutes)
C:\Users\you\Downloads               # uses the default interval
C:\Users\you\Desktop = 10            # scans every 10 min
C:\Users\you\Documents = 60          # scans every 60 min
```

The monitor ticks every 60 seconds and scans only the folders whose interval is due — so `Desktop` can be watched closely while `Documents` is checked hourly.

Files: `scripts/TawonTray.ps1` (monitor) · `scripts/Start Tawon Monitor.vbs` (hidden launcher) · `docs/tawon.ico` + `docs/tawon-warn.ico` (icons).

## 🚫 Anti-False-Positive, by Design

Most AVs annoy people by flagging innocent software. Tawon treats
false positives as a **design bug**, with three layers of defense:

1. **Text rules only apply to text files.** Short patterns like `-enc ` or
   `iex(` can appear *by coincidence* in the string tables of legit DLLs/EXEs
   (e.g. `Qt6Network.dll`, `libcrypto-1_1-x64.dll`). A `looks_like_text()`
   check (printable-byte ratio over a 64 KB sample) blocks all `TEXT`
   (medium) rules on binary content — **no more false DANGER on DLLs**.
2. **Length-aware criticality.** A bare `-enc ` is only *suspicious* (score
   bump), while the full `-EncodedCommand` or an `IEX(New-Object...)` cradle
   stays **critical**. Long, unambiguous patterns are still matched inside
   binaries, so a compiled dropper embedding a PowerShell string is still
   caught.
3. **UTF-16 aware.** PowerShell malware is often saved as UTF-16LE (each
   character followed by `0x00`). `looks_like_text()` de-interleaves UTF-16,
   so malicious scripts are detected regardless of encoding.

Combined with the tiered verdicts (`hash`/critical → DANGER, light heuristic →
informational only) and the allowlist, Tawon keeps scans *quiet unless sure*:

```
Before:  NotepadNext.exe / Qt6Network.dll / libcrypto DLL → [BAHAYA]  (false)
After:   same folder                        → 0 threats, 0 suspicious
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
**Smadav** (Indonesian anti-virus) and **ClamAV** (international open-source anti-virus).

## 🗺️ Roadmap

- [x] Signature + heuristic scanner + quarantine
- [x] System forensics, startup/process audit, allowlist, quiet mode
- [x] System tray monitor (background, anti-false-positive)
- [ ] Anti-rootkit / hidden process detection
- [ ] Real-time mode (ReadDirectoryChangesW) without polling
- [ ] Public signature database (community-driven)

## ⚠️ Disclaimer

Tawon is a **personal/educational** security tool, not a replacement for
commercial anti-virus (no cloud/ML/research team). Use it as a complement, not as your
only line of defense. Always verify files before restoring from quarantine.

## 📄 License

[MIT](LICENSE)

---

**🇮🇩 Bahasa Indonesia:** [README.id.md](README.id.md)

---

*Demo screenshot generated from the real `tawon` CLI output.*
