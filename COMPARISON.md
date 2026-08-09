# Comparison: Tawon vs Smadav vs ClamAV

An honest comparison between **Tawon** (a personal Rust-based AV), **Smadav**
(Indonesian AV, focused on USB protection), and **ClamAV** (international
open-source AV from Cisco Talos, focused on servers/mail gateways).

> ⚠️ Important note: Tawon is not a replacement for either. Tawon is a
> personal security tool — transparent, lightweight, no popups — suitable as a
> complement, an audit tool, and an educational project. Commercial tools like
> Smadav/ClamAV have signature databases in the millions plus research teams
> and automatic updates.

## Comparison Table

| Aspect | 🐝 Tawon | 🇮🇩 Smadav | 🌍 ClamAV |
|---|---|---|---|
| **Platform** | Windows (CLI) | Windows XP–11 (32/64-bit) | Windows, Linux, macOS, BSD |
| **Language** | Rust (memory-safe) | Proprietary | C/C++ |
| **Signature detection** | SHA-256 hashes, HEX patterns, text patterns (custom) | Smadav signature database + **Smadav-AI (ML)** | Millions of Cisco Talos signatures + bytecode |
| **Heuristics** | Yes (entropy, PE parsing & API injection, encoded scripts, double extensions) | Yes + AI/ML | Yes (bytecode, heuristics) |
| **Real-time detection** | No (has manual `watch` polling) | Yes (second layer, compatible with your main AV) | Linux: yes (`clamonacc`/fanotify); **Windows: no on-access** |
| **USB protection** | Not specific | **Main strength** (anti-exe + hidden file restore) | Not specific |
| **Quarantine** | Yes (manual, with restore) | Yes | Yes |
| **Allowlist** | Yes (trusted files/folders) | Pro only | Yes |
| **Size** | **~500 KB** (binary) | < 10 MB (installer) | ~5 GB (app + database) |
| **RAM** | Very low | < 20 MB | 3–4 GB recommended |
| **Signature updates** | Manual (edit `rules.txt`) | Automatic (updater) | Automatic (`freshclam`) |
| **GUI** | No (CLI) | Yes | No (CLI/daemon) |
| **License** | MIT (open source) | Freeware (Free/Pro) | GPL-2.0 (open source) |
| **Best for** | Personal auditing, old PCs, learning security, complement | USB drives used often (campus/office), Defender complement | Mail gateways, servers, NAS, mass scanning |

## Why Tawon Exists

1. **Quiet unless sure.** No popups, no noise, never deletes a file without an
   explicit command. Light heuristics = SUSPICIOUS (info), not execution.
2. **Fully transparent.** Every rule can be read & edited by the user
   (`rules.txt`). No mystery.
3. **Lightweight for old PCs.** One ~500 KB binary, no runtime dependencies,
   comfortable on a 15-year-old PC.
4. **Built-in forensics.** `tawon forensik` = crash report (Event 41/6008/WHEA),
   dumps, processes, network — things that usually need separate tools.

## The Honest Truth

- **Database**: Smadav & ClamAV are far ahead of Tawon (millions vs dozens of signatures).
- **AI/ML**: Smadav has Smadav-AI; ClamAV has a bytecode engine; Tawon is purely
  deterministic (no ML).
- **Real-time**: both have active protection modes; Tawon leaves that to user
  awareness (manual scan + watch).
- **Bottom line**: Tawon is worth using and learning from, but **don't make it
  your only line of defense** on a PC that frequently receives foreign files.

---

**🇮🇩 Bahasa Indonesia:** [COMPARISON.id.md](COMPARISON.id.md)
