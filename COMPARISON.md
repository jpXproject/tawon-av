# Perbandingan: Tawon vs Smadav vs ClamAV

Perbandingan jujur antara **Tawon** (AV pribadi berbasis Rust), **Smadav**
(AV Indonesia, fokus perlindungan USB), dan **ClamAV** (AV open-source
internasional dari Cisco Talos, berfokus pada server/mail gateway).

> ⚠️ Catatan penting: Tawon bukan pengganti keduanya. Tawon adalah alat
> keamanan pribadi — transparan, ringan, tanpa popup — cocok sebagai
> pelengkap, alat audit, dan proyek edukasi. Komersial seperti Smadav/ClamAV
> memiliki database jutaan signature + tim peneliti + update otomatis.

## Tabel Perbandingan

| Aspek | 🐝 Tawon | 🇮🇩 Smadav | 🌍 ClamAV |
|---|---|---|---|
| **Platform** | Windows (CLI) | Windows XP–11 (32/64-bit) | Windows, Linux, macOS, BSD |
| **Bahasa** | Rust (memory-safe) | Proprietary | C/C++ |
| **Deteksi signature** | Hash SHA-256, pola HEX, pola teks (kustom) | Database signature Smadav + **Smadav-AI (ML)** | Jutaan signature Cisco Talos + bytecode |
| **Heuristik** | Ya (entropy, PE parsing & API injeksi, encoded script, ekstensi ganda) | Ya + AI/ML | Ya (bytecode, heuristik) |
| **Deteksi real-time** | Tidak (ada `watch` polling manual) | Ya (lapisan kedua, kompatibel dengan AV utama) | Linux: ya (`clamonacc`/fanotify); **Windows: tidak ada on-access** |
| **Perlindungan USB** | Tidak spesifik | **Keunggulan utama** (anti-exe + restore file tersembunyi) | Tidak spesifik |
| **Karantina** | Ya (manual, dengan restore) | Ya | Ya |
| **Allowlist** | Ya (file/folder tepercaya) | Hanya di Pro | Ya |
| **Ukuran** | **~500 KB** (biner) | < 10 MB (installer) | ~5 GB (aplikasi + database) |
| **RAM** | Sangat rendah | < 20 MB | 3–4 GB direkomendasikan |
| **Update signature** | Manual (edit `rules.txt`) | Otomatis (updater) | Otomatis (`freshclam`) |
| **GUI** | Tidak (CLI) | Ya | Tidak (CLI/daemon) |
| **Lisensi** | MIT (open source) | Freeware (Free/Pro) | GPL-2.0 (open source) |
| **Cocok untuk** | Audit pribadi, PC tua, belajar security, pelengkap | USB drive sering dipakai (kampus/kantor), pelengkap Defender | Mail gateway, server, NAS, scan massal |

## Kenapa Tawon Ada

1. **Diam kalau tidak yakin.** Tidak ada popup, tidak berisik, tidak pernah
   menghapus file tanpa perintah eksplisit. Heuristik ringan = CURIGA (info),
   bukan eksekusi.
2. **Transparan total.** Semua rules bisa dibaca & diedit pengguna
   (`rules.txt`). Tidak ada misteri.
3. **Ringan untuk PC tua.** Satu biner ~500 KB, tanpa ketergantungan runtime,
   jalan nyaman di PC 15 tahun.
4. **Forensik bawaan.** `tawon forensik` = laporan crash (Event 41/6008/WHEA),
   dump, proses, jaringan — yang biasanya butuh tool terpisah.

## Kejujuran

- **Database**: Smadav & ClamAV jauh melampaui Tawon (jutaan vs puluhan signature).
- **AI/ML**: Smadav punya Smadav-AI; ClamAV punya bytecode engine; Tawon murni
  deterministic (tanpa ML).
- **Real-time**: keduanya punya mode proteksi aktif; Tawon menyerahkan itu ke
  kesadaran pengguna (scan manual + watch).
- **Kesimpulan**: Tawon layak dipakai dan dipelajari, tapi **jangan jadikan
  satu-satunya pertahanan** di PC yang sering menerima file asing.
