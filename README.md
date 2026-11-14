# ⚡ FlareRedirect Web (Localhost Engine)
> **High Performance Cloudflare 301 Permanent Redirect Manager & Live Domain Tracer**  
> Sistem web lokal mandiri (*localhost*) berkecepatan tinggi untuk mengelola, melacak, dan mengalihkan ribuan domain Cloudflare secara instan, aman, dan tanpa perantara pihak ketiga.

[![Platform](https://img.shields.io/badge/Platform-Localhost%20Web-blue.svg)](#)
[![Version](https://img.shields.io/badge/Version-v1.4.1%20Web-orange.svg)](#)
[![Python](https://img.shields.io/badge/Python-3.10%20%7C%203.14-green.svg)](#)
[![Zero Dependency Server](https://img.shields.io/badge/Server-Zero%20Dependency%20HTTP-success.svg)](#)
[![License](https://img.shields.io/badge/License-MIT-brightgreen.svg)](#)

---

## 🚀 CARA MENJALANKAN (1-KLIK)

Tidak perlu setup server hosting, domain publik, atau VPS. Sistem berjalan **100% di komputer lokal Anda**:

1. **Jalankan Skrip:**
   - Cukup klik dua kali file **`run.bat`** atau **`start_web.bat`**.
2. **Dashboard Otomatis Terbuka:**
   - Browser default Anda (Chrome/Edge/Firefox) akan langsung membuka alamat:
     ```text
     http://localhost:5050
     ```
3. **Selesai!** Dashboard siap digunakan dengan tampilan modern, responsif, dan ultra-cepat.

---

## ✨ FITUR UTAMA SISTEM WEB LOKAL

### 1. Zero-Lag Domain Manager (Untuk 5.000+ Domain)
* **Pencarian 0ms:** Filter dan cari nama domain secara instan via memori browser tanpa loading lambat.
* **Paginasi Cepat:** Pilihan tampilan fleksibel: `50`, `100`, `250`, `500`, atau `Semua Domain`.
* **Multi-Selection:** Centang perorangan atau *Select All* yang tersimpan lintas perpindahan halaman.

### 2. Direct Live Redirect Checker (Bebas Error 403)
* Menguji status pengalihan langsung ke internet (*HTTP HEAD/GET*), mendeteksi apakah domain aktif (200 OK), meredirect (301 / 302), atau memiliki **rantai redirect berganda (>1x redirect)**.
* **100% Bebas Error 403 Ruleset Cloudflare** karena pengetesan dilakukan secara langsung pada respons domain.
* Dilengkapi filter khusus: **⚠️ Multiple Redirect (>1x)**, **Normal 1x**, **Tanpa Redirect**, dan **Belum Diperiksa**.
* **Quick Live Tracer:** Kotak uji instan di bagian atas untuk melacak redirect domain manapun secara real-time.

### 3. Setup Bulk Redirect & Single Redirect
* Pasang aturan pengalihan 301 ke puluhan atau ratusan domain sekaligus secara otomatis.
* Dukungan multi-akun: domain dari berbagai akun Cloudflare berbeda dapat dialihkan secara bersamaan tanpa tertukar token.
* Pilihan *Preserve Path* untuk meneruskan path URL domain asal ke domain tujuan.

### 4. Manajemen Akun Multi-Profile & Auto-Prune Cache
* Hubungkan banyak akun Cloudflare menggunakan API Token atau Global API Key.
* **Pembersihan Cache Sisa (Auto-Prune):** Tombol **"🧹 Bersihkan Cache"** otomatis membuang domain yatim dari akun lama yang sudah tidak terpakai, menjaga sistem tetap bersih dan bebas bug token.

---

## 📁 STRUKTUR FOLDER PROYEK

```text
FlareRedirect/
├── data/
│   └── domains_cache.json     # Cache data domain lokal (aman & private)
├── src/
│   ├── cloudflare/            # Mesin komunikasi Cloudflare API (Zones, Redirects, Client)
│   ├── security/              # Validasi domain, sesi akun, dan Direct Live Checker
│   ├── utils/                 # Utility sanitize error & audit log
│   ├── config.py              # Konfigurasi sistem dasar
│   └── config_manager.py      # Manajemen profil akun dan cache file
├── web/
│   ├── css/
│   │   └── style.css          # Styling CSS terpusat (Data-Terminal dark theme)
│   ├── js/
│   │   └── main.js            # Controller frontend (pencarian 0ms & worker tracer)
│   ├── index.html             # Tampilan dashboard web utama
│   ├── server.py              # Server HTTP Python lokal (REST API & static server)
│   └── start_web.bat          # Batch runner di folder web
├── tests/                     # Unit & integration tests (81 passing tests, 100% pass)
├── config.json                # Penyimpanan akun Cloudflare lokal (ignored by git)
├── main.py                    # Entry point utama (menjalankan web server lokal)
├── requirements.txt           # Dependensi Python minimal (httpx, idna, dotenv)
├── run.bat                    # Skrip 1-klik runner utama
├── start_web.bat              # Skrip 1-klik runner shortcut
└── README.md
```

---

## 🔒 JAMINAN KEAMANAN & PRIVASI LOKAL
* **Zero Cloud Leak:** Semua token, kunci API, dan data cache domain hanya tersimpan di komputer lokal Anda (`config.json` dan `data/domains_cache.json`).
* Tidak ada server perantara eksternal. Semua komunikasi HTTP langsung dari komputer lokal Anda ke Cloudflare API resmi (`api.cloudflare.com`).
* Server lokal hanya mengikat (*bind*) ke `127.0.0.1` (localhost), sehingga tidak dapat diakses dari jaringan luar/publik.

---

## 🛠️ JALANKAN DARI TERMINAL (OPSIONAL)

Jika ingin menjalankan via command prompt atau terminal:
```powershell
# Pasang dependensi minimal (cukup sekali):
pip install -r requirements.txt

# Jalankan server:
python main.py
```
Akses web dashboard di: `http://localhost:5050`
