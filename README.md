# ⚡ FlareRedirect (v1.3.1)
> **High Performance Cloudflare 301 Permanent Redirect Engine**  
> Kelola ratusan aturan *Single Redirects (301 Permanent URL Forwarding)* di Cloudflare secara instan, aman, dan tanpa perantara pihak ketiga.

[![Platform](https://img.shields.io/badge/Platform-Windows%2010%20%7C%2011%20(64--bit)-blue.svg)](#)
[![Version](https://img.shields.io/badge/Version-v1.3.1-orange.svg)](#)
[![Python](https://img.shields.io/badge/Python-3.12%20%7C%203.14-green.svg)](#)
[![GUI](https://img.shields.io/badge/GUI-PySide6%20Qt-blueviolet.svg)](#)
[![License](https://img.shields.io/badge/License-MIT-brightgreen.svg)](#)

---

## 🚀 CARA CEPAT (Langsung Pakai File .EXE)
> **Rekomendasi Utama:** Anda **tidak perlu menginstal Python atau dependensi apapun**. Semua modul sudah dikemas ke dalam satu file executable mandiri berlabel versi resmi.

1. **Unduh / Buka Executable Berlabel Versi:**
   - Gunakan file versi terbaru di folder `dist/`:
     ```text
     dist\FlareRedirect_v1.3.1.exe
     ```
   - *(Setiap versi rilis selalu memiliki penamaan tag versi yang jelas)*.
2. **Jalankan Aplikasi:**
   - Klik dua kali pada `FlareRedirect_v1.3.1.exe`.
   - *(Jika muncul Windows SmartScreen, klik **More info** &rarr; **Run anyway**)*.
3. **Hubungkan Akun Cloudflare:**
   - Masuk ke menu **🔑 Kelola Akun** di pojok kanan atas.
   - Masukkan nama akun dan **API Token** (atau Global API Key + Email).
   - Pastikan opsi **"💾 Simpan ke config.json"** dicentang agar akun otomatis terhubung setiap kali aplikasi dibuka.
4. **Mulai Redirect Domain:**
   - Masuk ke menu **🌐 Domains** untuk melihat seluruh domain Anda.
   - **Local Cache Instant Startup:** Domain otomatis disimpan di penyimpanan lokal sehingga saat aplikasi dibuka kembali, domain langsung muncul tanpa menunggu koneksi Cloudflare! Gunakan tombol **"🔄 Refresh dari CF"** jika ingin menyinkronkan data terbaru.
   - Gunakan tombol **⚡ Bulk Redirect** untuk mengalihkan puluhan/ratusan domain sekaligus secara otomatis lintas akun!

---

## 💻 CARA MENJALANKAN DARI SOURCE CODE (Untuk Developer)

Jika Anda ingin menjalankan atau memodifikasi script Python secara langsung:

### 1. Buka Terminal / CMD di Folder Proyek
```powershell
cd C:\Users\skylark\FlarePilot
```
*(atau sesuaikan dengan direktori tempat Anda meletakkan folder `FlareRedirect`)*.

### 2. Cara Cepat (1-Klik via Batch Script)
Cukup klik dua kali file:
```cmd
run.bat
```

### 3. Atau Jalankan Manual via Terminal:
```powershell
# 1. Buat dan aktifkan virtual environment (opsional)
python -m venv venv
.\venv\Scripts\activate

# 2. Pasang dependensi
pip install -r requirements.txt

# 3. Jalankan aplikasi
python main.py
```

---

## 🔨 CARA BUILD ULANG FILE .EXE (Dengan Nomor Versi)

Untuk mengompilasi ulang kode Python menjadi file Windows `.exe` mandiri dengan metadata versi:

### Menggunakan Skrip 1-Klik:
```cmd
build_windows.bat
```

### Atau via Python:
```powershell
python build_exe.py
```

Skrip ini secara otomatis:
1. Membaca nomor versi dari `version.json` (saat ini `v1.3.1`).
2. Menanamkan metadata resource Windows (*File Version: 1.3.1.0, Product Version: 1.3.1.0, Icon*).
3. Mengemas aplikasi menjadi standalone executable tanpa konsol CMD.
4. Menghasilkan file output berlabel versi resmi di folder `dist/`:
   - `dist\FlareRedirect_v1.3.1.exe` (Selalu berlabel tag versi)

---

## 🔑 IZIN MINIMUM CLOUDFLARE TOKEN

Di portal [Cloudflare API Tokens](https://dash.cloudflare.com/profile/api-tokens), buat **Custom Token** dengan izin minimum:
- **Zone** &rarr; **Zone** &rarr; **Read** *(Membaca daftar zona domain)*
- **Zone** &rarr; **Single Redirect** &rarr; **Edit** *(Membuat & mengedit aturan redirect 301)*

*(Aplikasi juga mendukung autentikasi menggunakan **Global API Key + Email** jika akun Anda memerlukannya).*

---

## 🛡️ PRIVASI & KEAMANAN GITHUB (Zero-Leak)

- **Aman Dari Push:** Seluruh token dan profil akun disimpan di file lokal `config.json` dan `data/` yang secara mutlak **dikecualikan oleh `.gitignore`**.
- File kredensial pribadi dan cache domain lokal Anda **tidak akan pernah ter-push ke GitHub**.
- Untuk melakukan push pembaruan kode ke repository GitHub:
  ```cmd
  git_push.bat
  ```

---

## 🧪 PENGUJIAN UNIT (UNIT TESTS)

Untuk memverifikasi keutuhan seluruh engine validasi, proxy check, local cache, dan API client:
```powershell
pytest -v
```
*(Saat ini 58/58 unit tests terverifikasi 100% lulus)*.

---

## 📄 LISENSI
Didistribusikan di bawah lisensi MIT. Bebas digunakan dan disesuaikan untuk kebutuhan automasi domain Anda.
