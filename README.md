**PERTAMA TAMA SAYA UCAPKAN TERIMKASIH UNTUK ALLAH YANG MAHA KUASA🙏, YANG SUDAH MEMBERIKAN RAHMAT DAN KECERDASAN BERFIKIR, TANPA ALLAH SAYA TIDAK ADA DI SINI, DAN TERUTAMA ORANG TUA.**

---

# 🔒 Scanner Keamanan Domain Otomatis dengan Hydra

Platform pentesting otomatis yang mengintegrasikan berbagai tools keamanan termasuk **Hydra** untuk brute force login attack. Intinya masih sama kaya [autoPen](https://github.com/x866bash/autoPen) Tapi bedanya cuma aku tambahin hydra, Tool ini dirancang untuk membantu security professionals melakukan penetration testing dengan cara yang terstruktur dan efisien.

## ⚠️  PERINGATAN PENTING

**Tool ini hanya untuk tujuan edukasi dan pengujian pada sistem yang Anda miliki sendiri. Penggunaan pada sistem tanpa izin adalah ILEGAL dan dapat melanggar hukum. Pengguna bertanggung jawab penuh atas penggunaan tool ini.**

## 🚀 Fitur Utama

### 🔍 Scanning Tools
- **Nmap Port Scanning** - Deteksi port terbuka dan layanan
- **Subdomain Enumeration** - Pencarian subdomain menggunakan Subfinder
- **Vulnerability Scanning** - Deteksi kerentanan menggunakan Nikto
- **SSL/TLS Security Check** - Analisis keamanan sertifikat SSL
- **Security Headers Analysis** - Pemeriksaan HTTP security headers
- **DNS Enumeration** - Analisis record DNS

### 🔓 Brute Force Attack (Hydra) (get bug, cooming for update)
- **Multi-Service Support** - SSH, FTP, Telnet, SMTP, POP3, IMAP, RDP, MySQL, PostgreSQL
- **Smart Dictionary** - Username dan password umum yang sering digunakan
- **Timeout Protection** - Mencegah serangan yang terlalu lama
- **Real-time Results** - Menampilkan hasil secara langsung

## 📋 Persyaratan Sistem

### Tools yang Diperlukan
```bash
# Install tools keamanan yang diperlukan
sudo apt update

# Install Nmap
sudo apt install nmap

# Install Hydra
sudo apt install hydra

# Install Subfinder
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Install Nikto
sudo apt install nikto

# Install Python dependencies
pip install -r requirements.txt
```

### Dependencies Python
- FastAPI
- Uvicorn
- Requests
- DNSPython
- Pydantic
- Python-multipart

## 🛠️ Instalasi dan Setup

### 1. Clone Repository
```bash
git clone https://github.com/x866bash/autoPenV2
cd autoPenV2
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Install Security Tools
```bash
# Ubuntu/Debian
sudo apt install nmap hydra nikto

# Install Subfinder
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

### 4. Jalankan Aplikasi
```bash
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### 5. Akses Web Interface
Buka browser dan kunjungi: `http://localhost:8000`

### 6. Matikan Aplikasi
```bash
pkill -9 -f uvicorn
```

## 📖 Tutorial Penggunaan

### 1. Memulai Scan Dasar

1. **Buka Web Interface**
   - Akses `http://localhost:8000`
   - Anda akan melihat dashboard scanner

2. **Input Target**
   - Masukkan domain target (contoh: `example.com`)
   - Pilih tipe scan yang diinginkan

3. **Pilih Tipe Scan**
   - **Full Scan**: Menjalankan semua jenis scan
   - **Port Scan**: Hanya scan port menggunakan Nmap
   - **Subdomain**: Hanya pencarian subdomain
   - **Vulnerability**: Hanya scan kerentanan

### 2. Menggunakan Brute Force Attack (Hydra)

#### Contoh Penggunaan dengan example.com

1. **Jalankan Port Scan Terlebih Dahulu**
   ```
   Target: example.com
   Scan Type: Port Scan
   ```

2. **Tunggu Hasil Port Scan**
   - Sistem akan mendeteksi port terbuka
   - Contoh hasil: Port 22 (SSH), Port 21 (FTP), Port 80 (HTTP)

3. **Aktifkan Brute Force**
   - Setelah scan selesai, bagian "Brute Force Login Attack" akan muncul
   - Pilih layanan yang ingin diserang (SSH, FTP, dll.)
   - Klik tombol "🔓 Brute Force"

4. **Monitor Hasil**
   - Sistem akan menampilkan progress attack
   - Jika credentials ditemukan, akan ditampilkan dalam format:
     ```
     Username: admin
     Password: admin123
     Service: SSH
     Port: 22
     ```

### 3. Contoh Skenario Lengkap

#### Target: example.com

**Step 1: Reconnaissance**
```bash
# Jalankan Full Scan untuk mendapatkan gambaran lengkap
Target: example.com
Scan Type: Full Scan
```

**Step 2: Analisis Hasil**
```
Hasil yang mungkin ditemukan:
- Port 22 (SSH) - OPEN
- Port 80 (HTTP) - OPEN  
- Port 443 (HTTPS) - OPEN
- Port 21 (FTP) - OPEN
- Subdomain: mail.example.com, ftp.example.com
- SSL Certificate: Valid, expires in 90 days
- Missing Security Headers: X-Frame-Options, CSP
```

**Step 3: Brute Force Attack (BUG)**
```bash
# Pilih layanan untuk brute force
Service: SSH (Port 22)
Service: FTP (Port 21)

# Sistem akan menggunakan dictionary:
Usernames: admin, root, user, ftp, etc.
Passwords: password, 123456, admin, root, etc.
```

**Step 4: Hasil Brute Force (BUG)**
```
SSH (Port 22):
✅ Credentials Found: root:password123

FTP (Port 21):  
❌ No credentials found

Rekomendasi:
- Ganti password default pada SSH
- Implementasi key-based authentication
- Disable root login
```

## 🔧 Konfigurasi Lanjutan

### Menambah Dictionary Custom

Edit file `app/services/tools.py` pada fungsi `run_hydra_bruteforce`:

```python
# Custom usernames
usernames = [
    'admin', 'administrator', 'root', 'user', 'test',
    'custom_user', 'service_account', 'backup'
]

# Custom passwords
passwords = [
    'password', '123456', 'admin', 'root', 'toor',
    'company123', 'Welcome2023', 'P@ssw0rd'
]
```

### Mengatur Timeout dan Thread

```python
# Dalam fungsi run_hydra_bruteforce
cmd = f"hydra -L {user_file_path} -P {pass_file_path} -s {port} -t 8 -w 60 {target} {service}"
#                                                                    ^    ^
#                                                               threads timeout
```

## 🎯 API Endpoints

### Memulai Scan
```bash
POST /api/v1/scan
Content-Type: application/json

{
    "target": "example.com",
    "scan_type": "full"
}
```

### Cek Status Scan
```bash
GET /api/v1/scan/{scan_id}/status
```

### Mulai Brute Force
```bash
POST /api/v1/scan/{scan_id}/bruteforce?service=ssh&port=22
```

### Lihat Hasil Scan
```bash
GET /api/v1/scan/{scan_id}/results
```

## 🛡️ Best Practices Keamanan

### 1. Penggunaan yang Bertanggung Jawab
- Selalu dapatkan izin tertulis sebelum melakukan testing
- Gunakan hanya pada sistem yang Anda miliki
- Dokumentasikan semua aktivitas testing
- Laporkan kerentanan yang ditemukan kepada pemilik sistem

### 2. Konfigurasi Keamanan
- Jalankan aplikasi di environment terisolasi
- Gunakan VPN atau network terpisah untuk testing
- Batasi akses ke aplikasi scanner
- Monitor log aktivitas

### 3. Mitigasi Risiko
- Set timeout yang wajar untuk brute force
- Implementasi rate limiting
- Gunakan proxy atau Tor untuk anonymity (jika diperlukan)
- Backup dan restore point sebelum testing

## 🔍 Troubleshooting

### Error: "Command not found"
```bash
# Pastikan tools sudah terinstall
which nmap
which hydra
which subfinder
which nikto

# Jika belum terinstall, install ulang
sudo apt install nmap hydra nikto
```

### Error: "Permission denied"
```bash
# Jalankan dengan sudo jika diperlukan
sudo python -m uvicorn app.main:app --host 0.0.0.0 --port 8000

# Atau ubah port ke non-privileged port
python -m uvicorn app.main:app --host 0.0.0.0 --port 8080
```

### Brute Force Timeout
```bash
# Edit timeout dalam tools.py
timeout=600  # 10 menit

# Atau kurangi jumlah kombinasi password
passwords = ['password', '123456', 'admin']  # Dictionary lebih kecil
```

## 📊 Interpretasi Hasil

### Port Scan Results
```json
{
    "open_ports": [
        {"port": 22, "service": "ssh"},
        {"port": 80, "service": "http"},
        {"port": 443, "service": "https"}
    ]
}
```

### Brute Force Results
```json
{
    "credentials_found": [
        {
            "username": "admin",
            "password": "password123",
            "service": "ssh",
            "port": 22
        }
    ]
}
```

### Security Headers
```json
{
    "security_score": 42.8,
    "missing_headers": [
        "X-Frame-Options",
        "Content-Security-Policy"
    ]
}
```

---

## 🤝 Kontribusi

Untuk berkontribusi pada project ini:

1. Fork repository
2. Buat branch fitur baru
3. Commit perubahan Anda
4. Push ke branch
5. Buat Pull Request

---

## 📄 Lisensi

Project ini dilisensikan di bawah MIT License. Lihat file [LICENSE](https://github.com/x866bash/autoPenV2?tab=GPL-3.0-1-ov-file#) untuk detail lengkap.

---

## 🙏 Acknowledgments

- **Hydra** - [THC-Hydra](https://github.com/vanhauser-thc/thc-hydra) team
- **Nmap** - [Gordon Lyon FB](https://www.facebook.com/gordonlyon) dan [Nmap Web](https://nmap.org/) [Nmap Project Github](https://github.com/nmap/nmap)
- **Subfinder** - [ProjectDiscovery team](https://github.com/projectdiscovery/subfinder)
- **Nikto** - [CIRT.net](https://cirt.net/nikto2)
- **FastAPI** - [Sebastián Ramirez](https://de.linkedin.com/in/tiangolo)

---

## 📞 Support

Jika Anda mengalami masalah atau memiliki pertanyaan:

1. Baca dokumentasi ini terlebih dahulu
2. Check existing issues di GitHub
3. Buat issue baru dengan detail lengkap
4. Sertakan log error dan konfigurasi sistem
5. [mail](mailto:x866bash.github@zohomail.com)

---

**Disclaimer**: *⚠️  Tool ini dibuat untuk tujuan edukasi dan testing keamanan yang sah. Penulis tidak bertanggung jawab atas penyalahgunaan tool ini. Gunakan dengan bijak dan sesuai hukum yang berlaku.⚠️ *

---

*Tools ini di buat dengan cinta 💖 dan kasih sayang 🥰.*

---
