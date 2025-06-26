# 🛡️ Prism Auth Service

Layanan ini adalah gerbang utama untuk semua otentikasi dan otorisasi dalam ekosistem **Prism ERP**. Layanan ini bertanggung jawab untuk mengelola identitas pengguna, token akses, kunci API, dan integrasi dengan penyedia otentikasi pihak ketiga.

<!-- Workflow Badges -->
<p>
  <a href="https://github.com/Lumina-Enterprise-Solutions/prism-auth-service/actions/workflows/ci.yml">
    <img src="https://github.com/Lumina-Enterprise-Solutions/prism-auth-service/actions/workflows/ci.yml/badge.svg" alt="CI Pipeline">
  </a>
  <a href="https://github.com/Lumina-Enterprise-Solutions/prism-auth-service/actions/workflows/release.yml">
    <img src="https://github.com/Lumina-Enterprise-Solutions/prism-auth-service/actions/workflows/release.yml/badge.svg" alt="Release Pipeline">
  </a>
  <a href="https://github.com/Lumina-Enterprise-Solutions/prism-auth-service/pkgs/container/prism-auth-service">
    <img src="https://img.shields.io/github/v/release/Lumina-Enterprise-Solutions/prism-auth-service?label=ghcr.io&color=blue" alt="GHCR Package">
  </a>
  <a href="https://goreportcard.com/report/github.com/Lumina-Enterprise-Solutions/prism-auth-service">
    <img src="https://goreportcard.com/badge/github.com/Lumina-Enterprise-Solutions/prism-auth-service" alt="Go Report Card">
  </a>
  <a href="./LICENSE">
    <img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT">
  </a>
</p>

---

## ✨ Fitur Utama

-   **Otentikasi Berbasis JWT**: Menggunakan *Access Token* (berumur pendek) dan *Refresh Token* (berumur panjang).
-   **Manajemen API Key**: Membuat, melihat metadata, dan mencabut kunci API untuk otentikasi programatik.
-   **Social Login (OAuth2)**: Integrasi siap pakai untuk login melalui Google dan Microsoft.
-   **Two-Factor Authentication (2FA)**: Dukungan untuk setup dan verifikasi 2FA menggunakan TOTP.
-   **Password Recovery**: Alur kerja aman untuk "lupa password" dan "reset password".
-   **Server gRPC Internal**: Mengekspos fungsionalitas validasi token secara internal ke layanan lain di dalam cluster untuk komunikasi antar-layanan yang efisien.
-   **Observabilitas**: Terintegrasi penuh dengan OpenTelemetry untuk *tracing* terdistribusi ke Jaeger dan *metrics* ke Prometheus.
-   **Keamanan Terpusat**: Mengambil semua rahasia penting dari HashiCorp Vault saat startup.

---

## 🛠️ Teknologi

-   **Bahasa**: Go 1.24
-   **Framework**: Gin (untuk HTTP), gRPC (untuk komunikasi internal)
-   **Database**: PostgreSQL
-   **Cache**: Redis (untuk *denylist* token yang di-logout)
-   **Containerization**: Docker
-   **CI/CD**: GitHub Actions
-   **Manajemen Rahasia**: HashiCorp Vault

---

## 🚀 Menjalankan Secara Lokal

Layanan ini dirancang untuk dijalankan menggunakan Docker Compose dari root direktori monorepo.

1.  **Pastikan Prasyarat Terpenuhi**:
    -   Docker & Docker Compose
    -   Go 1.24+
    -   `make`

2.  **Jalankan Semua Layanan**:
    Dari direktori root proyek (`lumina-enterprise-solutions`), jalankan:
    ```bash
    make up
    ```
    Perintah ini akan membangun dan menjalankan semua layanan yang dibutuhkan, termasuk `prism-auth-service`, database, Redis, dan Vault.

3.  **Perintah Makefile Lokal**:
    Di dalam direktori `services/prism-auth-service`, Anda dapat menggunakan perintah `make` berikut:
    -   `make build`: Membangun atau membangun ulang image Docker untuk layanan ini.
    -   `make test`: Menjalankan unit test (cepat, tidak memerlukan dependensi eksternal).
    -   `make test-integration`: Menjalankan integration test (memerlukan Docker untuk Postgres & Redis).
    -   `make lint`: Menjalankan linter `golangci-lint` untuk memeriksa kualitas kode.
    -   `make tidy`: Merapikan dependensi di file `go.mod`.

---

## 🏗️ CI/CD & Alur Kerja Rilis

Proyek ini menggunakan dua alur kerja utama GitHub Actions:

1.  **`ci.yml` (Continuous Integration)**:
    -   **Trigger**: Berjalan pada setiap `push` ke branch utama (`main`, `develop`) dan PR.
    -   **Tugas**:
        -   Menjalankan linter untuk memastikan kualitas kode.
        -   Menjalankan unit test.
        -   Menyediakan service *database* dan *cache* untuk menjalankan integration test secara menyeluruh.
        -   Membangun aplikasi dan image Docker untuk memvalidasi `Dockerfile`.

2.  **`release.yml` (Continuous Delivery)**:
    -   **Trigger**: Berjalan hanya saat **tag baru** dengan format `v*` (misal: `v1.2.0`) di-push ke repository.
    -   **Tugas**:
        -   Membangun dan mem-push image Docker ke **GitHub Container Registry (GHCR)**.
        -   Memberi tag pada image dengan versi yang sesuai (e.g., `1.2.0`, `1.2`, `latest`).
        -   Membuat **GitHub Release** secara otomatis yang berisi changelog dari PR yang di-merge.

---
<details>
<summary><b>🔑 Variabel Lingkungan & Konfigurasi Rahasia</b></summary>

Layanan ini dikonfigurasi melalui variabel lingkungan, dengan beberapa rahasia yang diambil dari Vault saat startup.

| Variabel                      | Deskripsi                                                | Contoh Nilai                               | Diambil dari Vault? |
| ----------------------------- | -------------------------------------------------------- | ------------------------------------------ | ------------------- |
| `DATABASE_URL`                | URL koneksi ke database PostgreSQL.                      | `postgres://user:pass@host:port/db`        | **Ya**              |
| `REDIS_ADDR`                  | Alamat server Redis.                                     | `cache-redis:6379`                         | Tidak               |
| `JAEGER_ENDPOINT`             | Alamat kolektor Jaeger (OTLP gRPC).                      | `jaeger:4317`                              | Tidak               |
| `VAULT_ADDR`                  | Alamat server HashiCorp Vault.                           | `http://vault:8200`                        | Tidak               |
| `VAULT_TOKEN`                 | Token untuk mengakses Vault.                             | `root-token-for-dev`                       | Tidak               |
| `JWT_SECRET_KEY`              | Kunci rahasia untuk menandatangani JWT.                  | `super-secret-key-from-vault`              | **Ya**              |
| `GOOGLE_OAUTH_CLIENT_ID`      | Client ID untuk Google OAuth.                            | `...apps.googleusercontent.com`            | **Ya**              |
| `GOOGLE_OAUTH_CLIENT_SECRET`  | Client Secret untuk Google OAuth.                        | `GOCSPX-...`                               | **Ya**              |
| `MICROSOFT_OAUTH_CLIENT_ID`   | Client ID untuk Microsoft OAuth.                         | `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`     | **Ya**              |
| `MICROSOFT_OAUTH_CLIENT_SECRET` | Client Secret untuk Microsoft OAuth.                     | `xxx~xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`       | **Ya**              |
</details>

---

## 📡 Endpoint API

Semua endpoint berada di bawah prefix `/auth`. Otentikasi yang diperlukan bisa berupa `Bearer <JWT>` atau header `X-API-Key: <key>`.

### Rute Publik

| Metode | Path                     | Deskripsi                                            |
| ------ | ------------------------ | ---------------------------------------------------- |
| `POST` | `/register`              | Mendaftarkan pengguna baru.                          |
| `POST` | `/login`                 | Login dengan email/password (Tahap 1 jika 2FA aktif). |
| `POST` | `/login/2fa`             | Memverifikasi kode 2FA untuk menyelesaikan login.    |
| `POST` | `/refresh`               | Mendapatkan access token baru menggunakan refresh token. |
| `POST` | `/forgot-password`       | Memulai alur lupa password, mengirim email.          |
| `POST` | `/reset-password`        | Mengatur password baru menggunakan token dari email. |
| `GET`  | `/google/login`          | Mengarahkan pengguna ke halaman login Google.        |
| `GET`  | `/google/callback`       | Callback yang diproses oleh Google setelah login.    |
| `GET`  | `/microsoft/login`       | Mengarahkan pengguna ke halaman login Microsoft.     |
| `GET`  | `/microsoft/callback`    | Callback yang diproses oleh Microsoft setelah login. |
| `GET`  | `/health`                | Health check untuk service discovery.                |

### Rute Terproteksi (Memerlukan Otentikasi)

| Metode | Path             | Deskripsi                                                        |
| ------ | ---------------- | ---------------------------------------------------------------- |
| `GET`  | `/profile`       | Mendapatkan informasi profil pengguna yang sedang login.         |
| `POST` | `/logout`        | Mencabut (revoke) *access token* yang sedang digunakan.          |
| `POST` | `/2fa/setup`     | Menghasilkan QR code dan secret untuk setup 2FA.                 |
| `POST` | `/2fa/verify`    | Memverifikasi dan mengaktifkan 2FA untuk pengguna.               |
| `POST` | `/keys`          | Membuat API key baru. **Kunci hanya akan ditampilkan sekali**. |
| `GET`  | `/keys`          | Mendapatkan daftar metadata dari semua API key milik pengguna. |
| `DELETE`| `/keys/:id`     | Mencabut (revoke) sebuah API key berdasarkan ID-nya.             |
