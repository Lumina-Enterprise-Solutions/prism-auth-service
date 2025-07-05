# 🛡️ Prism Auth Service

[![CI Pipeline](https://github.com/Lumina-Enterprise-Solutions/prism-auth-service/actions/workflows/ci.yml/badge.svg)](https://github.com/Lumina-Enterprise-Solutions/prism-auth-service/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/Lumina-Enterprise-Solutions/prism-auth-service)](https://goreportcard.com/report/github.com/Lumina-Enterprise-Solutions/prism-auth-service)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)

Layanan ini adalah gerbang utama untuk semua otentikasi dan otorisasi dalam ekosistem **Prism ERP**. Layanan ini bertanggung jawab untuk mengelola identitas pengguna, token akses, dan integrasi dengan penyedia otentikasi pihak ketiga.

---

## ✨ Fitur Utama

-   **Otentikasi Berbasis JWT**: Menggunakan Access Token (berumur pendek) dan Refresh Token (berumur panjang).
-   **Registrasi & Login**: Endpoint standar untuk registrasi pengguna baru dan login dengan email/password.
-   **Social Login (OAuth2)**: Integrasi siap pakai untuk login melalui Google dan Microsoft.
-   **Single Sign-On (SSO)**: Fondasi untuk integrasi dengan penyedia identitas SAML 2.0 seperti Okta dan Azure AD.
-   **Two-Factor Authentication (2FA)**: Dukungan untuk setup dan verifikasi 2FA menggunakan TOTP (Time-based One-Time Password).
-   **Manajemen Token**: Endpoint untuk me-refresh access token dan melakukan logout (mencabut token).
-   **Observabilitas**: Terintegrasi penuh dengan OpenTelemetry untuk tracing terdistribusi ke Jaeger.

---

## 🛠️ Teknologi

-   **Bahasa**: Go 1.24
-   **Framework**: Gin Web Framework
-   **Database**: PostgreSQL
-   **Cache**: Redis (untuk daftar pencabutan token/denylist)
-   **Manajemen Rahasia**: HashiCorp Vault
-   **Service Discovery**: HashiCorp Consul

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
    Perintah ini akan membangun dan menjalankan semua layanan yang dibutuhkan, termasuk `prism-auth-service`, database, Redis, Vault, dan Consul.

3.  **Perintah Makefile Lokal**:
    Di dalam direktori `services/prism-auth-service`, Anda dapat menggunakan perintah `make` berikut:
    -   `make build`: Membangun image Docker untuk layanan ini.
    -   `make test`: Menjalankan unit test (cepat, tanpa dependensi).
    -   `make test-integration`: Menjalankan integration test yang memerlukan database.
    -   `make lint`: Menjalankan linter `golangci-lint`.

---

## 🔑 Variabel Lingkungan

Layanan ini dikonfigurasi melalui variabel lingkungan, dengan beberapa rahasia yang diambil dari Vault.

| Variabel                      | Deskripsi                                                | Contoh Nilai                               | Diambil dari Vault? |
| ----------------------------- | -------------------------------------------------------- | ------------------------------------------ | ------------------- |
| `DATABASE_URL`                | URL koneksi ke database PostgreSQL.                      | `postgres://user:pass@host:port/db`        | Tidak               |
| `REDIS_ADDR`                  | Alamat server Redis.                                     | `cache-redis:6379`                         | Tidak               |
| `JAEGER_ENDPOINT`             | Alamat kolektor Jaeger (OTLP gRPC).                      | `jaeger:4317`                              | Tidak               |
| `VAULT_ADDR`                  | Alamat server HashiCorp Vault.                           | `http://vault:8200`                        | Tidak               |
| `VAULT_TOKEN`                 | Token untuk mengakses Vault.                             | `root-token-for-dev`                       | Tidak               |
| `JWT_SECRET_KEY`              | Kunci rahasia untuk menandatangani JWT.                  | `super-secret-key-from-vault`              | **Ya**              |
| `GOOGLE_OAUTH_CLIENT_ID`      | Client ID untuk Google OAuth.                            | `...apps.googleusercontent.com`            | **Ya**              |
| `GOOGLE_OAUTH_CLIENT_SECRET`  | Client Secret untuk Google OAuth.                        | `GOCSPX-...`                               | **Ya**              |
| `MICROSOFT_OAUTH_CLIENT_ID`   | Client ID untuk Microsoft OAuth.                         | `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`     | **Ya**              |
| `MICROSOFT_OAUTH_CLIENT_SECRET` | Client Secret untuk Microsoft OAuth.                     | `xxx~xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`       | **Ya**              |

---

## 📡 Endpoint API

Semua endpoint berada di bawah prefix `/auth`.

### Rute Publik

| Metode | Path                     | Deskripsi                                            |
| ------ | ------------------------ | ---------------------------------------------------- |
| `POST` | `/register`              | Mendaftarkan pengguna baru.                          |
| `POST` | `/login`                 | Login dengan email/password (Tahap 1 2FA).           |
| `POST` | `/login/2fa`             | Memverifikasi kode 2FA untuk menyelesaikan login.    |
| `POST` | `/refresh`               | Mendapatkan access token baru menggunakan refresh token. |
| `GET`  | `/google/login`          | Mengarahkan pengguna ke halaman login Google.        |
| `GET`  | `/google/callback`       | Callback yang diproses oleh Google setelah login.    |
| `GET`  | `/microsoft/login`       | Mengarahkan pengguna ke halaman login Microsoft.     |
| `GET`  | `/microsoft/callback`    | Callback yang diproses oleh Microsoft setelah login. |
| `GET`  | `/health`                | Health check untuk service discovery.                |

### Rute Terproteksi (Memerlukan `Bearer Token`)

| Metode | Path          | Deskripsi                                    |
| ------ | ------------- | -------------------------------------------- |
| `GET`  | `/profile`    | Mendapatkan informasi profil pengguna dasar. |
| `POST` | `/logout`     | Mencabut (revoke) token yang sedang digunakan. |
| `POST` | `/2fa/setup`  | Menghasilkan QR code dan secret untuk setup 2FA. |
| `POST` | `/2fa/verify` | Memverifikasi dan mengaktifkan 2FA untuk pengguna. |
