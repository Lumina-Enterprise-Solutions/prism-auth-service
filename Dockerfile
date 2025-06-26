# Tahap 1: Builder - Fokus pada kompilasi kode Go
# Menggunakan versi Go yang spesifik dan image Alpine untuk ukuran yang kecil
FROM golang:1.24-alpine AS builder

# Menetapkan CGO_ENABLED=0 untuk build statis, sangat disarankan untuk Docker
ENV CGO_ENABLED=0

# Menetapkan direktori kerja di dalam image
WORKDIR /app

# Menyalin file go.mod dan go.sum untuk men-cache layer dependensi
# Tanda `.` di akhir berarti menyalin ke WORKDIR (/app)
COPY go.mod go.sum ./

# Mengunduh dependensi Go. Layer ini akan di-cache oleh Docker jika go.sum tidak berubah.
RUN go mod download

# Menyalin seluruh source code aplikasi ke dalam image
# Perhatikan bahwa .dockerignore harus digunakan untuk mengecualikan file yang tidak perlu (seperti .git, .env)
COPY . .

# Meng-compile aplikasi.
# -o /app/server: Output binary akan diberi nama 'server' dan diletakkan di /app
# -ldflags="-w -s": Opsi untuk mengurangi ukuran binary. '-w' menghilangkan debug info DWARF, '-s' menghilangkan symbol table.
# ./... : Pola ini akan mencari dan membangun dari direktori yang berisi main.go
RUN go build -ldflags="-w -s" -o /app/server ./...


# --- Tahap 2: Final Image - Fokus pada image akhir yang ramping dan aman ---
# Menggunakan image Alpine terbaru yang sangat kecil
FROM alpine:latest

# Menetapkan direktori kerja
WORKDIR /app

# PENTING: Menjalankan aplikasi sebagai non-root user untuk keamanan.
# 1. Buat group 'appgroup'
# 2. Buat user 'appuser' dan tambahkan ke 'appgroup'
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Salin binary aplikasi yang sudah di-compile dari tahap 'builder'
COPY --from=builder /app/server /app/server

# Label Standar OCI (Open Container Initiative) untuk metadata image
LABEL org.opencontainers.image.source="https://github.com/Lumina-Enterprise-Solutions/prism-auth-service"
LABEL org.opencontainers.image.title="PrismAuthService"
LABEL org.opencontainers.image.description="Authentication and authorization service for the Prism ERP ecosystem."

# Berikan kepemilikan direktori kerja kepada user baru kita
RUN chown -R appuser:appgroup /app

# Ganti user dari 'root' ke 'appuser'
USER appuser

# Expose port yang digunakan oleh aplikasi
# (Ini lebih sebagai dokumentasi, tidak benar-benar membuka port di host)
EXPOSE 8080

# Perintah untuk menjalankan aplikasi ketika kontainer dimulai
CMD ["/app/server"]
