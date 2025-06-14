// file: services/prism-auth-service/internal/client/notification_client.go
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

type NotificationClient struct {
	httpClient *http.Client
	baseURL    string
}

func NewNotificationClient() *NotificationClient {
	// Di Docker Compose, service bisa saling menemukan via nama service-nya.
	// URL ini menunjuk ke container 'notification-service' di port internalnya.
	baseURL := "http://notification-service:8080"
	return &NotificationClient{
		httpClient: &http.Client{Timeout: 5 * time.Second},
		baseURL:    baseURL,
	}
}

type NotificationPayload struct {
	Recipient string `json:"recipient"`
	Subject   string `json:"subject"`
	Message   string `json:"message"`
}

func (c *NotificationClient) SendWelcomeEmail(ctx context.Context, email, firstName string) {
	payload := NotificationPayload{
		Recipient: email,
		Subject:   "Welcome to Prism ERP!",
		Message:   fmt.Sprintf("Hello %s, welcome aboard!", firstName),
	}

	// Kita jalankan di goroutine agar tidak memblokir proses registrasi utama.
	go func() {
		// Buat body request di dalam goroutine
		body, err := json.Marshal(payload)
		if err != nil {
			log.Printf("[ERROR] Failed to marshal notification payload for background task: %v", err)
			return
		}

		// UBAH: Buat request baru di dalam goroutine dengan context.Background()
		// Ini memastikan request memiliki siklus hidupnya sendiri dan tidak dibatalkan oleh handler.
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, c.baseURL+"/notifications/send", bytes.NewBuffer(body))
		if err != nil {
			log.Printf("[ERROR] Failed to create background notification request: %v", err)
			return
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := c.httpClient.Do(req)
		if err != nil {
			// Error ini sekarang akan lebih relevan, misal "connection refused" jika service mati
			log.Printf("[ERROR] Failed to send notification: %v", err)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			log.Printf("[ERROR] Notification service returned non-200 status: %s", resp.Status)
		} else {
			log.Printf("Successfully triggered welcome notification for %s", email)
		}
	}()
}
