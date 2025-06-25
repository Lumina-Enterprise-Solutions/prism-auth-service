// file: services/prism-auth-service/internal/client/notification_client.go
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io" // <-- TAMBAHKAN
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

func (c *NotificationClient) sendNotification(ctx context.Context, payload NotificationPayload) {
	// Kita jalankan di goroutine agar tidak memblokir proses utama.
	go func() {
		body, err := json.Marshal(payload)
		if err != nil {
			log.Printf("[ERROR] Failed to marshal notification payload for background task: %v", err)
			return
		}

		// Gunakan context.Background() untuk request yang siklus hidupnya independen
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, c.baseURL+"/notifications/send", bytes.NewBuffer(body))
		if err != nil {
			log.Printf("[ERROR] Failed to create background notification request: %v", err)
			return
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := c.httpClient.Do(req)
		if err != nil {
			log.Printf("[ERROR] Failed to send notification for subject '%s': %v", payload.Subject, err)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusAccepted { // <-- Periksa StatusAccepted (202)
			bodyBytes, _ := io.ReadAll(resp.Body)
			log.Printf("[ERROR] Notification service returned non-202 status: %s, body: %s", resp.Status, string(bodyBytes))
		} else {
			log.Printf("Successfully enqueued notification '%s' for %s", payload.Subject, payload.Recipient)
		}
	}()
}

func (c *NotificationClient) SendWelcomeEmail(ctx context.Context, email, firstName string) {
	payload := NotificationPayload{
		Recipient: email,
		Subject:   "Welcome to Prism ERP!",
		Message:   fmt.Sprintf("<h1>Welcome, %s!</h1><p>Your account has been successfully created.</p>", firstName),
	}
	c.sendNotification(ctx, payload)
}

// --- METODE BARU ---
func (c *NotificationClient) SendPasswordResetEmail(ctx context.Context, email, firstName, resetLink string) {
	payload := NotificationPayload{
		Recipient: email,
		Subject:   "Your Prism ERP Password Reset Request",
		Message: fmt.Sprintf(
			`<h1>Password Reset Request</h1>
             <p>Hello %s,</p>
             <p>We received a request to reset your password. Please click the link below to set a new password:</p>
             <p><a href="%s">Reset Password</a></p>
             <p>This link will expire in 1 hour. If you did not request a password reset, please ignore this email.</p>
             <p>Thanks,<br>The Prism ERP Team</p>`,
			firstName,
			resetLink,
		),
	}
	c.sendNotification(ctx, payload)
}
