// File: internal/client/notification_client.go
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"time"
)

// NotificationClient is now an INTERFACE for better mocking and dependency injection.
type NotificationClient interface {
	SendWelcomeEmail(ctx context.Context, userID, email, firstName string)
	SendPasswordResetEmail(ctx context.Context, userID, email, firstName, resetLink string)
}

// httpNotificationClient is the concrete implementation of the NotificationClient interface.
type httpNotificationClient struct {
	httpClient *http.Client
	baseURL    string
}

// NewNotificationClient creates a new instance that implements the NotificationClient interface.
func NewNotificationClient() NotificationClient {
	baseURL := "http://notification-service:8080"
	return &httpNotificationClient{
		httpClient: &http.Client{Timeout: 5 * time.Second},
		baseURL:    baseURL,
	}
}

type NotificationPayload struct {
	RecipientID  string                 `json:"recipient_id"`
	Recipient    string                 `json:"recipient"`
	Subject      string                 `json:"subject"`
	TemplateName string                 `json:"template_name"`
	TemplateData map[string]interface{} `json:"template_data"`
}

func (c *httpNotificationClient) sendNotification(ctx context.Context, payload NotificationPayload) {
	go func() {
		body, err := json.Marshal(payload)
		if err != nil {
			log.Printf("[ERROR] Failed to marshal notification payload for background task: %v", err)
			return
		}

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
		// LINT FIX: Check the error returned from closing the response body.
		defer func() {
			if err := resp.Body.Close(); err != nil {
				log.Printf("[WARN] Failed to close response body on notification request: %v", err)
			}
		}()

		if resp.StatusCode != http.StatusAccepted {
			bodyBytes, _ := io.ReadAll(resp.Body)
			log.Printf("[ERROR] Notification service returned non-202 status: %s, body: %s", resp.Status, string(bodyBytes))
		} else {
			log.Printf("Successfully enqueued notification '%s' for %s", payload.Subject, payload.Recipient)
		}
	}()
}

func (c *httpNotificationClient) SendWelcomeEmail(ctx context.Context, userID, email, firstName string) {
	payload := NotificationPayload{
		RecipientID:  userID,
		Recipient:    email,
		Subject:      "Welcome to Prism ERP!",
		TemplateName: "welcome.html",
		TemplateData: map[string]interface{}{"FirstName": firstName},
	}
	c.sendNotification(ctx, payload)
}

func (c *httpNotificationClient) SendPasswordResetEmail(ctx context.Context, userID, email, firstName, resetLink string) {
	payload := NotificationPayload{
		RecipientID:  userID,
		Recipient:    email,
		Subject:      "Your Prism ERP Password Reset Request",
		TemplateName: "password_reset.html",
		TemplateData: map[string]interface{}{
			"FirstName": firstName,
			"ResetLink": resetLink,
		},
	}
	c.sendNotification(ctx, payload)
}
