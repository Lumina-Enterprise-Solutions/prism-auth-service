package client

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNotificationClient(t *testing.T) {
	t.Run("SendWelcomeEmail", func(t *testing.T) {
		var wg sync.WaitGroup
		wg.Add(1)

		// Arrange: mock server
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Assert request
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, "/notifications/send", r.URL.Path)
			assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

			body, err := io.ReadAll(r.Body)
			assert.NoError(t, err)

			var payload NotificationPayload
			err = json.Unmarshal(body, &payload)
			assert.NoError(t, err, "failed to unmarshal request body")

			// Assert payload
			assert.Equal(t, "user-123", payload.RecipientID)
			assert.Equal(t, "welcome@example.com", payload.Recipient)
			assert.Equal(t, "Welcome to Prism ERP!", payload.Subject)
			assert.Equal(t, "welcome.html", payload.TemplateName)
			assert.Equal(t, "John", payload.TemplateData["FirstName"])

			w.WriteHeader(http.StatusAccepted) // Notif service harusnya return 202
			wg.Done()
		}))
		defer mockServer.Close()

		client := NewNotificationClient()
		client.baseURL = mockServer.URL // Ganti baseURL dengan URL mock server

		// Act
		client.SendWelcomeEmail(context.Background(), "user-123", "welcome@example.com", "John")

		// Assert: tunggu goroutine selesai
		if waitTimeout(&wg, 1*time.Second) {
			t.Fatal("goroutine in SendWelcomeEmail did not finish in time")
		}
	})

	t.Run("SendPasswordResetEmail", func(t *testing.T) {
		var wg sync.WaitGroup
		wg.Add(1)

		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			var payload NotificationPayload
			err := json.Unmarshal(body, &payload)
			assert.NoError(t, err, "failed to unmarshal request body")

			assert.Equal(t, "user-456", payload.RecipientID)
			assert.Equal(t, "reset@example.com", payload.Recipient)
			assert.Equal(t, "Your Prism ERP Password Reset Request", payload.Subject)
			assert.Equal(t, "password_reset.html", payload.TemplateName)
			assert.Equal(t, "Jane", payload.TemplateData["FirstName"])
			assert.Equal(t, "http://test.com/reset?token=abc", payload.TemplateData["ResetLink"])

			w.WriteHeader(http.StatusAccepted)
			wg.Done()
		}))
		defer mockServer.Close()

		client := NewNotificationClient()
		client.baseURL = mockServer.URL

		// Act
		client.SendPasswordResetEmail(context.Background(), "user-456", "reset@example.com", "Jane", "http://test.com/reset?token=abc")

		// Assert
		if waitTimeout(&wg, 1*time.Second) {
			t.Fatal("goroutine in SendPasswordResetEmail did not finish in time")
		}
	})

}

// waitTimeout waits for the waitgroup for the specified duration.
// Returns true if waiting timed out.
func waitTimeout(wg *sync.WaitGroup, timeout time.Duration) bool {
	c := make(chan struct{})
	go func() {
		defer close(c)
		wg.Wait()
	}()
	select {
	case <-c:
		return false // completed normally
	case <-time.After(timeout):
		return true // timed out
	}
}
