package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/rs/zerolog/log"
)

type InvitationClient interface {
	ValidateInvitation(ctx context.Context, token string) (*InvitationData, error)
}

type httpInvitationClient struct {
	httpClient *http.Client
	baseURL    string
}

type InvitationData struct {
	Email string `json:"email"`
	Role  string `json:"role"`
}

func NewInvitationClient() InvitationClient {
	return &httpInvitationClient{
		httpClient: &http.Client{Timeout: 5 * time.Second},
		baseURL:    "http://invitation-service:8080",
	}
}

func (c *httpInvitationClient) ValidateInvitation(ctx context.Context, token string) (*InvitationData, error) {
	payload, _ := json.Marshal(map[string]string{"token": token})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/invitations/validate", bytes.NewBuffer(payload))
	if err != nil {
		return nil, fmt.Errorf("gagal membuat request validasi: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("gagal menghubungi invitation-service: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Warn().Err(err).Msg("Gagal menutup response body dari invitation-service")
		}
	}()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		log.Warn().Str("status", resp.Status).Bytes("body", bodyBytes).Msg("Gagal memvalidasi token undangan")
		return nil, fmt.Errorf("undangan tidak valid atau sudah kedaluwarsa (status: %s)", resp.Status)
	}

	var data InvitationData
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("gagal decode response validasi undangan: %w", err)
	}

	return &data, nil
}
