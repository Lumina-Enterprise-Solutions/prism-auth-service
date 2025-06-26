package handler

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Lumina-Enterprise-Solutions/prism-common-libs/model"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func setupTestRouterForAPIKey(handler *APIKeyHandler) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.Default()
	// Middleware tiruan untuk set user context
	router.Use(func(c *gin.Context) {
		claims := jwt.MapClaims{"sub": "user-123"}
		c.Set("claims", claims)
		c.Set("user_id", "user-123")
		c.Next()
	})

	// Auth-protected routes
	router.POST("/keys", handler.CreateAPIKey)
	router.GET("/keys", handler.GetAPIKeys)
	router.DELETE("/keys/:id", handler.RevokeAPIKey)

	return router
}

func TestAPIKeyHandler(t *testing.T) {
	mockService := new(MockAuthService) // Gunakan MockAuthService yang sama
	handler := NewAPIKeyHandler(mockService)
	router := setupTestRouterForAPIKey(handler)

	t.Run("Create API Key Success", func(t *testing.T) {
		// Arrange
		expectedAPIKey := "zpk_thisIsTheFullKey"
		mockService.On("CreateAPIKey", mock.Anything, "user-123", "My New Test Key").Return(expectedAPIKey, nil).Once()

		payload := map[string]string{"description": "My New Test Key"}
		body, _ := json.Marshal(payload)
		req, _ := http.NewRequest(http.MethodPost, "/keys", bytes.NewBuffer(body))
		w := httptest.NewRecorder()

		// Act
		router.ServeHTTP(w, req)

		// Assert
		assert.Equal(t, http.StatusCreated, w.Code)
		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, expectedAPIKey, response["api_key"])
		mockService.AssertExpectations(t)
	})

	t.Run("Get API Keys Success", func(t *testing.T) {
		// Arrange
		expectedKeys := []model.APIKeyMetadata{
			{ID: "key-1", Prefix: "p1", Description: "Key 1"},
			{ID: "key-2", Prefix: "p2", Description: "Key 2"},
		}
		mockService.On("GetAPIKeys", mock.Anything, "user-123").Return(expectedKeys, nil).Once()

		req, _ := http.NewRequest(http.MethodGet, "/keys", nil)
		w := httptest.NewRecorder()

		// Act
		router.ServeHTTP(w, req)

		// Assert
		assert.Equal(t, http.StatusOK, w.Code)
		var response []model.APIKeyMetadata
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Len(t, response, 2)
		assert.Equal(t, "p1", response[0].Prefix)
		mockService.AssertExpectations(t)
	})

	t.Run("Revoke API Key Success", func(t *testing.T) {
		// Arrange
		mockService.On("RevokeAPIKey", mock.Anything, "user-123", "key-to-delete").Return(nil).Once()

		req, _ := http.NewRequest(http.MethodDelete, "/keys/key-to-delete", nil)
		w := httptest.NewRecorder()

		// Act
		router.ServeHTTP(w, req)

		// Assert
		assert.Equal(t, http.StatusOK, w.Code)
		mockService.AssertExpectations(t)
	})

	t.Run("Revoke API Key Service Error", func(t *testing.T) {
		// Arrange
		mockService.On("RevokeAPIKey", mock.Anything, "user-123", "key-to-delete").Return(errors.New("db error")).Once()

		req, _ := http.NewRequest(http.MethodDelete, "/keys/key-to-delete", nil)
		w := httptest.NewRecorder()

		// Act
		router.ServeHTTP(w, req)

		// Assert
		assert.Equal(t, http.StatusInternalServerError, w.Code)
		mockService.AssertExpectations(t)
	})
}
