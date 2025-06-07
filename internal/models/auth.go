package models

import (
	"time"

	commonModels "github.com/Lumina-Enterprise-Solutions/prism-common-libs/pkg/models"
	"github.com/golang-jwt/jwt/v4"
)

type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=6"`
	TenantID string `json:"tenant_id"`
}

type RegisterRequest struct {
	Email     string `json:"email" binding:"required,email"`
	Password  string `json:"password" binding:"required,min=6"`
	FirstName string `json:"first_name" binding:"required"`
	LastName  string `json:"last_name" binding:"required"`
	TenantID  string `json:"tenant_id"`
}

type LoginResponse struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
	User         UserInfo  `json:"user"`
}

type UserInfo struct {
	ID        string   `json:"id"`
	Email     string   `json:"email"`
	FirstName string   `json:"first_name"`
	LastName  string   `json:"last_name"`
	Status    string   `json:"status"`
	Roles     []string `json:"roles"`
	TenantID  string   `json:"tenant_id"`
}

// [TAMBAHKAN] Helper function untuk konversi
func ToUserInfo(user *commonModels.User) UserInfo {
	roleNames := make([]string, len(user.Roles))
	for i, role := range user.Roles {
		roleNames[i] = role.Name
	}

	return UserInfo{
		ID:        user.ID.String(),
		Email:     user.Email,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		Status:    user.Status,
		Roles:     roleNames,
		TenantID:  user.TenantID,
	}
}

type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

type ForgotPasswordRequest struct {
	Email    string `json:"email" binding:"required,email"`
	TenantID string `json:"tenant_id"`
}

type ResetPasswordRequest struct {
	Token    string `json:"token" binding:"required"`
	Password string `json:"password" binding:"required,min=6"`
}

type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password" binding:"required"`
	NewPassword     string `json:"new_password" binding:"required,min=6"`
}

type Claims struct {
	UserID   string   `json:"user_id"`
	Email    string   `json:"email"`
	TenantID string   `json:"tenant_id"`
	Roles    []string `json:"roles"`
	jwt.RegisteredClaims
}
