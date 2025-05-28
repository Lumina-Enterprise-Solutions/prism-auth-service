package models

import (
	"time"

	commonModels "github.com/Lumina-Enterprise-Solutions/prism-common-libs/pkg/models"
	"github.com/google/uuid"
)

type CreateUserRequest struct {
	Email     string   `json:"email" binding:"required,email"`
	FirstName string   `json:"first_name" binding:"required"`
	LastName  string   `json:"last_name" binding:"required"`
	Password  string   `json:"password" binding:"required,min=6"`
	Roles     []string `json:"roles"`
	Status    string   `json:"status"`
}

type UpdateUserRequest struct {
	FirstName string   `json:"first_name"`
	LastName  string   `json:"last_name"`
	Roles     []string `json:"roles"`
	Status    string   `json:"status"`
}

type UpdateProfileRequest struct {
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
}

type CreateRoleRequest struct {
	Name        string                 `json:"name" binding:"required"`
	Permissions map[string]interface{} `json:"permissions"`
}

type UpdateRoleRequest struct {
	Name        string                 `json:"name"`
	Permissions map[string]interface{} `json:"permissions"`
}

type UserResponse struct {
	ID        uuid.UUID      `json:"id"`
	Email     string         `json:"email"`
	FirstName string         `json:"first_name"`
	LastName  string         `json:"last_name"`
	Status    string         `json:"status"`
	Roles     []RoleResponse `json:"roles"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
}

type RoleResponse struct {
	ID          uuid.UUID              `json:"id"`
	Name        string                 `json:"name"`
	Permissions map[string]interface{} `json:"permissions"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

// Convert common User model to UserResponse
func ToUserResponse(u *commonModels.User) UserResponse {
	roles := make([]RoleResponse, len(u.Roles))
	for i, role := range u.Roles {
		roles[i] = RoleResponse{
			ID:          role.ID,
			Name:        role.Name,
			Permissions: role.Permissions,
			CreatedAt:   role.CreatedAt,
			UpdatedAt:   role.UpdatedAt,
		}
	}

	return UserResponse{
		ID:        u.ID,
		Email:     u.Email,
		FirstName: u.FirstName,
		LastName:  u.LastName,
		Status:    u.Status,
		Roles:     roles,
		CreatedAt: u.CreatedAt,
		UpdatedAt: u.UpdatedAt,
	}
}
