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
	Roles     []string `json:"roles"`  // Bisa berupa ID Role atau Nama Role
	Status    string   `json:"status"` // e.g., "active", "inactive"
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
	Name        string              `json:"name" binding:"required"`
	Permissions map[string][]string `json:"permissions"` // [MODIFIKASI] Sesuai PermissionMap
}

type UpdateRoleRequest struct {
	Name        string              `json:"name,omitempty"`
	Permissions map[string][]string `json:"permissions,omitempty"` // [MODIFIKASI]
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
	ID          uuid.UUID           `json:"id"`
	Name        string              `json:"name"`
	Permissions map[string][]string `json:"permissions"` // [MODIFIKASI]
	CreatedAt   time.Time           `json:"created_at"`
	UpdatedAt   time.Time           `json:"updated_at"`
}

func ToUserResponse(u *commonModels.User) UserResponse {
	roles := make([]RoleResponse, 0) // Initialize as empty slice
	if u.Roles != nil {              // Check if Roles is nil before iterating
		roles = make([]RoleResponse, len(u.Roles))
		for i, role := range u.Roles {
			roles[i] = ToRoleResponse(&role) // Gunakan ToRoleResponse
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

// [TAMBAHKAN] Convert common Role model to RoleResponse
func ToRoleResponse(r *commonModels.Role) RoleResponse {
	// Pastikan permissions tidak nil di response jika di DB nil
	permissions := make(map[string][]string)
	if r.Permissions != nil {
		permissions = r.Permissions
	}
	return RoleResponse{
		ID:          r.ID,
		Name:        r.Name,
		Permissions: permissions,
		CreatedAt:   r.CreatedAt,
		UpdatedAt:   r.UpdatedAt,
	}
}
