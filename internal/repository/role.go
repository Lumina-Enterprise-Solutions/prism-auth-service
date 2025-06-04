// File: prism-auth-service/internal/repository/role.go
package repository

import (
	"errors"

	"github.com/Lumina-Enterprise-Solutions/prism-common-libs/pkg/database"
	commonModels "github.com/Lumina-Enterprise-Solutions/prism-common-libs/pkg/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type RoleRepository struct {
	db *database.PostgresDB
}

func NewRoleRepository(db *database.PostgresDB) *RoleRepository {
	return &RoleRepository{db: db}
}

// Create membuat role baru untuk tenant tertentu
func (r *RoleRepository) Create(role *commonModels.Role, tenantID string) error {
	db := r.db.WithTenant(tenantID)
	return db.Create(role).Error
}

// GetByID mengambil role berdasarkan ID untuk tenant tertentu
func (r *RoleRepository) GetByID(id uuid.UUID, tenantID string) (*commonModels.Role, error) {
	var role commonModels.Role
	db := r.db.WithTenant(tenantID)
	err := db.First(&role, "id = ?", id).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &role, nil
}

// GetByName mengambil role berdasarkan nama untuk tenant tertentu
func (r *RoleRepository) GetByName(name string, tenantID string) (*commonModels.Role, error) {
	var role commonModels.Role
	db := r.db.WithTenant(tenantID)
	err := db.First(&role, "name = ?", name).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &role, nil
}

// List mengambil semua role untuk tenant tertentu
func (r *RoleRepository) List(tenantID string) ([]commonModels.Role, error) {
	var roles []commonModels.Role
	db := r.db.WithTenant(tenantID)
	err := db.Find(&roles).Error
	return roles, err
}

// Update memperbarui role yang ada untuk tenant tertentu
func (r *RoleRepository) Update(role *commonModels.Role, tenantID string) error {
	db := r.db.WithTenant(tenantID)
	return db.Save(role).Error
}

// Delete menghapus role berdasarkan ID untuk tenant tertentu
func (r *RoleRepository) Delete(id uuid.UUID, tenantID string) error {
	db := r.db.WithTenant(tenantID)
	return db.Delete(&commonModels.Role{}, "id = ?", id).Error
}

// AssignRoleToUser menetapkan role ke user
func (r *RoleRepository) AssignRoleToUser(userID, roleID uuid.UUID, tenantID string) error {
	db := r.db.WithTenant(tenantID)
	// [DIHAPUS] Deklarasi userRole yang tidak digunakan
	// userRole := struct {
	// 	UserID uuid.UUID `gorm:"primaryKey"`
	// 	RoleID uuid.UUID `gorm:"primaryKey"`
	// }{UserID: userID, RoleID: roleID}

	// GORM akan mencari user dengan ID `userID` dan menambahkan role dengan ID `roleID`
	// ke dalam association "Roles" milik user tersebut. Ini akan membuat entri di tabel user_roles.
	// Pastikan model User dan Role Anda memiliki relasi many2many yang benar:
	// User struct: Roles []Role `gorm:"many2many:user_roles;"`
	// Role struct: Users []User `gorm:"many2many:user_roles;"`
	user := &commonModels.User{}
	user.ID = userID // Set ID user yang akan di-update asosiasinya

	roleToAppend := &commonModels.Role{}
	roleToAppend.ID = roleID // Set ID role yang akan ditambahkan

	// Penting: Pastikan db.WithTenant(tenantID) sudah mengatur search_path yang benar
	// sehingga GORM tahu di schema mana tabel user_roles berada.
	return db.Model(user).Association("Roles").Append(roleToAppend)
}

// RevokeRoleFromUser menghapus role dari user
func (r *RoleRepository) RevokeRoleFromUser(userID, roleID uuid.UUID, tenantID string) error {
	db := r.db.WithTenant(tenantID)

	user := &commonModels.User{}
	user.ID = userID

	roleToDelete := &commonModels.Role{}
	roleToDelete.ID = roleID

	return db.Model(user).Association("Roles").Delete(roleToDelete)
}

// GetUserRoles mengambil semua role yang dimiliki oleh user
func (r *RoleRepository) GetUserRoles(userID uuid.UUID, tenantID string) ([]commonModels.Role, error) {
	var user commonModels.User
	db := r.db.WithTenant(tenantID)
	// Preload("Roles") akan mengambil semua role yang berasosiasi dengan user ini
	// melalui tabel junction user_roles dalam schema tenant yang aktif.
	err := db.Preload("Roles").First(&user, "id = ?", userID).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return []commonModels.Role{}, nil
		}
		return nil, err
	}
	return user.Roles, nil
}
