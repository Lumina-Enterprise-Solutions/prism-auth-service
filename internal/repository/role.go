package repository

import (
	"errors"

	"github.com/Lumina-Enterprise-Solutions/prism-common-libs/pkg/database"
	commonLogger "github.com/Lumina-Enterprise-Solutions/prism-common-libs/pkg/logger" // <-- [TAMBAHKAN]
	commonModels "github.com/Lumina-Enterprise-Solutions/prism-common-libs/pkg/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
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

func (r *RoleRepository) AssignRoleToUser(user *commonModels.User, roleID uuid.UUID, tenantID string) error {
	db := r.db.WithTenant(tenantID)

	// roleToAppend := &commonModels.Role{}
	// roleToAppend.ID = roleID
	userRole := map[string]interface{}{
		"user_id": user.ID,
		"role_id": roleID,
	}

	// This is now more explicit: append the role to this specific user object's "Roles" association.
	// return db.Model(user).Association("Roles").Append(roleToAppend)
	return db.Table("user_roles").Clauses(clause.OnConflict{DoNothing: true}).Create(&userRole).Error
}

func (r *RoleRepository) RevokeRoleFromUser(user *commonModels.User, roleID uuid.UUID, tenantID string) error {
	db := r.db.WithTenant(tenantID)

	// roleToDelete := &commonModels.Role{}
	// roleToDelete.ID = roleID

	// return db.Model(user).Association("Roles").Delete(roleToDelete)
	return db.Table("user_roles").Where("user_id = ? AND role_id = ?", user.ID, roleID).Delete(nil).Error
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

// GetUserPermissions mengambil dan menggabungkan semua permission untuk daftar nama role tertentu dalam satu tenant.
// Ini adalah implementasi untuk interface RBACPermissionChecker.
func (r *RoleRepository) GetUserPermissions(tenantID string, roleNames []string) (commonModels.PermissionMap, error) {
	if len(roleNames) == 0 {
		return make(commonModels.PermissionMap), nil // Tidak ada role, tidak ada permission
	}

	db := r.db.WithTenant(tenantID)
	var roles []commonModels.Role

	// Ambil semua objek Role berdasarkan nama-nama role
	// PERHATIAN: `WHERE name IN (?)` dengan GORM bisa tricky jika roleNames kosong. Sudah ditangani di atas.
	if err := db.Where("name IN ?", roleNames).Find(&roles).Error; err != nil {
		commonLogger.Errorf("RBAC/Repo: Error fetching roles by names for tenant %s: %v. Roles: %v", tenantID, err, roleNames)
		return nil, err
	}

	if len(roles) == 0 {
		commonLogger.Warnf("RBAC/Repo: No roles found for names %v in tenant %s", roleNames, tenantID)
		// Ini bisa berarti role yang ada di JWT tidak (lagi) ada di DB.
		// Bisa dianggap sebagai tidak ada permission.
		return make(commonModels.PermissionMap), nil
	}

	// Gabungkan semua permissions dari role-role tersebut
	// Key: Resource, Value: map[string]bool untuk action (untuk de-duplikasi action)
	mergedPermissions := make(commonModels.PermissionMap)

	for _, role := range roles {
		if role.Permissions == nil {
			continue
		}
		for resource, actions := range role.Permissions {
			if _, ok := mergedPermissions[resource]; !ok {
				mergedPermissions[resource] = []string{}
			}

			// Untuk menghindari duplikasi action pada resource yang sama dari role berbeda
			existingActionsMap := make(map[string]bool)
			for _, existingAction := range mergedPermissions[resource] {
				existingActionsMap[existingAction] = true
			}

			for _, newAction := range actions {
				if !existingActionsMap[newAction] {
					mergedPermissions[resource] = append(mergedPermissions[resource], newAction)
					existingActionsMap[newAction] = true
				}
			}
		}
	}
	commonLogger.Debugf("RBAC/Repo: Merged permissions for tenant %s, roles %v: %v", tenantID, roleNames, mergedPermissions)
	return mergedPermissions, nil
}
