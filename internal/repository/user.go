package repository

import (
	"errors"

	"github.com/Lumina-Enterprise-Solutions/prism-common-libs/pkg/database"
	"github.com/Lumina-Enterprise-Solutions/prism-common-libs/pkg/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type UserRepository struct {
	db *database.PostgresDB
}

func NewUserRepository(db *database.PostgresDB) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) Create(user *models.User, tenantID string) error {
	// Pastikan user.TenantID diisi sebelum create, bisa dari arg tenantID
	if user.TenantID == "" {
		user.TenantID = tenantID // Atau pastikan ini sudah diset oleh service
	}
	db := r.db.WithTenant(tenantID)
	return db.Create(user).Error
}

func (r *UserRepository) GetByID(id uuid.UUID, tenantID string) (*models.User, error) {
	var user models.User
	db := r.db.WithTenant(tenantID)
	err := db.Preload("Roles").First(&user, "id = ?", id).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &user, nil
}

func (r *UserRepository) GetByEmail(email, tenantID string) (*models.User, error) {
	var user models.User
	db := r.db.WithTenant(tenantID)
	// Tambahkan filter tenant_id jika belum ada di model User dan query
	err := db.Preload("Roles").First(&user, "email = ? AND tenant_id = ?", email, tenantID).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &user, nil
}

func (r *UserRepository) Update(user *models.User, tenantID string) error {
	// Sama, pastikan user.TenantID ada dan sesuai
	if user.TenantID == "" {
		user.TenantID = tenantID
	}
	db := r.db.WithTenant(tenantID)
	return db.Save(user).Error
}

func (r *UserRepository) Delete(id uuid.UUID, tenantID string) error {
	db := r.db.WithTenant(tenantID)
	return db.Delete(&models.User{}, "id = ?", id).Error
}

func (r *UserRepository) List(tenantID string, offset, limit int) ([]models.User, int64, error) {
	var users []models.User
	var total int64

	db := r.db.WithTenant(tenantID)

	// Count total records
	if err := db.Model(&models.User{}).Count(&total).Error; err != nil {
		return nil, 0, err
	}

	// Get paginated results
	err := db.Preload("Roles").Offset(offset).Limit(limit).Find(&users).Error
	return users, total, err
}

func (r *UserRepository) UpdatePassword(userID uuid.UUID, hashedPassword, tenantID string) error {
	db := r.db.WithTenant(tenantID)
	return db.Model(&models.User{}).Where("id = ?", userID).Update("password_hash", hashedPassword).Error
}

// [TAMBAHKAN] GetByADObjectID mengambil user berdasarkan AD Object GUID dan TenantID
func (r *UserRepository) GetByADObjectID(adObjectID string, tenantID string) (*models.User, error) {
	var user models.User
	db := r.db.WithTenant(tenantID) // Penting jika user di-scope per tenant
	// Jika adObjectID global unik, tenantID mungkin tidak perlu di query ini, tapi bagus untuk konsistensi.
	// Jika model User memiliki field TenantID, maka query harus menyertakannya.
	err := db.Preload("Roles").First(&user, "ad_object_id = ? AND tenant_id = ?", adObjectID, tenantID).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &user, nil
}

// [TAMBAHKAN] ListADManagedByTenant mengambil semua user yang AD-managed untuk tenant tertentu
func (r *UserRepository) ListADManagedByTenant(tenantID string) ([]models.User, error) {
	var users []models.User
	db := r.db.WithTenant(tenantID)
	// Pastikan filter tenant_id juga diterapkan jika User model punya field TenantID
	err := db.Where("is_ad_managed = ? AND tenant_id = ?", true, tenantID).Find(&users).Error
	return users, err
}
