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
	err := db.Preload("Roles").First(&user, "email = ?", email).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &user, nil
}

func (r *UserRepository) Update(user *models.User, tenantID string) error {
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
