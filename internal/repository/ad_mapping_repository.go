// File: prism-auth-service/internal/repository/ad_mapping_repository.go
package repository

import (
	"errors"

	"github.com/Lumina-Enterprise-Solutions/prism-common-libs/pkg/database"
	commonModels "github.com/Lumina-Enterprise-Solutions/prism-common-libs/pkg/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type ADMappingRepository struct {
	db *database.PostgresDB // Ini adalah koneksi DB utama, bukan yang di-scope ke tenant
}

func NewADMappingRepository(db *database.PostgresDB) *ADMappingRepository {
	return &ADMappingRepository{db: db}
}

// CreateMapping membuat mapping baru. Operasi pada skema public.
func (r *ADMappingRepository) CreateMapping(mapping *commonModels.ADGroupRoleMapping) error {
	return r.db.DB.Create(mapping).Error // Langsung menggunakan r.db.DB
}

func (r *ADMappingRepository) GetMappingByID(id uuid.UUID) (*commonModels.ADGroupRoleMapping, error) {
	var mapping commonModels.ADGroupRoleMapping
	err := r.db.DB.First(&mapping, "id = ?", id).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &mapping, nil
}

func (r *ADMappingRepository) GetMappingsByTenant(tenantID string) ([]commonModels.ADGroupRoleMapping, error) {
	var mappings []commonModels.ADGroupRoleMapping
	err := r.db.DB.Where("tenant_id = ?", tenantID).Find(&mappings).Error
	return mappings, err
}

// GetMappingByADGroupAndTenant mengambil mapping berdasarkan nama grup AD dan ID Tenant
func (r *ADMappingRepository) GetMappingByADGroupAndTenant(tenantID, adGroupName string) (*commonModels.ADGroupRoleMapping, error) {
	var mapping commonModels.ADGroupRoleMapping
	err := r.db.DB.Where("tenant_id = ? AND ad_group_name = ?", tenantID, adGroupName).First(&mapping).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &mapping, nil
}

func (r *ADMappingRepository) UpdateMapping(mapping *commonModels.ADGroupRoleMapping) error {
	return r.db.DB.Save(mapping).Error
}

func (r *ADMappingRepository) DeleteMapping(id uuid.UUID) error {
	return r.db.DB.Delete(&commonModels.ADGroupRoleMapping{}, "id = ?", id).Error
}

// GetMappingsByADGroupNames retrieves mappings for specific AD group names within a tenant.
func (r *ADMappingRepository) GetMappingsByADGroupNames(tenantID string, adGroupNames []string) ([]commonModels.ADGroupRoleMapping, error) {
	if len(adGroupNames) == 0 {
		return []commonModels.ADGroupRoleMapping{}, nil
	}
	var mappings []commonModels.ADGroupRoleMapping
	err := r.db.DB.Where("tenant_id = ? AND ad_group_name IN ?", tenantID, adGroupNames).Find(&mappings).Error
	return mappings, err
}
