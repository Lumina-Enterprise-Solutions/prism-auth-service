package services // <--- Pastikan package adalah 'services'

import (
	"errors"
	"fmt"

	"github.com/Lumina-Enterprise-Solutions/prism-auth-service/internal/repository" // <--- Pastikan impor ini ada
	commonModels "github.com/Lumina-Enterprise-Solutions/prism-common-libs/pkg/models"
	"github.com/google/uuid"
)

// Pastikan nama struct dimulai dengan huruf kapital
type ADMappingService struct {
	mappingRepo *repository.ADMappingRepository
	roleRepo    *repository.RoleRepository
}

// Pastikan nama struct dimulai dengan huruf kapital
type CreateADMappingRequest struct {
	ADGroupName string    `json:"ad_group_name" binding:"required"`
	RoleID      uuid.UUID `json:"role_id" binding:"required"`
	TenantID    string    `json:"tenant_id" binding:"required"`
}

// Pastikan nama struct dimulai dengan huruf kapital
type UpdateADMappingRequest struct {
	ADGroupName *string    `json:"ad_group_name"`
	RoleID      *uuid.UUID `json:"role_id"`
}

func NewADMappingService(mappingRepo *repository.ADMappingRepository, roleRepo *repository.RoleRepository) *ADMappingService {
	return &ADMappingService{
		mappingRepo: mappingRepo,
		roleRepo:    roleRepo,
	}
}

func (s *ADMappingService) CreateMapping(req *CreateADMappingRequest) (*commonModels.ADGroupRoleMapping, error) {
	// 1. Validasi apakah RoleID ada untuk TenantID yang diberikan
	role, err := s.roleRepo.GetByID(req.RoleID, req.TenantID)
	if err != nil {
		return nil, fmt.Errorf("error validating role: %w", err)
	}
	if role == nil {
		return nil, fmt.Errorf("role with ID %s not found for tenant %s", req.RoleID, req.TenantID)
	}

	mapping := &commonModels.ADGroupRoleMapping{
		ADGroupName: req.ADGroupName,
		RoleID:      req.RoleID,
		TenantID:    req.TenantID,
	}

	if err := s.mappingRepo.CreateMapping(mapping); err != nil {
		return nil, fmt.Errorf("failed to create AD group role mapping: %w", err)
	}
	return mapping, nil
}

func (s *ADMappingService) GetMappingByID(id uuid.UUID) (*commonModels.ADGroupRoleMapping, error) {
	mapping, err := s.mappingRepo.GetMappingByID(id)
	if err != nil {
		return nil, err
	}
	if mapping == nil {
		return nil, errors.New("mapping not found") // Service layer returns specific error
	}
	return mapping, nil
}

func (s *ADMappingService) GetMappingsByTenant(tenantID string) ([]commonModels.ADGroupRoleMapping, error) {
	if tenantID == "" {
		return nil, errors.New("tenant_id is required")
	}
	return s.mappingRepo.GetMappingsByTenant(tenantID)
}

func (s *ADMappingService) UpdateMapping(id uuid.UUID, req *UpdateADMappingRequest, currentTenantID string /* unused for now */) (*commonModels.ADGroupRoleMapping, error) {
	mapping, err := s.mappingRepo.GetMappingByID(id)
	if err != nil {
		return nil, fmt.Errorf("error fetching mapping: %w", err)
	}
	if mapping == nil {
		return nil, errors.New("mapping not found")
	}

	updated := false
	if req.ADGroupName != nil && *req.ADGroupName != "" && *req.ADGroupName != mapping.ADGroupName {
		// Cek apakah kombinasi TenantID dan ADGroupName baru sudah ada (jika harus unik)
		// existing, _ := s.mappingRepo.GetMappingByADGroupAndTenant(mapping.TenantID, *req.ADGroupName)
		// if existing != nil && existing.ID != mapping.ID {
		// 	 return nil, errors.New("another mapping for this AD group and tenant already exists")
		// }
		mapping.ADGroupName = *req.ADGroupName
		updated = true
	}
	if req.RoleID != nil && *req.RoleID != uuid.Nil && *req.RoleID != mapping.RoleID {
		role, err := s.roleRepo.GetByID(*req.RoleID, mapping.TenantID)
		if err != nil {
			return nil, fmt.Errorf("error validating new role: %w", err)
		}
		if role == nil {
			return nil, fmt.Errorf("new role with ID %s not found for tenant %s", *req.RoleID, mapping.TenantID)
		}
		mapping.RoleID = *req.RoleID
		updated = true
	}

	if updated {
		if err := s.mappingRepo.UpdateMapping(mapping); err != nil {
			return nil, fmt.Errorf("failed to update AD group role mapping: %w", err)
		}
	}
	return mapping, nil
}

func (s *ADMappingService) DeleteMapping(id uuid.UUID, currentTenantID string /* unused for now */) error {
	mapping, err := s.mappingRepo.GetMappingByID(id)
	if err != nil {
		return fmt.Errorf("error fetching mapping for deletion: %w", err)
	}
	if mapping == nil {
		return errors.New("mapping not found")
	}
	return s.mappingRepo.DeleteMapping(id)
}
