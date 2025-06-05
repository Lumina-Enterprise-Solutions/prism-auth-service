// File: prism-auth-service/internal/handlers/ad_mapping_handler.go
package handlers

import (
	"net/http"

	"github.com/Lumina-Enterprise-Solutions/prism-auth-service/internal/services"
	"github.com/Lumina-Enterprise-Solutions/prism-common-libs/pkg/utils"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type ADMappingHandler struct {
	service *services.ADMappingService
}

func NewADMappingHandler(service *services.ADMappingService) *ADMappingHandler {
	return &ADMappingHandler{service: service}
}

func (h *ADMappingHandler) CreateADMapping(c *gin.Context) {
	var req services.CreateADMappingRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.ValidationErrorResponse(c, utils.FormatValidationErrors(err))
		return
	}

	// TenantID bisa diambil dari body (jika superadmin) atau dari JWT admin tenant.
	// Untuk sekarang, kita ambil dari body request.
	if req.TenantID == "" {
		utils.ErrorResponse(c, http.StatusBadRequest, "tenant_id is required in request body", nil)
		return
	}

	mapping, err := h.service.CreateMapping(&req)
	if err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Failed to create AD mapping", err)
		return
	}
	utils.SuccessResponse(c, "AD mapping created successfully", mapping)
}

func (h *ADMappingHandler) GetADMappings(c *gin.Context) {
	// Superadmin bisa melihat semua atau filter by tenant_id query param.
	// Admin tenant hanya bisa melihat mapping untuk tenantnya.
	tenantID := c.Query("tenant_id") // Ambil dari query param

	// Jika admin non-super, tenantID harus dari JWT dan tidak bisa query tenant lain.
	// jwtTenantID, _ := c.Get("tenant_id").(string) // Dari token admin tenant
	// if !isSuperAdmin(c) && tenantID != jwtTenantID {
	//    utils.ErrorResponse(c, http.StatusForbidden, "Access denied to this tenant's mappings", nil)
	//    return
	// }
	// Untuk saat ini kita izinkan query param tenant_id untuk superadmin.

	if tenantID == "" {
		// Jika ingin hanya superadmin yang bisa GET semua tanpa filter tenant:
		// if !isSuperAdmin(c) {
		//    utils.ErrorResponse(c, http.StatusBadRequest, "tenant_id query parameter is required for non-superadmin", nil)
		//    return
		// }
		// Atau, default ke tenant dari JWT admin tenant jika ada.
		// Untuk saat ini, jika tenant_id kosong, kita bisa error atau biarkan service handle.
		utils.ErrorResponse(c, http.StatusBadRequest, "tenant_id query parameter is required", nil)
		return
	}

	mappings, err := h.service.GetMappingsByTenant(tenantID)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to get AD mappings", err)
		return
	}
	utils.SuccessResponse(c, "AD mappings retrieved successfully", mappings)
}

func (h *ADMappingHandler) GetADMappingByID(c *gin.Context) {
	mappingID, err := uuid.Parse(c.Param("mapping_id"))
	if err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid mapping ID format", err)
		return
	}
	mapping, err := h.service.GetMappingByID(mappingID)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to get AD mapping", err)
		return
	}
	if mapping == nil {
		utils.ErrorResponse(c, http.StatusNotFound, "AD mapping not found", nil)
		return
	}
	// Otorisasi: cek apakah admin punya hak akses ke tenant dari mapping.TenantID
	utils.SuccessResponse(c, "AD mapping retrieved successfully", mapping)
}

func (h *ADMappingHandler) UpdateADMapping(c *gin.Context) {
	mappingID, err := uuid.Parse(c.Param("mapping_id"))
	if err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid mapping ID format", err)
		return
	}

	var req services.UpdateADMappingRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.ValidationErrorResponse(c, utils.FormatValidationErrors(err))
		return
	}

	// Dapatkan tenantID dari JWT admin (jika bukan superadmin) untuk otorisasi
	// currentTenantID, _ := c.Get("tenant_id").(string)

	mapping, err := h.service.UpdateMapping(mappingID, &req, "" /* currentTenantID */) // Pass tenant dari JWT untuk validasi
	if err != nil {
		if err.Error() == "mapping not found" {
			utils.ErrorResponse(c, http.StatusNotFound, "AD mapping not found", err)
		} else {
			utils.ErrorResponse(c, http.StatusBadRequest, "Failed to update AD mapping", err)
		}
		return
	}
	utils.SuccessResponse(c, "AD mapping updated successfully", mapping)
}

func (h *ADMappingHandler) DeleteADMapping(c *gin.Context) {
	mappingID, err := uuid.Parse(c.Param("mapping_id"))
	if err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid mapping ID format", err)
		return
	}
	// currentTenantID, _ := c.Get("tenant_id").(string)

	err = h.service.DeleteMapping(mappingID, "" /* currentTenantID */)
	if err != nil {
		if err.Error() == "mapping not found" {
			utils.ErrorResponse(c, http.StatusNotFound, "AD mapping not found", err)
		} else {
			utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to delete AD mapping", err)
		}
		return
	}
	utils.SuccessResponse(c, "AD mapping deleted successfully", nil)
}
