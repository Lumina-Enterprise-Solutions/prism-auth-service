// File: prism-auth-service/internal/services/ad_sync_service.go
package services

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Lumina-Enterprise-Solutions/prism-auth-service/internal/repository"
	commonConfig "github.com/Lumina-Enterprise-Solutions/prism-common-libs/pkg/config"
	commonLogger "github.com/Lumina-Enterprise-Solutions/prism-common-libs/pkg/logger"
	commonModels "github.com/Lumina-Enterprise-Solutions/prism-common-libs/pkg/models"
	"github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"
)

type ADSyncService struct {
	userRepo    *repository.UserRepository
	roleRepo    *repository.RoleRepository
	mappingRepo *repository.ADMappingRepository
	tenantRepo  *repository.TenantRepository // Untuk mendapatkan daftar tenant yang akan disinkronkan
	appConfig   *commonConfig.Config
	// authService *AuthService // Mungkin tidak perlu authService di sini, tapi ldapConnect dan convertGUID bisa jadi helper global
}

// Fungsi untuk konversi GUID bisa dipindah ke package utils jika dipakai di banyak tempat
func convertADObjectGUIDToStringGlobal(guidBytes []byte) string {
	if len(guidBytes) != 16 {
		return ""
	}
	return fmt.Sprintf("%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		guidBytes[3], guidBytes[2], guidBytes[1], guidBytes[0],
		guidBytes[5], guidBytes[4],
		guidBytes[7], guidBytes[6],
		guidBytes[8], guidBytes[9],
		guidBytes[10], guidBytes[11], guidBytes[12], guidBytes[13], guidBytes[14], guidBytes[15])
}

func NewADSyncService(
	userRepo *repository.UserRepository,
	roleRepo *repository.RoleRepository,
	mappingRepo *repository.ADMappingRepository,
	tenantRepo *repository.TenantRepository,
	appConfig *commonConfig.Config,
) *ADSyncService {
	return &ADSyncService{
		userRepo:    userRepo,
		roleRepo:    roleRepo,
		mappingRepo: mappingRepo,
		tenantRepo:  tenantRepo,
		appConfig:   appConfig,
	}
}

// ldapConnect (bisa di-refactor menjadi helper global jika AuthService juga pakai)
func (s *ADSyncService) ldapConnect(cfgLDAP commonConfig.LDAPConfig) (*ldap.Conn, error) {
	ldapURL := fmt.Sprintf("ldap://%s:%d", cfgLDAP.Host, cfgLDAP.Port)
	var l *ldap.Conn
	var err error
	if cfgLDAP.UseTLS {
		ldapURL = fmt.Sprintf("ldaps://%s:%d", cfgLDAP.Host, cfgLDAP.Port)
		tlsConfig := &tls.Config{InsecureSkipVerify: true} // HANYA UNTUK DEV
		l, err = ldap.DialURL(ldapURL, ldap.DialWithTLSConfig(tlsConfig))
	} else {
		l, err = ldap.DialURL(ldapURL)
	}
	if err != nil {
		return nil, fmt.Errorf("ldap dial error: %w", err)
	}
	// StartTLS jika diperlukan (tidak diimplementasikan di sini)
	return l, nil
}

// SyncAllTenants menjalankan sinkronisasi untuk semua tenant yang terdaftar (atau yang dikonfigurasi untuk sync AD).
// Ini bisa dipanggil oleh scheduler.
func (s *ADSyncService) SyncAllTenants(ctx context.Context) error {
	commonLogger.Info(ctx, "Starting AD Sync for all configured tenants...")
	cfgLDAP := s.appConfig.LDAP
	if cfgLDAP.Host == "" {
		commonLogger.Error(ctx, "ADSync: LDAP Host not configured. Skipping sync.")
		return errors.New("ldap not configured")
	}

	// Dapatkan semua tenant dari DB (Anda mungkin ingin filter tenant yang aktif atau yang punya konfigurasi AD sync).
	// Untuk sekarang, kita asumsikan TenantRepository punya ListAllActive atau semacamnya.
	// Ini adalah contoh, Anda perlu method yang sesuai di tenantRepo.
	// tenants, err := s.tenantRepo.ListAllActiveTenants() // Placeholder
	// if err != nil {
	// 	commonLogger.Error(ctx, "ADSync: Failed to list tenants", "error", err)
	// 	return err
	// }
	// Untuk demo, kita akan sync tenant "default" saja.
	tenants := []commonModels.Tenant{{Slug: "default", Name: "Default Tenant"}} // Placeholder

	for _, tenant := range tenants {
		commonLogger.Info(ctx, "ADSync: Starting sync for tenant", "tenant_id", tenant.Slug, "tenant_name", tenant.Name)
		err := s.syncTenant(ctx, tenant.Slug, cfgLDAP) // Menggunakan slug tenant sebagai tenantID
		if err != nil {
			commonLogger.Error(ctx, "ADSync: Failed to sync tenant", "tenant_id", tenant.Slug, "error", err)
			// Lanjutkan ke tenant berikutnya atau stop? Untuk sekarang, lanjutkan.
		} else {
			commonLogger.Info(ctx, "ADSync: Successfully synced tenant", "tenant_id", tenant.Slug)
		}
	}
	commonLogger.Info(ctx, "AD Sync for all configured tenants completed.")
	return nil
}

// syncTenant melakukan sinkronisasi untuk satu tenant.
func (s *ADSyncService) syncTenant(ctx context.Context, tenantID string, cfgLDAP commonConfig.LDAPConfig) error {
	l, err := s.ldapConnect(cfgLDAP)
	if err != nil {
		return fmt.Errorf("ldap connection for tenant %s failed: %w", tenantID, err)
	}
	defer l.Close()

	// Bind dengan service account
	if cfgLDAP.BindDN == "" || cfgLDAP.BindPassword == "" {
		return fmt.Errorf("ldap service account (BindDN or BindPassword) not configured for tenant %s sync", tenantID)
	}
	err = l.Bind(cfgLDAP.BindDN, cfgLDAP.BindPassword)
	if err != nil {
		return fmt.Errorf("ldap bind with service account for tenant %s failed: %w", tenantID, err)
	}
	commonLogger.Debug(ctx, "ADSync: LDAP bind successful with service account", "tenant_id", tenantID)

	// Filter dasar untuk user + filter kustom dari config
	baseFilter := "(objectClass=user)"
	finalFilter := baseFilter
	if cfgLDAP.ADUserFilter != "" {
		finalFilter = fmt.Sprintf("(&%s%s)", baseFilter, cfgLDAP.ADUserFilter)
	}

	attributesToFetch := []string{
		cfgLDAP.ADAttributeUPN, cfgLDAP.ADAttributeObjectGUID, cfgLDAP.ADAttributeEmail,
		cfgLDAP.ADAttributeFirstName, cfgLDAP.ADAttributeLastName, cfgLDAP.ADAttributeMemberOf,
		cfgLDAP.ADAttributeAccountStatus, // e.g., userAccountControl
	}
	// Bersihkan atribut kosong
	var validAttributes []string
	for _, attr := range attributesToFetch {
		if attr != "" {
			validAttributes = append(validAttributes, attr)
		}
	}
	if len(validAttributes) < 3 { // UPN, GUID, Status minimal
		return fmt.Errorf("insufficient AD attributes configured for sync (UPN, GUID, Status are essential)")
	}

	searchRequest := ldap.NewSearchRequest(
		cfgLDAP.UserBaseDN, // BaseDN bisa juga per-tenant jika konfigurasi mendukung
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		finalFilter,
		validAttributes,
		nil,
	)

	commonLogger.Info(ctx, "ADSync: Searching AD users for sync", "tenant_id", tenantID, "base_dn", cfgLDAP.UserBaseDN, "filter", finalFilter)
	sr, err := l.SearchWithPaging(searchRequest, 500) // Gunakan paging untuk hasil besar
	if err != nil {
		return fmt.Errorf("ldap search for tenant %s failed: %w", tenantID, err)
	}
	commonLogger.Info(ctx, "ADSync: Found AD users for sync", "count", len(sr.Entries), "tenant_id", tenantID)

	processedADObjectGUIDs := make(map[string]bool) // Untuk melacak user AD yang diproses

	for _, adEntry := range sr.Entries {
		select {
		case <-ctx.Done():
			commonLogger.Info(ctx, "ADSync: Context cancelled, stopping sync for tenant", "tenant_id", tenantID)
			return ctx.Err()
		default:
		}

		adUPN := adEntry.GetAttributeValue(cfgLDAP.ADAttributeUPN)
		adObjectGUIDRaw := adEntry.GetRawAttributeValue(cfgLDAP.ADAttributeObjectGUID)
		adObjectGUID := convertADObjectGUIDToStringGlobal(adObjectGUIDRaw)

		if adObjectGUID == "" {
			commonLogger.Warn(ctx, "ADSync: Skipping entry, missing ObjectGUID", "dn", adEntry.DN, "tenant_id", tenantID)
			continue
		}
		processedADObjectGUIDs[adObjectGUID] = true

		adEmail := adEntry.GetAttributeValue(cfgLDAP.ADAttributeEmail)
		if adEmail == "" {
			adEmail = adUPN
		} // Fallback email ke UPN jika kosong
		adFirstName := adEntry.GetAttributeValue(cfgLDAP.ADAttributeFirstName)
		adLastName := adEntry.GetAttributeValue(cfgLDAP.ADAttributeLastName)
		adMemberOf := adEntry.GetAttributeValues(cfgLDAP.ADAttributeMemberOf)
		adStatusRaw := adEntry.GetAttributeValue(cfgLDAP.ADAttributeAccountStatus) // userAccountControl

		// Tentukan status lokal berdasarkan status AD
		// userAccountControl: 512 (Enabled), 514 (Disabled), 544 (Enabled, Password Not Required), etc.
		// Bit 1 (0x0002) adalah ACCOUNTDISABLE.
		isADAccountDisabled := false
		if cfgLDAP.ADAttributeAccountStatus == "userAccountControl" && adStatusRaw != "" {
			// [MODIFIKASI] Gunakan strconv.Atoi atau ParseInt
			uac, errAtoi := strconv.Atoi(adStatusRaw)
			if errAtoi != nil {
				commonLogger.Warn(ctx, "ADSync: Failed to parse userAccountControl value",
					"value", adStatusRaw, "dn", adEntry.DN, "error", errAtoi)
				// Default ke tidak disabled jika tidak bisa parse, atau kebijakan lain
			} else {
				if (uac & 0x0002) == 0x0002 { // Jika bit ACCOUNTDISABLE diset
					isADAccountDisabled = true
				}
			}
		}

		localUserStatus := "active"
		if isADAccountDisabled {
			localUserStatus = "inactive_ad" // Status khusus untuk user nonaktif dari AD
		}

		// Cari atau buat user lokal
		localUser, err := s.userRepo.GetByADObjectID(adObjectGUID, tenantID)
		if err != nil {
			commonLogger.Error(ctx, "ADSync: DB error fetching local user by AD GUID", "ad_guid", adObjectGUID, "tenant_id", tenantID, "error", err)
			continue // Lanjut ke user AD berikutnya
		}

		now := time.Now()
		if localUser == nil { // JIT Provisioning
			commonLogger.Info(ctx, "ADSync: Provisioning new local user from AD", "ad_upn", adUPN, "ad_guid", adObjectGUID, "tenant_id", tenantID)
			newUser := &commonModels.User{
				TenantID:            tenantID,
				Email:               adEmail,
				FirstName:           adFirstName,
				LastName:            adLastName,
				Status:              localUserStatus,
				ADUserPrincipalName: adUPN,
				ADObjectID:          adObjectGUID,
				IsADManaged:         true,
				LastADSync:          &now,
			}
			if errCreate := s.userRepo.Create(newUser, tenantID); errCreate != nil {
				commonLogger.Error(ctx, "ADSync: Failed to create local user", "ad_upn", adUPN, "tenant_id", tenantID, "error", errCreate)
				continue
			}
			localUser = newUser
		} else { // Update user lokal yang ada
			if localUser.ADUserPrincipalName != adUPN || localUser.Email != adEmail ||
				localUser.FirstName != adFirstName || localUser.LastName != adLastName ||
				localUser.Status != localUserStatus || !localUser.IsADManaged {

				localUser.ADUserPrincipalName = adUPN
				localUser.Email = adEmail
				localUser.FirstName = adFirstName
				localUser.LastName = adLastName
				localUser.Status = localUserStatus
				localUser.IsADManaged = true // Pastikan ini diset
				localUser.LastADSync = &now
				if errUpdate := s.userRepo.Update(localUser, tenantID); errUpdate != nil {
					commonLogger.Error(ctx, "ADSync: Failed to update local user", "local_user_id", localUser.ID, "tenant_id", tenantID, "error", errUpdate)
					// Lanjutkan saja untuk sinkronisasi role
				}
			} else {
				// Tidak ada perubahan atribut dasar, hanya update LastADSync
				localUser.LastADSync = &now
				if errUpdate := s.userRepo.Update(localUser, tenantID); errUpdate != nil {
					commonLogger.Warn(ctx, "ADSync: Failed to update LastADSync for local user", "local_user_id", localUser.ID, "error", errUpdate)
				}
			}
		}

		// Sinkronkan roles
		// (Menggunakan fungsi yang sama seperti di AuthService.Login, bisa di-refactor ke helper)
		// authSvc := NewAuthService(s.userRepo, s.roleRepo, s.mappingRepo, nil, nil, s.appConfig) // JWTService & RedisClient bisa nil jika hanya butuh sync
		// if errSyncRoles := authSvc.syncUserRolesFromADGroups(localUser, adMemberOf, tenantID); errSyncRoles != nil {
		// Ganti dengan memanggil metode internal atau helper
		if errSyncRoles := s.syncUserRolesFromADGroupsInternal(localUser, adMemberOf, tenantID, ctx); errSyncRoles != nil {
			commonLogger.Warn(ctx, "ADSync: Failed to sync roles for user", "local_user_id", localUser.ID, "ad_upn", adUPN, "tenant_id", tenantID, "error", errSyncRoles)
		}
	}

	// De-provisioning: Nonaktifkan user lokal yang IsADManaged=true, ada di tenant ini,
	// tapi ADObjectID-nya tidak ada di processedADObjectGUIDs (artinya tidak lagi ada di AD atau tidak cocok filter)
	// Ini adalah operasi yang berpotensi destruktif, lakukan dengan hati-hati.
	// Ambil semua user lokal yang AD-managed untuk tenant ini.
	allADManagedUsersInTenant, err := s.userRepo.ListADManagedByTenant(tenantID) // Perlu method baru di repo
	if err != nil {
		commonLogger.Error(ctx, "ADSync: Failed to list local AD managed users for de-provisioning check", "tenant_id", tenantID, "error", err)
		return err // Mungkin lebih baik stop jika ini gagal
	}

	for _, localUser := range allADManagedUsersInTenant {
		select {
		case <-ctx.Done():
			commonLogger.Info(ctx, "ADSync: Context cancelled during de-provisioning", "tenant_id", tenantID)
			return ctx.Err()
		default:
		}
		if _, foundInAD := processedADObjectGUIDs[localUser.ADObjectID]; !foundInAD {
			if localUser.Status != "archived_ad" && localUser.Status != "inactive_ad" { // Atau status lain yang menandakan sudah diproses
				commonLogger.Info(ctx, "ADSync: De-provisioning local user (not found in current AD sync)", "local_user_id", localUser.ID, "ad_guid", localUser.ADObjectID, "tenant_id", tenantID)
				localUser.Status = "archived_ad"       // Atau "inactive_ad_removed"
				localUser.LastADSync = Ptr(time.Now()) // Helper Ptr untuk time.Time
				if errUpdate := s.userRepo.Update(&localUser, tenantID); errUpdate != nil {
					commonLogger.Error(ctx, "ADSync: Failed to de-provision (update status) local user", "local_user_id", localUser.ID, "tenant_id", tenantID, "error", errUpdate)
				}
			}
		}
	}
	return nil
}

// syncUserRolesFromADGroupsInternal adalah helper internal yang mirip dengan yang ada di AuthService
func (s *ADSyncService) syncUserRolesFromADGroupsInternal(localUser *commonModels.User, adGroupDNs []string, tenantID string, ctx context.Context) error {
	if !localUser.IsADManaged {
		return nil
	}

	var adGroupSimpleNames []string
	for _, dn := range adGroupDNs {
		if parts := strings.Split(dn, ","); len(parts) > 0 {
			if cnParts := strings.Split(parts[0], "="); len(cnParts) == 2 {
				adGroupSimpleNames = append(adGroupSimpleNames, cnParts[1])
			}
		}
	}
	if len(adGroupSimpleNames) == 0 {
		commonLogger.Debug(ctx, "ADSyncRoles: No simple AD group names extracted for user", "user_id", localUser.ID, "ad_upn", localUser.ADUserPrincipalName)
		// Jika tidak ada grup AD, pertimbangkan untuk menghapus semua role yang berasal dari AD.
		// Untuk implementasi yang lebih aman, kita hanya proses jika ada grup.
		// Menghapus semua role bisa berisiko jika ada role yang diassign manual.
		// Ini memerlukan flag pada user_roles (misal, `is_from_ad`) untuk pembersihan yang aman.
	}

	mappings, err := s.mappingRepo.GetMappingsByADGroupNames(tenantID, adGroupSimpleNames)
	if err != nil {
		return fmt.Errorf("error fetching AD group to role mappings for sync: %w", err)
	}

	targetRoleIDsFromAD := make(map[uuid.UUID]bool)
	for _, m := range mappings {
		targetRoleIDsFromAD[m.RoleID] = true
	}

	currentUserRoles, err := s.roleRepo.GetUserRoles(localUser.ID, tenantID)
	if err != nil {
		return fmt.Errorf("error fetching current user roles for sync: %w", err)
	}
	currentRoleIDsMap := make(map[uuid.UUID]bool)
	for _, r := range currentUserRoles {
		currentRoleIDsMap[r.ID] = true
	}

	// Revoke
	for _, currentRole := range currentUserRoles {
		// Asumsi sederhana: jika role tidak lagi di mapping AD, revoke.
		// Perlu logika lebih canggih jika ada role manual.
		if _, shouldHaveRole := targetRoleIDsFromAD[currentRole.ID]; !shouldHaveRole {
			// Cek apakah role ini memang berasal dari AD (jika ada flagnya).
			// Untuk sekarang, kita revoke saja.
			commonLogger.Info(ctx, "ADSyncRoles: Revoking role for user", "role_id", currentRole.ID, "role_name", currentRole.Name, "user_id", localUser.ID)
			if errRevoke := s.roleRepo.RevokeRoleFromUser(localUser.ID, currentRole.ID, tenantID); errRevoke != nil {
				commonLogger.Warn(ctx, "ADSyncRoles: Failed to revoke role", "role_id", currentRole.ID, "user_id", localUser.ID, "error", errRevoke)
			}
		}
	}
	// Assign
	for roleID := range targetRoleIDsFromAD {
		if _, alreadyHasRole := currentRoleIDsMap[roleID]; !alreadyHasRole {
			roleDetails, _ := s.roleRepo.GetByID(roleID, tenantID)
			roleNameForLog := fmt.Sprintf("ID %s", roleID)
			if roleDetails != nil {
				roleNameForLog = roleDetails.Name
			}
			commonLogger.Info(ctx, "ADSyncRoles: Assigning role to user", "role_id", roleID, "role_name", roleNameForLog, "user_id", localUser.ID)
			if errAssign := s.roleRepo.AssignRoleToUser(localUser.ID, roleID, tenantID); errAssign != nil {
				if !strings.Contains(strings.ToLower(errAssign.Error()), "already has this role") && !strings.Contains(strings.ToLower(errAssign.Error()), "unique constraint") {
					commonLogger.Warn(ctx, "ADSyncRoles: Failed to assign role", "role_id", roleID, "user_id", localUser.ID, "error", errAssign)
				}
			}
		}
	}
	return nil
}

// Helper Ptr untuk membuat pointer ke time.Time, berguna untuk field opsional
func Ptr[T any](v T) *T {
	return &v
}
