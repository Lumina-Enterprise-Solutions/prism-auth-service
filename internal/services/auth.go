// File: prism-auth-service/internal/services/auth.go
package services

import (
	"crypto/tls" // <-- [TAMBAHKAN]
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/Lumina-Enterprise-Solutions/prism-auth-service/internal/models"
	"github.com/Lumina-Enterprise-Solutions/prism-auth-service/internal/repository"
	"github.com/Lumina-Enterprise-Solutions/prism-common-libs/pkg/cache"               // <-- [TAMBAHKAN]
	commonConfig "github.com/Lumina-Enterprise-Solutions/prism-common-libs/pkg/config" // Untuk akses ke cfg.LDAP
	commonLogger "github.com/Lumina-Enterprise-Solutions/prism-common-libs/pkg/logger" // <-- [TAMBAHKAN]
	commonModels "github.com/Lumina-Enterprise-Solutions/prism-common-libs/pkg/models"
)

type AuthService struct {
	userRepo    *repository.UserRepository
	roleRepo    *repository.RoleRepository      // Dibutuhkan untuk JIT provisioning role
	mappingRepo *repository.ADMappingRepository // Dibutuhkan untuk JIT provisioning role
	jwtService  *JWTService
	redisClient *cache.RedisClient
	appConfig   *commonConfig.Config // Untuk akses ke cfg.LDAP
}

// [MODIFIKASI] NewAuthService sekarang membutuhkan lebih banyak dependensi
func NewAuthService(
	userRepo *repository.UserRepository,
	roleRepo *repository.RoleRepository,
	mappingRepo *repository.ADMappingRepository,
	jwtService *JWTService,
	redisClient *cache.RedisClient,
	appConfig *commonConfig.Config, // Suntikkan config
) *AuthService {
	return &AuthService{
		userRepo:    userRepo,
		roleRepo:    roleRepo,
		mappingRepo: mappingRepo,
		jwtService:  jwtService,
		redisClient: redisClient,
		appConfig:   appConfig,
	}
}

// [MODIFIKASI TOTAL] Login sekarang akan mencoba autentikasi ke AD
func (s *AuthService) Login(req *models.LoginRequest) (*models.LoginResponse, error) {
	// Di dunia nyata, kita akan punya logika untuk memilih metode auth (local vs AD).
	// Untuk sekarang, kita utamakan AD jika dikonfigurasi.
	useADAuth := s.appConfig.LDAP.Host != ""

	if useADAuth {
		return s.loginViaAD(req)
	}
	return s.loginLocal(req)
}

// [BARU] Logika login untuk user lokal (non-AD)
func (s *AuthService) loginLocal(req *models.LoginRequest) (*models.LoginResponse, error) {
	user, err := s.userRepo.GetByEmail(req.Email, req.TenantID)
	if err != nil {
		return nil, fmt.Errorf("database error: %w", err)
	}
	if user == nil || user.IsADManaged {
		return nil, errors.New("invalid credentials or user is AD-managed")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		return nil, errors.New("invalid credentials")
	}

	if user.Status != "active" {
		return nil, errors.New("user account is not active")
	}

	roleNames := make([]string, len(user.Roles))
	for i, role := range user.Roles {
		roleNames[i] = role.Name
	}

	accessToken, refreshToken, expiresAt, err := s.jwtService.GenerateTokens(
		user.ID.String(), user.Email, user.TenantID, roleNames,
	)
	if err != nil {
		return nil, fmt.Errorf("could not generate tokens: %w", err)
	}

	return &models.LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    expiresAt,
		User:         models.ToUserInfo(user),
	}, nil
}

// [BARU] Logika login untuk user AD
func (s *AuthService) loginViaAD(req *models.LoginRequest) (*models.LoginResponse, error) {
	cfgLDAP := s.appConfig.LDAP

	// OpenLDAP simulator Anda menggunakan 'uid' sebagai username untuk login, bukan email.
	// Kita akan coba cari user di LDAP berdasarkan email dulu untuk mendapatkan uid-nya.
	// Di AD asli, seringkali bisa login langsung dengan UPN (UserPrincipalName) yang formatnya seperti email.
	// Konfigurasi Anda di vault.json: "ldap_ad_attribute_upn":"uid"
	// dan "ldap_ad_attribute_email":"mail"
	// Jadi, `req.Email` dari Postman (misal: authadmin@erp.prism.local) akan dicari di field 'mail'.

	l, err := s.ldapConnect(cfgLDAP)
	if err != nil {
		commonLogger.Errorf("LDAP connection failed: %v", err)
		return nil, errors.New("authentication provider unavailable")
	}
	defer l.Close()

	// 1. Bind dengan service account untuk mencari user DN
	err = l.Bind(cfgLDAP.BindDN, cfgLDAP.BindPassword)
	if err != nil {
		commonLogger.Errorf("LDAP bind with service account failed: %v", err)
		return nil, errors.New("authentication provider misconfigured")
	}
	var searchFilter string
	if strings.Contains(req.Email, "@") {
		// Jika input terlihat seperti email, cari di atribut email
		searchFilter = fmt.Sprintf("(%s=%s)", cfgLDAP.ADAttributeEmail, ldap.EscapeFilter(req.Email))
	} else {
		// Jika tidak, asumsikan itu adalah UID/sAMAccountName
		searchFilter = fmt.Sprintf("(%s=%s)", cfgLDAP.ADAttributeUPN, ldap.EscapeFilter(req.Email))
	}
	searchRequest := ldap.NewSearchRequest(
		cfgLDAP.UserBaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 1, 0, false,
		searchFilter,
		[]string{"dn"}, // Kita hanya butuh DN-nya untuk bind
		nil,
	)
	sr, err := l.Search(searchRequest)
	if err != nil || len(sr.Entries) == 0 {
		commonLogger.Warnf("LDAP user with email '%s' not found", req.Email)
		return nil, errors.New("invalid AD credentials")
	}
	userDN := sr.Entries[0].DN

	// 3. Coba Bind dengan DN user dan password yang diberikan untuk autentikasi
	err = l.Bind(userDN, req.Password)
	if err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			commonLogger.Warnf("LDAP bind failed for user DN %s: Invalid Credentials", userDN)
			return nil, errors.New("invalid AD credentials")
		}
		commonLogger.Errorf("LDAP bind failed for user DN %s: %v", userDN, err)
		return nil, errors.New("AD authentication failed")
	}
	commonLogger.Infof("LDAP bind successful for user DN: %s", userDN)

	// 4. Autentikasi AD berhasil. Sekarang ambil detail user untuk JIT Provisioning.
	// (Kita sudah terikat sebagai service account, jadi bisa langsung search lagi)
	err = l.Bind(cfgLDAP.BindDN, cfgLDAP.BindPassword) // Re-bind dengan service account
	if err != nil {                                    /* ... handle error ... */
		return nil, errors.New("auth provider internal error")
	}

	attributesToFetch := []string{
		cfgLDAP.ADAttributeUPN,
		cfgLDAP.ADAttributeObjectGUID,
		cfgLDAP.ADAttributeEmail,
		cfgLDAP.ADAttributeFirstName,
		cfgLDAP.ADAttributeLastName,
		cfgLDAP.ADAttributeMemberOf,
	}

	searchRequest = ldap.NewSearchRequest(
		cfgLDAP.UserBaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 1, 0, false,
		searchFilter, // Gunakan filter yang sama
		attributesToFetch,
		nil,
	)
	sr, err = l.Search(searchRequest)
	if err != nil || len(sr.Entries) == 0 {
		commonLogger.Errorf("AD user '%s' authenticated but could not be retrieved for JIT sync.", req.Email)
		return nil, errors.New("failed to retrieve AD user details post-auth")
	}
	adEntry := sr.Entries[0]

	// Di simulator OpenLDAP, objectGUID adalah 'entryUUID' dan berupa string.
	// Di AD asli, ini binary dan perlu konversi. Kita buat agar kompatibel.
	var adObjectGUID string
	if cfgLDAP.ADAttributeObjectGUID == "entryUUID" {
		adObjectGUID = adEntry.GetAttributeValue(cfgLDAP.ADAttributeObjectGUID)
	} else {
		adObjectGUIDRaw := adEntry.GetRawAttributeValue(cfgLDAP.ADAttributeObjectGUID)
		adObjectGUID = s.convertADObjectGUIDToString(adObjectGUIDRaw)
	}

	adUPN := adEntry.GetAttributeValue(cfgLDAP.ADAttributeUPN)
	adEmail := adEntry.GetAttributeValue(cfgLDAP.ADAttributeEmail)
	adFirstName := adEntry.GetAttributeValue(cfgLDAP.ADAttributeFirstName)
	adLastName := adEntry.GetAttributeValue(cfgLDAP.ADAttributeLastName)
	adMemberOf := adEntry.GetAttributeValues(cfgLDAP.ADAttributeMemberOf)

	if adObjectGUID == "" {
		commonLogger.Errorf("Essential AD attribute (ObjectGUID/entryUUID) missing for user %s", req.Email)
		return nil, errors.New("incomplete AD user profile")
	}

	// 5. Cari atau buat user di DB lokal (JIT Provisioning)
	tenantID := req.TenantID
	if tenantID == "" {
		tenantID = "default"
	}

	localUser, err := s.userRepo.GetByADObjectID(adObjectGUID, tenantID)
	if err != nil {
		return nil, errors.New("database error during login")
	}

	now := time.Now()
	if localUser == nil { // JIT Provisioning
		commonLogger.Infof("JIT Provisioning: Creating new local user for AD user %s in tenant %s", adUPN, tenantID)
		newUser := &commonModels.User{
			TenantID:            tenantID,
			Email:               adEmail,
			FirstName:           adFirstName,
			LastName:            adLastName,
			Status:              "active",
			ADUserPrincipalName: adUPN,
			ADObjectID:          adObjectGUID,
			IsADManaged:         true,
			LastADSync:          &now,
		}
		if err = s.userRepo.Create(newUser, tenantID); err != nil {
			return nil, errors.New("failed to provision local user account")
		}
		localUser = newUser
	} else { // Update user yang ada
		localUser.FirstName = adFirstName
		localUser.LastName = adLastName
		localUser.Email = adEmail
		localUser.ADUserPrincipalName = adUPN
		localUser.Status = "active"
		localUser.IsADManaged = true
		localUser.LastADSync = &now
		if errUpdate := s.userRepo.Update(localUser, tenantID); errUpdate != nil {
			commonLogger.Warnf("Failed to update local user %s info from AD: %v", adUPN, errUpdate)
		}
	}

	// 6. Sinkronisasi Role berdasarkan keanggotaan grup AD
	if errSyncRoles := s.syncUserRolesFromADGroups(localUser, adMemberOf, tenantID); errSyncRoles != nil {
		commonLogger.Warnf("Failed to sync roles during login for user %s: %v.", adUPN, errSyncRoles)
	}

	// 7. Generate JWT
	reloadedUser, err := s.userRepo.GetByID(localUser.ID, tenantID)
	if err != nil || reloadedUser == nil {
		return nil, errors.New("failed to finalize user session")
	}

	if reloadedUser.Status != "active" {
		return nil, errors.New("local user account is not active")
	}

	roleNames := make([]string, len(reloadedUser.Roles))
	for i, role := range reloadedUser.Roles {
		roleNames[i] = role.Name
	}

	accessToken, refreshToken, expiresAt, err := s.jwtService.GenerateTokens(
		reloadedUser.ID.String(), reloadedUser.Email, tenantID, roleNames,
	)
	if err != nil {
		return nil, fmt.Errorf("could not generate tokens: %w", err)
	}

	return &models.LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    expiresAt,
		User:         models.ToUserInfo(reloadedUser),
	}, nil
}

// [MODIFIKASI] Register sekarang harus memastikan user tidak bentrok dengan user AD
func (s *AuthService) Register(req *models.RegisterRequest) (*commonModels.User, error) {
	existingUser, err := s.userRepo.GetByEmail(req.Email, req.TenantID)
	if err != nil {
		return nil, fmt.Errorf("error checking existing user: %w", err)
	}
	if existingUser != nil {
		return nil, errors.New("user with this email already exists")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	user := &commonModels.User{
		Email:        req.Email,
		PasswordHash: string(hashedPassword),
		FirstName:    req.FirstName,
		LastName:     req.LastName,
		Status:       "active",
		TenantID:     req.TenantID,
		IsADManaged:  false, // User lokal
	}

	if err := s.userRepo.Create(user, req.TenantID); err != nil {
		return nil, err
	}
	commonLogger.Infof("Local user registered: %s for tenant %s", user.Email, user.TenantID)

	return user, nil
}

// ... (sisanya bisa sama, tapi kita tambahkan helper LDAP)

// [BARU] Helper untuk koneksi LDAP
func (s *AuthService) ldapConnect(cfgLDAP commonConfig.LDAPConfig) (*ldap.Conn, error) {
	ldapURL := fmt.Sprintf("ldap://%s:%d", cfgLDAP.Host, cfgLDAP.Port)
	var l *ldap.Conn
	var err error

	if cfgLDAP.UseTLS {
		ldapURL = fmt.Sprintf("ldaps://%s:%d", cfgLDAP.Host, cfgLDAP.Port)
		tlsConfig := &tls.Config{InsecureSkipVerify: true} // BAHAYA: Hanya untuk dev!
		l, err = ldap.DialURL(ldapURL, ldap.DialWithTLSConfig(tlsConfig))
	} else {
		l, err = ldap.DialURL(ldapURL)
	}

	if err != nil {
		return nil, err
	}
	return l, nil
}

// [BARU] Helper untuk konversi ObjectGUID AD (byte slice) ke string UUID standar
func (s *AuthService) convertADObjectGUIDToString(guidBytes []byte) string {
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

// [BARU] syncUserRolesFromADGroups menyinkronkan role lokal user berdasarkan keanggotaan grup AD dan mapping.
func (s *AuthService) syncUserRolesFromADGroups(localUser *commonModels.User, adGroupDNs []string, tenantID string) error {
	if !localUser.IsADManaged {
		return nil
	}

	var adGroupSimpleNames []string
	for _, dn := range adGroupDNs {
		// Contoh DN: cn=ERP_Admins,ou=Groups,dc=erp,dc=prism,dc=local -> kita mau "ERP_Admins"
		if parts := strings.Split(dn, ","); len(parts) > 0 {
			if cnParts := strings.Split(parts[0], "="); len(cnParts) == 2 {
				adGroupSimpleNames = append(adGroupSimpleNames, cnParts[1])
			}
		}
	}
	if len(adGroupSimpleNames) == 0 {
		return nil
	}

	// 1. Dapatkan mapping AD Group -> Role Sistem
	mappings, err := s.mappingRepo.GetMappingsByADGroupNames(tenantID, adGroupSimpleNames)
	if err != nil {
		return fmt.Errorf("error fetching AD group to role mappings: %w", err)
	}

	targetRoleIDsFromAD := make(map[uuid.UUID]bool)
	for _, m := range mappings {
		targetRoleIDsFromAD[m.RoleID] = true
	}

	// 2. Dapatkan role lokal user saat ini
	currentUserRoles, err := s.roleRepo.GetUserRoles(localUser.ID, tenantID)
	if err != nil {
		return fmt.Errorf("error fetching current user roles: %w", err)
	}
	currentRoleIDsMap := make(map[uuid.UUID]bool)
	for _, r := range currentUserRoles {
		currentRoleIDsMap[r.ID] = true
	}

	// 3. Revoke role yang tidak lagi dimiliki via AD
	for _, currentRole := range currentUserRoles {
		if _, shouldHaveRole := targetRoleIDsFromAD[currentRole.ID]; !shouldHaveRole {
			// vvvvvvvvvv FIX vvvvvvvvvvvv
			s.roleRepo.RevokeRoleFromUser(localUser, currentRole.ID, tenantID)
			// ^^^^^^^^^^^^ FIX ^^^^^^^^^^^^
		}
	}

	for roleID := range targetRoleIDsFromAD {
		if _, alreadyHasRole := currentRoleIDsMap[roleID]; !alreadyHasRole {
			// vvvvvvvvvv FIX vvvvvvvvvvvv
			s.roleRepo.AssignRoleToUser(localUser, roleID, tenantID)
			// ^^^^^^^^^^^^ FIX ^^^^^^^^^^^^
		}
	}
	return nil
}

func (s *AuthService) RefreshToken(req *models.RefreshTokenRequest) (*models.LoginResponse, error) {
	// 1. Validasi token (format, signature, expiry)
	oldClaims, err := s.jwtService.ValidateToken(req.RefreshToken)
	if err != nil {
		return nil, errors.New("invalid or expired refresh token")
	}

	// 2. Cek apakah JTI lama ada di Redis (allow-list)
	oldJTI := oldClaims.ID
	expectedUserID, isValidJTI, err := s.jwtService.ValidateRefreshTokenJTI(oldJTI)
	if err != nil {
		return nil, errors.New("error validating refresh token state")
	}
	if !isValidJTI {
		// SECURITY: Ini bisa jadi indikasi token reuse. Cabut semua token milik user ini.
		commonLogger.Warnf("Refresh token reuse attempt or token already revoked. JTI: %s", oldJTI)
		return nil, errors.New("refresh token has been revoked or already used")
	}

	// Pastikan UserID dari JTI di Redis cocok dengan UserID di claims token
	if oldClaims.Subject != expectedUserID {
		_ = s.jwtService.RevokeRefreshTokenJTI(oldJTI) // Hapus JTI yang mencurigakan
		return nil, errors.New("refresh token mismatch")
	}

	// 3. Jika valid, *segera* cabut JTI lama dari Redis untuk mencegah reuse (ROTATION)
	if err = s.jwtService.RevokeRefreshTokenJTI(oldJTI); err != nil {
		return nil, errors.New("error rotating refresh token")
	}

	// 4. Dapatkan data user terbaru dari DB
	userID, _ := uuid.Parse(oldClaims.UserID)
	user, err := s.userRepo.GetByID(userID, oldClaims.TenantID)
	if err != nil || user == nil || user.Status != "active" {
		return nil, errors.New("user not found or not active")
	}

	// 5. Generate token baru (access dan refresh baru). JTI baru otomatis disimpan.
	roleNames := make([]string, len(user.Roles))
	for i, r := range user.Roles {
		roleNames[i] = r.Name
	}

	newAccessToken, newRefreshToken, newExpiresAt, err := s.jwtService.GenerateTokens(
		user.ID.String(), user.Email, user.TenantID, roleNames,
	)
	if err != nil {
		return nil, fmt.Errorf("could not generate new tokens: %w", err)
	}

	return &models.LoginResponse{
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
		ExpiresAt:    newExpiresAt,
		User:         models.ToUserInfo(user),
	}, nil
}

// [BARU] Logout service method
func (s *AuthService) Logout(refreshTokenString string) error {
	claims, err := s.jwtService.ValidateToken(refreshTokenString)
	if err != nil {
		// Jika token sudah expired/invalid, JTI-nya mungkin sudah tidak ada. Anggap sukses.
		return nil
	}

	jtiToRevoke := claims.ID
	if jtiToRevoke == "" {
		return errors.New("refresh token for logout is missing JTI")
	}

	// Cabut JTI menggunakan JWTService
	return s.jwtService.RevokeRefreshTokenJTI(jtiToRevoke)
}

func (s *AuthService) ChangePassword(userID uuid.UUID, req *models.ChangePasswordRequest, tenantID string) error {
	user, err := s.userRepo.GetByID(userID, tenantID)
	if err != nil {
		return err
	}
	if user == nil {
		return errors.New("user not found")
	}

	// Verify current password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.CurrentPassword)); err != nil {
		return errors.New("invalid current password")
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	return s.userRepo.UpdatePassword(userID, string(hashedPassword), tenantID)
}

func (s *AuthService) ForgotPassword(req *models.ForgotPasswordRequest) error {
	// Implementation would typically:
	// 1. Check if user exists
	// 2. Generate reset token
	// 3. Store token in cache/database
	// 4. Send email with reset link

	user, err := s.userRepo.GetByEmail(req.Email, req.TenantID)
	if err != nil {
		return err
	}
	if user == nil {
		// Don't reveal if user exists or not
		return nil
	}

	// TODO: Implement email sending logic
	fmt.Printf("Password reset requested for user: %s\n", user.Email)

	return nil
}

func (s *AuthService) ResetPassword(req *models.ResetPasswordRequest) error {
	// Implementation would typically:
	// 1. Validate reset token
	// 2. Get user from token
	// 3. Update password
	// 4. Invalidate token

	// TODO: Implement reset password logic
	fmt.Printf("Password reset for token: %s\n", req.Token)

	return nil
}
