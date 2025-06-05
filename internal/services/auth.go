package services

import (
	// <-- [TAMBAHKAN]
	"crypto/tls"
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

// Login sekarang akan mencoba autentikasi ke AD
func (s *AuthService) Login(req *models.LoginRequest) (*models.LoginResponse, error) {
	cfgLDAP := s.appConfig.LDAP // Akses konfigurasi LDAP
	if cfgLDAP.Host == "" {
		commonLogger.Error("LDAP Host not configured. Cannot perform AD authentication.")
		return nil, errors.New("authentication provider not configured")
	}

	// Input `req.Email` akan kita asumsikan sebagai UserPrincipalName (UPN) atau sAMAccountName
	// Input `req.Password` adalah password AD user
	username := req.Email // Bisa UPN (user@domain.com) atau sAMAccountName (user)
	password := req.Password

	l, err := s.ldapConnect(cfgLDAP)
	if err != nil {
		commonLogger.Errorf("LDAP connection failed: %v", err)
		return nil, errors.New("authentication provider unavailable")
	}
	defer l.Close()

	// 1. Coba Bind dengan kredensial user untuk autentikasi
	// Format UPN (user@domain.com) biasanya bisa langsung digunakan untuk bind.
	// Jika menggunakan sAMAccountName, Anda mungkin perlu mencari DN user dulu.
	// Untuk kesederhanaan, kita asumsikan username adalah UPN atau sesuatu yang bisa di-bind langsung.
	// Beberapa AD memperbolehkan bind dengan UPN.
	commonLogger.Infof("Attempting LDAP bind for user: %s", username)
	err = l.Bind(username, password)
	if err != nil {
		// Periksa error LDAP spesifik jika perlu (e.g., invalid credentials)
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			commonLogger.Warnf("LDAP bind failed for user %s: Invalid Credentials", username)
			return nil, errors.New("invalid AD credentials")
		}
		commonLogger.Errorf("LDAP bind failed for user %s: %v", username, err)
		return nil, errors.New("AD authentication failed")
	}
	commonLogger.Infof("LDAP bind successful for user: %s", username)

	// 2. Autentikasi AD berhasil. Sekarang cari/provision user di DB lokal.
	// Kita perlu mengambil beberapa atribut dari AD seperti UPN, ObjectGUID, nama, email, memberOf.
	// Untuk itu, kita mungkin perlu melakukan bind lagi dengan akun layanan (jika bind user awal tidak punya hak search),
	// atau jika bind user awal sudah cukup, kita bisa langsung search.
	// Untuk sekarang, kita re-bind dengan service account untuk search (praktik umum).
	if cfgLDAP.BindDN != "" && cfgLDAP.BindPassword != "" {
		commonLogger.Debugf("Re-binding to LDAP with service account: %s", cfgLDAP.BindDN)
		err = l.Bind(cfgLDAP.BindDN, cfgLDAP.BindPassword)
		if err != nil {
			commonLogger.Errorf("LDAP re-bind with service account failed: %v", err)
			return nil, errors.New("failed to query user details post-auth")
		}
	} else {
		commonLogger.Debug("LDAP service account not configured for search, continuing with user's bind context (might have limited search rights).")
	}

	// Tentukan filter pencarian. Jika username adalah UPN, filter bisa (userPrincipalName=username)
	// Jika sAMAccountName, filter bisa (sAMAccountName=username)
	// Asumsi username adalah UPN untuk filter
	searchFilter := fmt.Sprintf("(&(%s=%s)(objectClass=user))", cfgLDAP.ADAttributeUPN, ldap.EscapeFilter(username))
	if !strings.Contains(username, "@") { // Jika formatnya seperti sAMAccountName
		searchFilter = fmt.Sprintf("(&(%s=%s)(objectClass=user))", "sAMAccountName", ldap.EscapeFilter(username)) // Ganti "sAMAccountName" jika atributnya beda
	}

	attributesToFetch := []string{
		cfgLDAP.ADAttributeUPN,
		cfgLDAP.ADAttributeObjectGUID, // Penting untuk ID unik
		cfgLDAP.ADAttributeEmail,
		cfgLDAP.ADAttributeFirstName,
		cfgLDAP.ADAttributeLastName,
		cfgLDAP.ADAttributeMemberOf,  // Untuk grup
		"whenCreated", "whenChanged", // Atribut standar AD
	}
	// Hapus atribut kosong dari slice jika tidak dikonfigurasi
	var finalAttributes []string
	for _, attr := range attributesToFetch {
		if attr != "" {
			finalAttributes = append(finalAttributes, attr)
		}
	}
	if len(finalAttributes) == 0 { // Minimal UPN dan ObjectGUID harus ada
		finalAttributes = []string{cfgLDAP.ADAttributeUPN, cfgLDAP.ADAttributeObjectGUID, "cn"} // cn sebagai fallback
	}

	searchRequest := ldap.NewSearchRequest(
		cfgLDAP.UserBaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		searchFilter,
		finalAttributes,
		nil,
	)

	commonLogger.Debugf("Searching AD user with filter: %s, baseDN: %s, attributes: %v", searchFilter, cfgLDAP.UserBaseDN, finalAttributes)
	sr, err := l.Search(searchRequest)
	if err != nil {
		commonLogger.Errorf("LDAP search failed for user %s: %v", username, err)
		return nil, errors.New("failed to retrieve AD user details")
	}

	if len(sr.Entries) == 0 {
		commonLogger.Warnf("AD user %s authenticated but not found via search. This is unusual.", username)
		return nil, errors.New("AD user details not found after auth")
	}
	if len(sr.Entries) > 1 {
		commonLogger.Warnf("Multiple AD entries found for %s. Using the first one.", username)
	}
	adEntry := sr.Entries[0]

	adUPN := adEntry.GetAttributeValue(cfgLDAP.ADAttributeUPN)
	adObjectGUIDRaw := adEntry.GetRawAttributeValue(cfgLDAP.ADAttributeObjectGUID) // Ambil raw bytes untuk GUID
	adObjectGUID := s.convertADObjectGUIDToString(adObjectGUIDRaw)                 // Konversi ke string
	adEmail := adEntry.GetAttributeValue(cfgLDAP.ADAttributeEmail)
	adFirstName := adEntry.GetAttributeValue(cfgLDAP.ADAttributeFirstName)
	adLastName := adEntry.GetAttributeValue(cfgLDAP.ADAttributeLastName)
	adMemberOf := adEntry.GetAttributeValues(cfgLDAP.ADAttributeMemberOf) // Slice of group DNs

	if adUPN == "" || adObjectGUID == "" {
		commonLogger.Errorf("Essential AD attributes (UPN or ObjectGUID) missing for user %s. UPN: '%s', GUID: '%s'", username, adUPN, adObjectGUID)
		return nil, errors.New("incomplete AD user profile from LDAP")
	}

	// 3. Cari atau buat user di DB lokal
	// TenantID untuk user ini diambil dari request login.
	// Ini berarti tenant harus sudah ada di sistem kita.
	// Atau, jika ada logika untuk menentukan tenant dari UPN/grup AD, itu bisa diimplementasikan.
	tenantID := req.TenantID
	if tenantID == "" {
		// Default ke tenant 'default' jika tidak ada di request. Ini mungkin perlu kebijakan khusus.
		commonLogger.Warnf("TenantID not provided in login request for AD user %s, defaulting to 'default'. Consider making TenantID mandatory for AD logins.", adUPN)
		tenantID = "default"
	}

	localUser, err := s.userRepo.GetByADObjectID(adObjectGUID, tenantID) // Perlu method baru di repo
	if err != nil {
		commonLogger.Errorf("Error checking local DB for AD user %s (GUID: %s): %v", adUPN, adObjectGUID, err)
		return nil, errors.New("database error during login")
	}

	now := time.Now()
	if localUser == nil {
		// JIT Provisioning: User AD ada, tapi tidak ada di DB lokal (untuk tenant ini)
		commonLogger.Infof("JIT Provisioning: AD user %s (GUID: %s) not found in local DB for tenant %s. Creating new user.", adUPN, adObjectGUID, tenantID)
		newUser := &commonModels.User{
			TenantID:            tenantID,
			Email:               adEmail, // Atau adUPN jika email AD tidak selalu ada/reliable
			FirstName:           adFirstName,
			LastName:            adLastName,
			Status:              "active", // Default status untuk user baru dari AD
			ADUserPrincipalName: adUPN,
			ADObjectID:          adObjectGUID,
			IsADManaged:         true,
			LastADSync:          &now,
			// PasswordHash kosong karena dikelola AD
		}
		err = s.userRepo.Create(newUser, tenantID) // Create akan set ID, CreatedAt, dll.
		if err != nil {
			commonLogger.Errorf("JIT Provisioning: Failed to create local user for AD user %s: %v", adUPN, err)
			return nil, errors.New("failed to provision local user account")
		}
		localUser = newUser // Gunakan user yang baru dibuat
		commonLogger.Infof("JIT Provisioning: Successfully created local user ID %s for AD user %s", localUser.ID, adUPN)

		// Assign roles berdasarkan keanggotaan grup AD dan mapping
		if errSyncRoles := s.syncUserRolesFromADGroups(localUser, adMemberOf, tenantID); errSyncRoles != nil {
			commonLogger.Warnf("JIT Provisioning: Failed to sync roles for new user %s: %v. User created without initial roles from AD.", adUPN, errSyncRoles)
			// Lanjutkan tanpa role, atau gagalkan? Tergantung kebijakan.
		}

	} else {
		// User lokal sudah ada, update info jika perlu (sinkronisasi mini)
		commonLogger.Infof("AD User %s (GUID: %s, LocalID: %s) found in local DB for tenant %s. Updating.", adUPN, adObjectGUID, localUser.ID, tenantID)
		localUser.FirstName = adFirstName
		localUser.LastName = adLastName
		localUser.Email = adEmail             // atau adUPN
		localUser.ADUserPrincipalName = adUPN // Pastikan UPN juga update jika bisa berubah
		localUser.Status = "active"           // Asumsikan jika bisa login AD, status di sistem kita harus aktif
		localUser.IsADManaged = true
		localUser.LastADSync = &now
		if errUpdate := s.userRepo.Update(localUser, tenantID); errUpdate != nil {
			commonLogger.Warnf("Failed to update local user %s info from AD: %v", adUPN, errUpdate)
			// Lanjutkan saja, login masih bisa berhasil.
		}
		// Update roles berdasarkan keanggotaan grup AD saat ini
		if errSyncRoles := s.syncUserRolesFromADGroups(localUser, adMemberOf, tenantID); errSyncRoles != nil {
			commonLogger.Warnf("Failed to sync roles during login for user %s: %v.", adUPN, errSyncRoles)
		}
	}

	// Muat ulang user dengan roles yang sudah di-preload untuk JWT
	reloadedUser, err := s.userRepo.GetByID(localUser.ID, tenantID)
	if err != nil || reloadedUser == nil {
		commonLogger.Errorf("Failed to reload user %s with roles after AD sync: %v", localUser.ID, err)
		return nil, errors.New("failed to finalize user session")
	}
	localUser = reloadedUser

	// 4. Generate JWT sistem kita
	if localUser.Status != "active" {
		commonLogger.Warnf("Local user account %s (ID: %s) is not active (status: %s) after AD auth.", adUPN, localUser.ID, localUser.Status)
		return nil, errors.New("local user account is not active")
	}

	roleNames := make([]string, len(localUser.Roles))
	for i, role := range localUser.Roles {
		roleNames[i] = role.Name
	}

	accessToken, refreshToken, expiresAt, err := s.jwtService.GenerateTokens(
		localUser.ID.String(),
		localUser.Email, // atau adUPN
		tenantID,
		roleNames,
	)
	if err != nil {
		commonLogger.Errorf("Failed to generate tokens for AD user %s: %v", adUPN, err)
		return nil, fmt.Errorf("could not generate tokens: %w", err)
	}

	commonLogger.Infof("Successfully generated JWT for AD user %s (LocalID: %s) on tenant %s", adUPN, localUser.ID, tenantID)
	return &models.LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    expiresAt,
		User: models.UserInfo{
			ID:        localUser.ID.String(),
			Email:     localUser.Email, // atau adUPN
			FirstName: localUser.FirstName,
			LastName:  localUser.LastName,
			Status:    localUser.Status,
			Roles:     roleNames,
			TenantID:  tenantID,
		},
	}, nil
}

// Register: Perlu dipikirkan ulang. Jika AD adalah source of truth, apakah register lokal masih valid?
// Jika masih ada, pastikan user yang diregister lokal tidak bentrok dengan user AD (misal, email).
// Atau, register lokal menandai IsADManaged = false.
// PasswordHash juga akan relevan untuk user lokal.
func (s *AuthService) Register(req *models.RegisterRequest) (*models.LoginResponse, error) {
	// Cek apakah user dengan email ini sudah ada sebagai user AD (jika email adalah UPN)
	// Ini adalah contoh sederhana, logika sebenarnya bisa lebih kompleks.
	// Untuk sekarang, kita hanya cek user lokal.
	existingUser, err := s.userRepo.GetByEmail(req.Email, req.TenantID) // GetByEmail perlu di-scope per tenant
	if err != nil {
		return nil, fmt.Errorf("error checking existing user: %w", err)
	}
	if existingUser != nil {
		if existingUser.IsADManaged {
			return nil, errors.New("an AD-managed user with this email/UPN already exists. Please login via AD.")
		}
		return nil, errors.New("local user with this email already exists")
	}

	// Hash password lokal
	// hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	// if err != nil {
	// 	return nil, err
	// }
    // Untuk sementara, kita tidak hash password karena login AD belum selesai sepenuhnya dan mungkin bcrypt belum di-import ulang.
    // Jika register lokal masih ada, bagian ini perlu diaktifkan lagi.
    hashedPassword := []byte("$2a$INVALID_HASH_UNTIL_LOCAL_REGISTER_IS_CONFIRMED")


	user := &commonModels.User{
		Email:        req.Email,
		PasswordHash: string(hashedPassword),
		FirstName:    req.FirstName,
		LastName:     req.LastName,
		Status:       "active",
		TenantID:     req.TenantID, // Pastikan tenant ID ada di request atau diambil dari header
		IsADManaged:  false,       // User lokal
	}

	if err := s.userRepo.Create(user, req.TenantID); err != nil {
		return nil, err
	}
	commonLogger.Infof("Local user registered: %s for tenant %s", user.Email, user.TenantID)

	// Login user lokal yang baru diregistrasi (jika masih ingin auto-login)
	// Ini akan menggunakan password hash lokal.
	// Tapi karena kita baru saja mengubah Login untuk AD, ini akan gagal.
	// Untuk sekarang, kita kembalikan error bahwa login setelah register lokal perlu diimplementasikan ulang.
	// return s.Login(...) // Ini akan mencoba AD login
	return nil, errors.New("local registration successful, please login (AD login is primary, local login flow needs review)")
}

func (s *AuthService) RefreshToken(req *models.RefreshTokenRequest) (*models.LoginResponse, error) {
	// 1. Validasi token (format, signature, standard claims seperti expiry)
	oldClaims, err := s.jwtService.ValidateToken(req.RefreshToken)
	if err != nil {
		commonLogger.Warnf("RefreshToken: Invalid refresh token format/signature/expiry: %v", err)
		return nil, errors.New("invalid or expired refresh token")
	}

	// 2. Ekstrak JTI dari refresh token lama (ValidateToken sudah melakukannya via models.Claims)
	oldJTI := oldClaims.ID
	if oldJTI == "" {
		commonLogger.Warn("RefreshToken: Refresh token is missing JTI claim.")
		return nil, errors.New("refresh token is missing JTI")
	}

	// 3. Periksa apakah JTI lama ada di Redis (allow-list)
	//    Fungsi ValidateRefreshTokenJTI akan mengembalikan userID jika valid
	expectedUserID, isValidJTI, err := s.jwtService.ValidateRefreshTokenJTI(oldJTI)
	if err != nil {
		commonLogger.Errorf("RefreshToken: Error validating JTI %s from Redis: %v", oldJTI, err)
		return nil, errors.New("error validating refresh token state")
	}
	if !isValidJTI {
		commonLogger.Warnf("RefreshToken: JTI %s for user ID %s (from claims) not found in Redis or is invalid. Possible reuse or revocation.", oldJTI, oldClaims.UserID)
		// Ini bisa jadi indikasi token reuse attempt atau token sudah direvoke.
		// SECURITY: Anda mungkin ingin melakukan tindakan tambahan di sini, seperti mencabut semua token milik user ini.
		return nil, errors.New("refresh token has been revoked or already used")
	}

	// Pastikan UserID dari JTI di Redis cocok dengan UserID di claims token (jika ada Subject)
	// oldClaims.Subject seharusnya adalah UserID
	if oldClaims.Subject != expectedUserID {
		commonLogger.Warnf("RefreshToken: JTI %s in Redis is for user %s, but token subject is %s. Tampering attempt?", oldJTI, expectedUserID, oldClaims.Subject)
		// Hapus JTI yang mencurigakan ini dari Redis
		_ = s.jwtService.RevokeRefreshTokenJTI(oldJTI)
		return nil, errors.New("refresh token mismatch")
	}

	// 4. Jika valid, *segera* cabut JTI lama dari Redis untuk mencegah reuse (ROTATION)
	err = s.jwtService.RevokeRefreshTokenJTI(oldJTI)
	if err != nil {
		commonLogger.Errorf("RefreshToken: Failed to revoke old JTI %s for user %s: %v", oldJTI, oldClaims.UserID, err)
		// Ini adalah kondisi kritis, karena token baru akan diterbitkan tapi yang lama mungkin masih valid di Redis
		// Anda bisa memilih untuk menggagalkan operasi ini.
		return nil, errors.New("error rotating refresh token")
	}
	commonLogger.Infof("RefreshToken: Successfully revoked old JTI %s for user %s", oldJTI, oldClaims.UserID)

	// Dapatkan user dari DB untuk memastikan masih valid dan mendapatkan role terbaru
	userID, err := uuid.Parse(oldClaims.UserID) // atau oldClaims.Subject
	if err != nil {
		commonLogger.Warnf("RefreshToken: Invalid user ID format in claims (%s): %v", oldClaims.UserID, err)
		return nil, errors.New("invalid user ID in token")
	}

	user, err := s.userRepo.GetByID(userID, oldClaims.TenantID)
	if err != nil {
		commonLogger.Errorf("RefreshToken: User repo error for user ID %s, tenant %s: %v", userID, oldClaims.TenantID, err)
		return nil, fmt.Errorf("error retrieving user: %w", err)
	}
	if user == nil || user.Status != "active" {
		commonLogger.Warnf("RefreshToken: User ID %s, tenant %s not found or not active.", userID, oldClaims.TenantID)
		return nil, errors.New("user not found or not active")
	}

	roleNames := make([]string, len(user.Roles))
	for i, role := range user.Roles {
		roleNames[i] = role.Name
	}

	// 5. Generate token baru (access dan refresh baru).
	//    JWTService.GenerateTokens akan menyimpan JTI baru ke Redis secara otomatis.
	newAccessToken, newRefreshToken, newExpiresAt, err := s.jwtService.GenerateTokens(
		user.ID.String(),
		user.Email,
		oldClaims.TenantID, // Gunakan tenantID dari refresh token lama
		roleNames,
	)
	if err != nil {
		commonLogger.Errorf("RefreshToken: Failed to generate new tokens for user %s: %v", user.Email, err)
		return nil, fmt.Errorf("could not generate new tokens: %w", err)
	}
	commonLogger.Infof("RefreshToken: Successfully generated new tokens for user %s (ID: %s)", user.Email, user.ID.String())

	return &models.LoginResponse{
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
		ExpiresAt:    newExpiresAt,
		User: models.UserInfo{
			ID:        user.ID.String(),
			Email:     user.Email,
			FirstName: user.FirstName,
			LastName:  user.LastName,
			Status:    user.Status,
			Roles:     roleNames,
			TenantID:  oldClaims.TenantID,
		},
	}, nil
}

// [TAMBAHKAN] Logout service method
func (s *AuthService) Logout(refreshTokenString string) error {
	// 1. Validasi token string (format, signature, standard claims seperti expiry)
	// Kita tidak terlalu peduli dengan expiry di sini karena kita hanya ingin JTI-nya
	// tapi parsing akan tetap gagal jika sudah expired.
	claims, err := s.jwtService.ValidateToken(refreshTokenString)
	if err != nil {
		// Jika token sudah expired atau invalid, JTI nya mungkin sudah tidak ada di Redis.
		// Atau jika formatnya salah, kita tidak bisa dapat JTI.
		commonLogger.Warnf("Logout: Attempted to logout with invalid or expired refresh token: %v", err)
		// Anda bisa mengembalikan error atau anggap sukses karena tokennya sudah tidak berguna.
		// Mengembalikan nil lebih sederhana untuk client.
		return nil // Atau errors.New("invalid refresh token for logout")
	}

	// 2. Ekstrak JTI. models.Claims.ID adalah JTI.
	jtiToRevoke := claims.ID
	if jtiToRevoke == "" {
		commonLogger.Warn("Logout: Refresh token for logout is missing JTI claim.")
		return errors.New("refresh token for logout is missing JTI")
	}

	// 3. Cabut JTI menggunakan JWTService
	err = s.jwtService.RevokeRefreshTokenJTI(jtiToRevoke)
	if err != nil {
		commonLogger.Errorf("Logout: Failed to revoke JTI %s for user %s: %v", jtiToRevoke, claims.UserID, err)
		return fmt.Errorf("could not revoke refresh token: %w", err)
	}

	commonLogger.Infof("Logout: Successfully revoked JTI %s for user %s (ID: %s)", jtiToRevoke, claims.Email, claims.UserID)
	return nil
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

// Helper untuk koneksi LDAP
func (s *AuthService) ldapConnect(cfgLDAP commonConfig.LDAPConfig) (*ldap.Conn, error) {
	ldapURL := fmt.Sprintf("ldap://%s:%d", cfgLDAP.Host, cfgLDAP.Port)
	var l *ldap.Conn
	var err error

	if cfgLDAP.UseTLS { // Ini untuk LDAPS (LDAP over SSL/TLS pada port 636)
		ldapURL = fmt.Sprintf("ldaps://%s:%d", cfgLDAP.Host, cfgLDAP.Port)
		// Perlu konfigurasi TLS, termasuk SkipVerify jika sertifikat AD self-signed (TIDAK AMAN untuk produksi)
		tlsConfig := &tls.Config{InsecureSkipVerify: true} // BAHAYA: Hanya untuk dev!
		l, err = ldap.DialURL(ldapURL, ldap.DialWithTLSConfig(tlsConfig))
	} else {
		l, err = ldap.DialURL(ldapURL)
	}

	if err != nil {
		return nil, err
	}

	// Jika bukan LDAPS, dan port 389, AD biasanya mendukung StartTLS setelah koneksi awal
	// Ini tidak diimplementasikan di sini untuk kesederhanaan, tapi bisa ditambahkan.
	// if !cfgLDAP.UseTLS && cfgLDAP.Port == 389 {
	// err = l.StartTLS(&tls.Config{ServerName: cfgLDAP.Host, InsecureSkipVerify: true})
	// if err != nil {
	// l.Close()
	// return nil, fmt.Errorf("LDAP StartTLS failed: %w", err)
	//    }
	// }
	return l, nil
}

// Helper untuk konversi ObjectGUID AD (byte slice) ke string UUID standar
func (s *AuthService) convertADObjectGUIDToString(guidBytes []byte) string {
	if len(guidBytes) != 16 {
		return "" // Atau uuid.Nil.String() jika ingin default UUID
	}
	// Format UUID standar: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
	// Byte order ObjectGUID AD sedikit berbeda untuk beberapa bagian pertama.
	// https://ldapwiki.com/wiki/ObjectGUID
	return fmt.Sprintf("%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		guidBytes[3], guidBytes[2], guidBytes[1], guidBytes[0], // byte 0-3 dibalik
		guidBytes[5], guidBytes[4], // byte 4-5 dibalik
		guidBytes[7], guidBytes[6], // byte 6-7 dibalik
		guidBytes[8], guidBytes[9], // byte 8-9 normal
		guidBytes[10], guidBytes[11], guidBytes[12], guidBytes[13], guidBytes[14], guidBytes[15]) // byte 10-15 normal
}

// syncUserRolesFromADGroups menyinkronkan role lokal user berdasarkan keanggotaan grup AD dan mapping.
func (s *AuthService) syncUserRolesFromADGroups(localUser *commonModels.User, adGroupDNs []string, tenantID string) error {
	if !localUser.IsADManaged { // Hanya untuk user AD
		return nil
	}
	if len(adGroupDNs) == 0 {
		commonLogger.Infof("User %s (ID: %s) is not a member of any AD groups relevant for mapping.", localUser.ADUserPrincipalName, localUser.ID)
		// Hapus semua role yang mungkin berasal dari AD jika user tidak lagi di grup mana pun
		// Ini perlu logika hati-hati agar tidak menghapus role yang di-assign manual (jika diizinkan)
	}

	// Ekstrak nama grup dari DN (Distinguished Name)
	var adGroupSimpleNames []string
	for _, dn := range adGroupDNs {
		// Contoh DN: CN=ERP_Admins,OU=Groups,DC=example,DC=com
		// Kita ingin "ERP_Admins"
		// Ini parsing sederhana, mungkin perlu lebih robust
		if parts := strings.Split(dn, ","); len(parts) > 0 {
			if cnParts := strings.Split(parts[0], "="); len(cnParts) == 2 {
				adGroupSimpleNames = append(adGroupSimpleNames, cnParts[1])
			}
		}
	}
	if len(adGroupSimpleNames) == 0 {
		commonLogger.Debugf("No simple AD group names extracted for user %s.", localUser.ADUserPrincipalName)
		// Jika tidak ada grup AD, maka tidak ada role dari AD yang perlu di-assign.
		// Pertimbangkan untuk menghapus semua role yang berasal dari AD jika implementasinya seperti itu.
		// Untuk saat ini, kita tidak melakukan apa-apa jika tidak ada grup.
		return nil
	}

	// 1. Dapatkan mapping AD Group -> Role Sistem untuk tenant ini dan grup-grup tersebut
	mappings, err := s.mappingRepo.GetMappingsByADGroupNames(tenantID, adGroupSimpleNames)
	if err != nil {
		return fmt.Errorf("error fetching AD group to role mappings: %w", err)
	}

	targetRoleIDsFromAD := make(map[uuid.UUID]bool)
	for _, m := range mappings {
		targetRoleIDsFromAD[m.RoleID] = true
		commonLogger.Debugf("User %s, AD Group '%s' maps to System Role ID '%s' for tenant '%s'", localUser.ADUserPrincipalName, m.ADGroupName, m.RoleID, tenantID)
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
		// Hanya revoke role yang mungkin berasal dari AD.
		// Perlu cara untuk membedakan role yang di-assign manual vs dari AD.
		// Untuk sekarang, kita asumsikan semua role user AD dikelola oleh AD group.
		// Ini adalah penyederhanaan besar.
		if _, shouldHaveRole := targetRoleIDsFromAD[currentRole.ID]; !shouldHaveRole {
			commonLogger.Infof("Revoking role '%s' (ID: %s) from user %s as it's no longer mapped from their AD groups.", currentRole.Name, currentRole.ID, localUser.ADUserPrincipalName)
			if errRevoke := s.roleRepo.RevokeRoleFromUser(localUser.ID, currentRole.ID, tenantID); errRevoke != nil {
				commonLogger.Warnf("Failed to revoke role %s from user %s: %v", currentRole.Name, localUser.ADUserPrincipalName, errRevoke)
			}
		}
	}

	// 4. Assign role baru dari AD
	for roleID := range targetRoleIDsFromAD {
		if _, alreadyHasRole := currentRoleIDsMap[roleID]; !alreadyHasRole {
			// Dapatkan nama role untuk logging
			roleDetails, _ := s.roleRepo.GetByID(roleID, tenantID)
			roleNameForLog := roleID.String()
			if roleDetails != nil {
				roleNameForLog = roleDetails.Name
			}
			commonLogger.Infof("Assigning role '%s' (ID: %s) to user %s based on AD group mapping.", roleNameForLog, roleID, localUser.ADUserPrincipalName)
			if errAssign := s.roleRepo.AssignRoleToUser(localUser.ID, roleID, tenantID); errAssign != nil {
				// Periksa apakah error karena "user already has this role" (jika repo Anda mengembalikan error ini)
				// Dalam kasus itu, bukan error fatal.
				if !strings.Contains(errAssign.Error(), "already has this role") { // Contoh pemeriksaan error
					commonLogger.Warnf("Failed to assign role ID %s to user %s: %v", roleID, localUser.ADUserPrincipalName, errAssign)
				}
			}
		}
	}
	return nil
}
