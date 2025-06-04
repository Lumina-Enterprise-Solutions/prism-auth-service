package services

import (
	// <-- [TAMBAHKAN]
	"errors"
	"fmt"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/Lumina-Enterprise-Solutions/prism-auth-service/internal/models"
	"github.com/Lumina-Enterprise-Solutions/prism-auth-service/internal/repository"
	"github.com/Lumina-Enterprise-Solutions/prism-common-libs/pkg/cache"               // <-- [TAMBAHKAN]
	commonLogger "github.com/Lumina-Enterprise-Solutions/prism-common-libs/pkg/logger" // <-- [TAMBAHKAN]
	commonModels "github.com/Lumina-Enterprise-Solutions/prism-common-libs/pkg/models"
)

type AuthService struct {
	userRepo    *repository.UserRepository
	jwtService  *JWTService
	redisClient *cache.RedisClient // <-- [TAMBAHKAN] (opsional jika JWTService menangani semua interaksi Redis)
}

// [MODIFIKASI] Konstruktor untuk menerima RedisClient (opsional)
func NewAuthService(userRepo *repository.UserRepository, jwtService *JWTService, redisClient *cache.RedisClient) *AuthService {
	return &AuthService{
		userRepo:    userRepo,
		jwtService:  jwtService,
		redisClient: redisClient, // Hanya jika AuthService perlu interaksi Redis langsung
	}
}

// Login: Tidak banyak perubahan, GenerateTokens sudah handle JTI baru
func (s *AuthService) Login(req *models.LoginRequest) (*models.LoginResponse, error) {
	user, err := s.userRepo.GetByEmail(req.Email, req.TenantID)
	if err != nil {
		commonLogger.Warnf("Login attempt: User repo error for email %s, tenant %s: %v", req.Email, req.TenantID, err)
		return nil, errors.New("invalid credentials") // Generic error
	}
	if user == nil {
		commonLogger.Warnf("Login attempt: User not found for email %s, tenant %s", req.Email, req.TenantID)
		return nil, errors.New("invalid credentials")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		commonLogger.Warnf("Login attempt: Invalid password for user %s (ID: %s)", user.Email, user.ID.String())
		return nil, errors.New("invalid credentials")
	}

	if user.Status != "active" {
		commonLogger.Warnf("Login attempt: User %s (ID: %s) is not active (status: %s)", user.Email, user.ID.String(), user.Status)
		return nil, errors.New("user account is not active")
	}

	roleNames := make([]string, len(user.Roles))
	for i, role := range user.Roles {
		roleNames[i] = role.Name
	}

	accessToken, refreshToken, expiresAt, err := s.jwtService.GenerateTokens(
		user.ID.String(),
		user.Email,
		req.TenantID,
		roleNames,
	)
	if err != nil {
		commonLogger.Errorf("Login attempt: Failed to generate tokens for user %s: %v", user.Email, err)
		return nil, fmt.Errorf("could not generate tokens: %w", err)
	}

	commonLogger.Infof("Login successful for user %s (ID: %s), tenant %s", user.Email, user.ID.String(), req.TenantID)
	return &models.LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    expiresAt,
		User: models.UserInfo{
			ID:        user.ID.String(),
			Email:     user.Email,
			FirstName: user.FirstName,
			LastName:  user.LastName,
			Status:    user.Status,
			Roles:     roleNames,
			TenantID:  req.TenantID,
		},
	}, nil
}

// Register: Tidak banyak perubahan, GenerateTokens sudah handle JTI baru
func (s *AuthService) Register(req *models.RegisterRequest) (*models.LoginResponse, error) {
	existingUser, err := s.userRepo.GetByEmail(req.Email, req.TenantID)
	if err != nil {
		// Ini adalah error server, bukan "user sudah ada"
		commonLogger.Errorf("Registration: User repo error for email %s, tenant %s: %v", req.Email, req.TenantID, err)
		return nil, fmt.Errorf("error checking existing user: %w", err)
	}
	if existingUser != nil {
		commonLogger.Warnf("Registration: User already exists with email %s, tenant %s", req.Email, req.TenantID)
		return nil, errors.New("user already exists")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		commonLogger.Errorf("Registration: Failed to hash password for %s: %v", req.Email, err)
		return nil, fmt.Errorf("could not hash password: %w", err)
	}

	user := &commonModels.User{
		Email:        req.Email,
		PasswordHash: string(hashedPassword),
		FirstName:    req.FirstName,
		LastName:     req.LastName,
		Status:       "active", // Default status
	}

	if err := s.userRepo.Create(user, req.TenantID); err != nil {
		commonLogger.Errorf("Registration: Failed to create user %s, tenant %s: %v", req.Email, req.TenantID, err)
		return nil, fmt.Errorf("could not create user: %w", err)
	}
	commonLogger.Infof("Registration successful for user %s (ID: %s), tenant %s", user.Email, user.ID.String(), req.TenantID)

	loginReq := &models.LoginRequest{
		Email:    req.Email,
		Password: req.Password, // Tidak ideal mengirim password plain text lagi, tapi untuk auto-login setelah register
		TenantID: req.TenantID,
	}
	return s.Login(loginReq)
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
