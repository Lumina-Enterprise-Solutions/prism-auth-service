package services

import (
	"errors"
	"fmt"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/Lumina-Enterprise-Solutions/prism-auth-service/internal/models"
	"github.com/Lumina-Enterprise-Solutions/prism-auth-service/internal/repository"
	commonModels "github.com/Lumina-Enterprise-Solutions/prism-common-libs/pkg/models"
)

type AuthService struct {
	userRepo   *repository.UserRepository
	jwtService *JWTService
}

func NewAuthService(userRepo *repository.UserRepository, jwtService *JWTService) *AuthService {
	return &AuthService{
		userRepo:   userRepo,
		jwtService: jwtService,
	}
}

func (s *AuthService) Login(req *models.LoginRequest) (*models.LoginResponse, error) {
	user, err := s.userRepo.GetByEmail(req.Email, req.TenantID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, errors.New("invalid credentials")
	}

	// Check password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		return nil, errors.New("invalid credentials")
	}

	// Check user status
	if user.Status != "active" {
		return nil, errors.New("user account is not active")
	}

	// Extract role names
	roleNames := make([]string, len(user.Roles))
	for i, role := range user.Roles {
		roleNames[i] = role.Name
	}

	// Generate tokens
	accessToken, refreshToken, expiresAt, err := s.jwtService.GenerateTokens(
		user.ID.String(),
		user.Email,
		req.TenantID,
		roleNames,
	)
	if err != nil {
		return nil, err
	}

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

func (s *AuthService) Register(req *models.RegisterRequest) (*models.LoginResponse, error) {
	// Check if user already exists
	existingUser, err := s.userRepo.GetByEmail(req.Email, req.TenantID)
	if err != nil {
		return nil, err
	}
	if existingUser != nil {
		return nil, errors.New("user already exists")
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	// Create user
	user := &commonModels.User{
		Email:        req.Email,
		PasswordHash: string(hashedPassword),
		FirstName:    req.FirstName,
		LastName:     req.LastName,
		Status:       "active",
	}

	if err := s.userRepo.Create(user, req.TenantID); err != nil {
		return nil, err
	}

	// Login the user
	loginReq := &models.LoginRequest{
		Email:    req.Email,
		Password: req.Password,
		TenantID: req.TenantID,
	}

	return s.Login(loginReq)
}

func (s *AuthService) RefreshToken(req *models.RefreshTokenRequest) (*models.LoginResponse, error) {
	claims, err := s.jwtService.ValidateToken(req.RefreshToken)
	if err != nil {
		return nil, errors.New("invalid refresh token")
	}

	// Get user to ensure they still exist and are active
	userID, err := uuid.Parse(claims.UserID)
	if err != nil {
		return nil, errors.New("invalid user ID in token")
	}

	user, err := s.userRepo.GetByID(userID, claims.TenantID)
	if err != nil {
		return nil, err
	}
	if user == nil || user.Status != "active" {
		return nil, errors.New("user not found or not active")
	}

	// Extract role names
	roleNames := make([]string, len(user.Roles))
	for i, role := range user.Roles {
		roleNames[i] = role.Name
	}

	// Generate new tokens
	accessToken, refreshToken, expiresAt, err := s.jwtService.GenerateTokens(
		user.ID.String(),
		user.Email,
		claims.TenantID,
		roleNames,
	)
	if err != nil {
		return nil, err
	}

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
			TenantID:  claims.TenantID,
		},
	}, nil
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
