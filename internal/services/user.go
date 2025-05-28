package services

import (
	"errors"

	"golang.org/x/crypto/bcrypt"

	"github.com/Lumina-Enterprise-Solutions/prism-auth-service/internal/models"
	"github.com/Lumina-Enterprise-Solutions/prism-auth-service/internal/repository"
	commonModels "github.com/Lumina-Enterprise-Solutions/prism-common-libs/pkg/models"
	"github.com/google/uuid"
)

type UserService struct {
	userRepo   *repository.UserRepository
	tenantRepo *repository.TenantRepository
}

func NewUserService(userRepo *repository.UserRepository, tenantRepo *repository.TenantRepository) *UserService {
	return &UserService{
		userRepo:   userRepo,
		tenantRepo: tenantRepo,
	}
}

func (s *UserService) GetUsers(tenantID string, page, limit int) ([]models.UserResponse, int64, error) {
	offset := (page - 1) * limit
	users, total, err := s.userRepo.List(tenantID, offset, limit)
	if err != nil {
		return nil, 0, err
	}

	userResponses := make([]models.UserResponse, len(users))
	for i, user := range users {
		userResponses[i] = models.ToUserResponse(&user)
	}

	return userResponses, total, nil
}

func (s *UserService) GetUser(id uuid.UUID, tenantID string) (*models.UserResponse, error) {
	user, err := s.userRepo.GetByID(id, tenantID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, errors.New("user not found")
	}

	response := models.ToUserResponse(user)
	return &response, nil
}

func (s *UserService) CreateUser(req *models.CreateUserRequest, tenantID string) (*models.UserResponse, error) {
	// Check if user already exists
	existingUser, err := s.userRepo.GetByEmail(req.Email, tenantID)
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
		Status:       req.Status,
	}

	if user.Status == "" {
		user.Status = "active"
	}

	if err := s.userRepo.Create(user, tenantID); err != nil {
		return nil, err
	}

	response := models.ToUserResponse(user)
	return &response, nil
}

func (s *UserService) UpdateUser(id uuid.UUID, req *models.UpdateUserRequest, tenantID string) (*models.UserResponse, error) {
	user, err := s.userRepo.GetByID(id, tenantID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, errors.New("user not found")
	}

	// Update fields
	if req.FirstName != "" {
		user.FirstName = req.FirstName
	}
	if req.LastName != "" {
		user.LastName = req.LastName
	}
	if req.Status != "" {
		user.Status = req.Status
	}

	// TODO: Handle role updates

	if err := s.userRepo.Update(user, tenantID); err != nil {
		return nil, err
	}

	response := models.ToUserResponse(user)
	return &response, nil
}

func (s *UserService) DeleteUser(id uuid.UUID, tenantID string) error {
	user, err := s.userRepo.GetByID(id, tenantID)
	if err != nil {
		return err
	}
	if user == nil {
		return errors.New("user not found")
	}

	return s.userRepo.Delete(id, tenantID)
}

func (s *UserService) UpdateProfile(userID uuid.UUID, req *models.UpdateProfileRequest, tenantID string) (*models.UserResponse, error) {
	user, err := s.userRepo.GetByID(userID, tenantID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, errors.New("user not found")
	}

	// Update profile fields
	if req.FirstName != "" {
		user.FirstName = req.FirstName
	}
	if req.LastName != "" {
		user.LastName = req.LastName
	}

	if err := s.userRepo.Update(user, tenantID); err != nil {
		return nil, err
	}

	response := models.ToUserResponse(user)
	return &response, nil
}

// TODO: Add role management methods
func (s *UserService) GetRoles(tenantID string) ([]models.RoleResponse, error) {
	// Implementation needed
	return []models.RoleResponse{}, nil
}

func (s *UserService) CreateRole(req *models.CreateRoleRequest, tenantID string) (*models.RoleResponse, error) {
	// Implementation needed
	return nil, errors.New("not implemented")
}

func (s *UserService) UpdateRole(id uuid.UUID, req *models.UpdateRoleRequest, tenantID string) (*models.RoleResponse, error) {
	// Implementation needed
	return nil, errors.New("not implemented")
}

func (s *UserService) DeleteRole(id uuid.UUID, tenantID string) error {
	// Implementation needed
	return errors.New("not implemented")
}
