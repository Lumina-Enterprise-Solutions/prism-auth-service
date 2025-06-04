package services

import (
	"errors"
	"fmt"

	// <-- [TAMBAHKAN]
	"golang.org/x/crypto/bcrypt"

	"github.com/Lumina-Enterprise-Solutions/prism-auth-service/internal/models"
	"github.com/Lumina-Enterprise-Solutions/prism-auth-service/internal/repository"
	commonLogger "github.com/Lumina-Enterprise-Solutions/prism-common-libs/pkg/logger"
	commonModels "github.com/Lumina-Enterprise-Solutions/prism-common-libs/pkg/models"
	"github.com/google/uuid"
)

type UserService struct {
	userRepo   *repository.UserRepository
	tenantRepo *repository.TenantRepository // Mungkin tidak diperlukan di sini lagi jika semua operasi tenant-scoped
	roleRepo   *repository.RoleRepository   // <-- [TAMBAHKAN]
}

// [MODIFIKASI] Konstruktor
func NewUserService(userRepo *repository.UserRepository, tenantRepo *repository.TenantRepository, roleRepo *repository.RoleRepository) *UserService {
	return &UserService{
		userRepo:   userRepo,
		tenantRepo: tenantRepo,
		roleRepo:   roleRepo, // <-- [TAMBAHKAN]
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
	existingUser, err := s.userRepo.GetByEmail(req.Email, tenantID)
	if err != nil {
		return nil, err
	}
	if existingUser != nil {
		return nil, errors.New("user already exists with this email")
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
		Status:       req.Status,
	}
	if user.Status == "" {
		user.Status = "active"
	}

	if err := s.userRepo.Create(user, tenantID); err != nil {
		return nil, err
	}

	// Assign roles if provided
	if len(req.Roles) > 0 {
		for _, roleNameOrID := range req.Roles {
			var roleToAssign *commonModels.Role
			// Coba parse sebagai UUID dulu
			roleUUID, errParseUUID := uuid.Parse(roleNameOrID)
			if errParseUUID == nil {
				roleToAssign, err = s.roleRepo.GetByID(roleUUID, tenantID)
			} else {
				// Jika bukan UUID, anggap sebagai nama role
				roleToAssign, err = s.roleRepo.GetByName(roleNameOrID, tenantID)
			}

			if err != nil {
				commonLogger.Warnf("Error fetching role '%s' for user '%s' during creation: %v", roleNameOrID, user.Email, err)
				// Lanjutkan atau gagalkan? Untuk sekarang kita log dan lanjutkan.
				continue
			}
			if roleToAssign == nil {
				commonLogger.Warnf("Role '%s' not found for tenant '%s' during user '%s' creation.", roleNameOrID, tenantID, user.Email)
				continue
			}
			if errAssign := s.roleRepo.AssignRoleToUser(user.ID, roleToAssign.ID, tenantID); errAssign != nil {
				commonLogger.Warnf("Failed to assign role '%s' to user '%s': %v", roleNameOrID, user.Email, errAssign)
				// Lanjutkan atau gagalkan?
			}
		}
		// Muat ulang user dengan roles
		createdUserWithRoles, _ := s.userRepo.GetByID(user.ID, tenantID)
		if createdUserWithRoles != nil {
			user = createdUserWithRoles
		}
	}

	response := models.ToUserResponse(user) // ToUserResponse harus bisa handle user.Roles
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

	if req.FirstName != "" {
		user.FirstName = req.FirstName
	}
	if req.LastName != "" {
		user.LastName = req.LastName
	}
	if req.Status != "" {
		user.Status = req.Status
	}

	if err := s.userRepo.Update(user, tenantID); err != nil {
		return nil, err
	}

	// Handle role updates (jika ada di request, ini bisa jadi lebih kompleks: hapus semua, tambah yang baru)
	// Untuk saat ini, role update dipisah ke endpoint assign/revoke.
	// Jika ingin disertakan di sini, Anda perlu logika untuk:
	// 1. Dapatkan role yang ada sekarang.
	// 2. Bandingkan dengan role di request.
	// 3. Revoke yang tidak ada di request tapi ada di DB.
	// 4. Assign yang ada di request tapi tidak ada di DB.

	// Muat ulang user dengan roles
	updatedUserWithRoles, _ := s.userRepo.GetByID(user.ID, tenantID)
	if updatedUserWithRoles != nil {
		user = updatedUserWithRoles
	}

	response := models.ToUserResponse(user)
	return &response, nil
}

// --- Role Management Methods ---

func (s *UserService) GetRoles(tenantID string) ([]models.RoleResponse, error) {
	roles, err := s.roleRepo.List(tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get roles: %w", err)
	}

	roleResponses := make([]models.RoleResponse, len(roles))
	for i, role := range roles {
		roleResponses[i] = models.ToRoleResponse(&role)
	}
	return roleResponses, nil
}

func (s *UserService) GetRoleByID(roleID uuid.UUID, tenantID string) (*models.RoleResponse, error) {
	role, err := s.roleRepo.GetByID(roleID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get role by ID: %w", err)
	}
	if role == nil {
		return nil, errors.New("role not found")
	}
	response := models.ToRoleResponse(role)
	return &response, nil
}

func (s *UserService) CreateRole(req *models.CreateRoleRequest, tenantID string) (*models.RoleResponse, error) {
	existingRole, err := s.roleRepo.GetByName(req.Name, tenantID)
	if err != nil {
		return nil, fmt.Errorf("error checking existing role: %w", err)
	}
	if existingRole != nil {
		return nil, errors.New("role with this name already exists for the tenant")
	}

	role := &commonModels.Role{
		Name:        req.Name,
		Permissions: commonModels.PermissionMap(req.Permissions), // Konversi tipe
	}

	if err := s.roleRepo.Create(role, tenantID); err != nil {
		return nil, fmt.Errorf("failed to create role: %w", err)
	}

	response := models.ToRoleResponse(role)
	return &response, nil
}

func (s *UserService) UpdateRole(id uuid.UUID, req *models.UpdateRoleRequest, tenantID string) (*models.RoleResponse, error) {
	role, err := s.roleRepo.GetByID(id, tenantID)
	if err != nil {
		return nil, fmt.Errorf("error fetching role for update: %w", err)
	}
	if role == nil {
		return nil, errors.New("role not found")
	}

	if req.Name != "" {
		// Jika nama diubah, cek apakah nama baru sudah ada (kecuali itu nama role ini sendiri)
		if req.Name != role.Name {
			existingRole, err := s.roleRepo.GetByName(req.Name, tenantID)
			if err != nil {
				return nil, fmt.Errorf("error checking new role name: %w", err)
			}
			if existingRole != nil {
				return nil, errors.New("another role with this name already exists for the tenant")
			}
		}
		role.Name = req.Name
	}
	if req.Permissions != nil { // Cek nil karena map bisa jadi tidak diupdate
		role.Permissions = commonModels.PermissionMap(req.Permissions)
	}

	if err := s.roleRepo.Update(role, tenantID); err != nil {
		return nil, fmt.Errorf("failed to update role: %w", err)
	}
	response := models.ToRoleResponse(role)
	return &response, nil
}

func (s *UserService) DeleteRole(id uuid.UUID, tenantID string) error {
	role, err := s.roleRepo.GetByID(id, tenantID)
	if err != nil {
		return fmt.Errorf("error fetching role for deletion: %w", err)
	}
	if role == nil {
		return errors.New("role not found")
	}
	// Logika tambahan: cek jika role ini digunakan oleh user sebelum dihapus?
	// Atau biarkan GORM ON DELETE CASCADE menghapus dari user_roles.
	return s.roleRepo.Delete(id, tenantID)
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

// --- User-Role Assignment Methods ---

func (s *UserService) AssignRoleToUser(userID, roleID uuid.UUID, tenantID string) error {
	// 1. Validasi user ada
	user, err := s.userRepo.GetByID(userID, tenantID)
	if err != nil {
		return fmt.Errorf("error fetching user: %w", err)
	}
	if user == nil {
		return errors.New("user not found")
	}

	// 2. Validasi role ada
	role, err := s.roleRepo.GetByID(roleID, tenantID)
	if err != nil {
		return fmt.Errorf("error fetching role: %w", err)
	}
	if role == nil {
		return errors.New("role not found")
	}

	// 3. Cek apakah user sudah memiliki role ini
	currentUserRoles, err := s.roleRepo.GetUserRoles(userID, tenantID)
	if err != nil {
		return fmt.Errorf("error fetching current user roles: %w", err)
	}
	for _, r := range currentUserRoles {
		if r.ID == roleID {
			return errors.New("user already has this role") // Atau return nil jika tidak masalah
		}
	}

	commonLogger.Infof("Assigning role '%s' (ID: %s) to user '%s' (ID: %s) for tenant '%s'", role.Name, role.ID, user.Email, user.ID, tenantID)
	return s.roleRepo.AssignRoleToUser(userID, roleID, tenantID)
}

func (s *UserService) RevokeRoleFromUser(userID, roleID uuid.UUID, tenantID string) error {
	// Validasi user dan role ada (opsional, repository bisa handle not found)
	user, err := s.userRepo.GetByID(userID, tenantID)
	if err != nil {
		return fmt.Errorf("error fetching user: %w", err)
	}
	if user == nil {
		return errors.New("user not found")
	}
	role, err := s.roleRepo.GetByID(roleID, tenantID)
	if err != nil {
		return fmt.Errorf("error fetching role: %w", err)
	}
	if role == nil {
		return errors.New("role not found")
	}
	commonLogger.Infof("Revoking role '%s' (ID: %s) from user '%s' (ID: %s) for tenant '%s'", role.Name, role.ID, user.Email, user.ID, tenantID)
	return s.roleRepo.RevokeRoleFromUser(userID, roleID, tenantID)
}

func (s *UserService) GetUserRoles(userID uuid.UUID, tenantID string) ([]models.RoleResponse, error) {
	roles, err := s.roleRepo.GetUserRoles(userID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user roles: %w", err)
	}
	roleResponses := make([]models.RoleResponse, len(roles))
	for i, role := range roles {
		roleResponses[i] = models.ToRoleResponse(&role)
	}
	return roleResponses, nil
}
