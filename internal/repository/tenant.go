package repository

import (
	"errors"
	"fmt"
	"strings"

	"github.com/Lumina-Enterprise-Solutions/prism-common-libs/pkg/database"
	"github.com/Lumina-Enterprise-Solutions/prism-common-libs/pkg/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type TenantRepository struct {
	db *database.PostgresDB
}

func NewTenantRepository(db *database.PostgresDB) *TenantRepository {
	return &TenantRepository{db: db}
}

func (r *TenantRepository) GetByID(id uuid.UUID) (*models.Tenant, error) {
	var tenant models.Tenant
	err := r.db.DB.First(&tenant, "id = ?", id).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &tenant, nil
}

func (r *TenantRepository) GetBySlug(slug string) (*models.Tenant, error) {
	var tenant models.Tenant
	err := r.db.DB.First(&tenant, "slug = ?", slug).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &tenant, nil
}

func (r *TenantRepository) Create(tenant *models.Tenant) error {
	// Sanitize tenant slug for schema name
	safeSchemaName := strings.ReplaceAll(tenant.Slug, "-", "_")
	schemaName := fmt.Sprintf("tenant_%s", safeSchemaName)

	// Create tenant schema
	err := r.db.DB.Exec(fmt.Sprintf("CREATE SCHEMA IF NOT EXISTS %s", schemaName)).Error
	if err != nil {
		return fmt.Errorf("failed to create tenant schema: %w", err)
	}

	// Create users table in tenant schema
	err = r.db.DB.Exec(fmt.Sprintf(`
        CREATE TABLE IF NOT EXISTS %s.users (
            id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
            email VARCHAR(255) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            first_name VARCHAR(100) NOT NULL,
            last_name VARCHAR(100) NOT NULL,
            status VARCHAR(20) DEFAULT 'active',
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            deleted_at TIMESTAMP WITH TIME ZONE
        );
        CREATE INDEX IF NOT EXISTS idx_users_email ON %s.users(email);
        CREATE INDEX IF NOT EXISTS idx_users_status ON %s.users(status);
        CREATE INDEX IF NOT EXISTS idx_users_deleted_at ON %s.users(deleted_at);
    `, schemaName, schemaName, schemaName, schemaName)).Error
	if err != nil {
		return fmt.Errorf("failed to create users table in tenant schema: %w", err)
	}

	// Create roles table in tenant schema
	err = r.db.DB.Exec(fmt.Sprintf(`
        CREATE TABLE IF NOT EXISTS %s.roles (
            id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
            name VARCHAR(100) UNIQUE NOT NULL,
            permissions JSONB DEFAULT '{}',
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            deleted_at TIMESTAMP WITH TIME ZONE
        );
        CREATE INDEX IF NOT EXISTS idx_roles_name ON %s.roles(name);
    `, schemaName, schemaName)).Error
	if err != nil {
		return fmt.Errorf("failed to create roles table in tenant schema: %w", err)
	}

	// Create user_roles junction table in tenant schema
	err = r.db.DB.Exec(fmt.Sprintf(`
        CREATE TABLE IF NOT EXISTS %s.user_roles (
            user_id UUID REFERENCES %s.users(id) ON DELETE CASCADE,
            role_id UUID REFERENCES %s.roles(id) ON DELETE CASCADE,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (user_id, role_id)
        );
        CREATE INDEX IF NOT EXISTS idx_user_roles_user_id ON %s.user_roles(user_id);
        CREATE INDEX IF NOT EXISTS idx_user_roles_role_id ON %s.user_roles(role_id);
    `, schemaName, schemaName, schemaName, schemaName, schemaName)).Error
	if err != nil {
		return fmt.Errorf("failed to create user_roles table in tenant schema: %w", err)
	}

	// Create tenant record in public.tenants
	return r.db.DB.Create(tenant).Error
}
