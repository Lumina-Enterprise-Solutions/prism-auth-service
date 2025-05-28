-- Create roles table in tenant_default schema
CREATE TABLE IF NOT EXISTS tenant_default.roles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(100) UNIQUE NOT NULL,
    permissions JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE
);

-- Create user_roles junction table in tenant_default schema
CREATE TABLE IF NOT EXISTS tenant_default.user_roles (
    user_id UUID REFERENCES tenant_default.users(id) ON DELETE CASCADE,
    role_id UUID REFERENCES tenant_default.roles(id) ON DELETE CASCADE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, role_id)
);

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_roles_name ON tenant_default.roles(name);
CREATE INDEX IF NOT EXISTS idx_user_roles_user_id ON tenant_default.user_roles(user_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_role_id ON tenant_default.user_roles(role_id);
