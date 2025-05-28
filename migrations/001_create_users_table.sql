-- Ensure uuid-ossp extension is available
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Create default tenant schema
CREATE SCHEMA IF NOT EXISTS tenant_default;

-- Create users table in tenant_default schema
CREATE TABLE IF NOT EXISTS tenant_default.users (
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

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_users_email ON tenant_default.users(email);
CREATE INDEX IF NOT EXISTS idx_users_status ON tenant_default.users(status);
CREATE INDEX IF NOT EXISTS idx_users_deleted_at ON tenant_default.users(deleted_at);
