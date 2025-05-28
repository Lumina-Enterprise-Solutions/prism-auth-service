#!/bin/bash

# Create directories if they don't exist
mkdir -p cmd/server
mkdir -p internal/{handlers,services,repository,models,config}
mkdir -p pkg/middleware
mkdir -p migrations
mkdir -p k8s

# Create files only if they don't exist
touch_if_not_exists() {
    if [ ! -f "$1" ]; then
        touch "$1"
        echo "Created $1"
    else
        echo "Skipped $1 (already exists)"
    fi
}

# cmd
touch_if_not_exists cmd/server/main.go

# internal/handlers
touch_if_not_exists internal/handlers/auth.go
touch_if_not_exists internal/handlers/user.go
touch_if_not_exists internal/handlers/health.go

# internal/services
touch_if_not_exists internal/services/auth.go
touch_if_not_exists internal/services/user.go
touch_if_not_exists internal/services/jwt.go

# internal/repository
touch_if_not_exists internal/repository/user.go
touch_if_not_exists internal/repository/tenant.go

# internal/models
touch_if_not_exists internal/models/auth.go
touch_if_not_exists internal/models/user.go

# internal/config
touch_if_not_exists internal/config/config.go

# pkg/middleware
touch_if_not_exists pkg/middleware/auth.go

# migrations
touch_if_not_exists migrations/001_create_users_table.sql
touch_if_not_exists migrations/002_create_roles_table.sql
touch_if_not_exists migrations/003_create_tenants_table.sql

# docker
touch_if_not_exists docker/Dockerfile

# k8s
touch_if_not_exists k8s/deployment.yaml
touch_if_not_exists k8s/service.yaml
touch_if_not_exists k8s/configmap.yaml
touch_if_not_exists k8s/secrets.yaml

# root files
touch_if_not_exists go.mod
touch_if_not_exists go.sum
touch_if_not_exists Makefile
touch_if_not_exists README.md

echo "Project structure setup complete!"
