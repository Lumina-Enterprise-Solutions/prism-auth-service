# Prism Auth Service

A microservice for authentication and user management in the Prism platform.

## Features

- JWT-based authentication
- User registration and login
- Password reset functionality
- Role-based access control (RBAC)
- Multi-tenant support
- RESTful API
- Health checks
- Docker support

## Prerequisites

- Go 1.21 or higher
- PostgreSQL 13+
- Redis 6+
- Docker and Docker Compose (optional)

## Quick Start

### Using Docker Compose (Recommended)

1. Clone the repository
2. Copy environment file:
   ```bash
   cp .env.example .env
