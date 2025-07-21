// File: services/prism-auth-service/internal/client/tenant_service_client.go
package client

import (
	"context"
	"fmt"
	"log"

	tenantv1 "github.com/Lumina-Enterprise-Solutions/prism-protobufs/gen/go/prism/tenant/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// DIUBAH: Tambahkan metode baru ke interface
type TenantServiceClient interface {
	CreateTenantWithAdmin(ctx context.Context, req *tenantv1.CreateTenantWithAdminRequest) (*tenantv1.CreateTenantWithAdminResponse, error)
	GetTenantByName(ctx context.Context, name string) (*tenantv1.Tenant, error)
	Close()
}

type grpcTenantServiceClient struct {
	client tenantv1.TenantServiceClient
	conn   *grpc.ClientConn
}

func NewTenantServiceClient(target string) (TenantServiceClient, error) {
	conn, err := grpc.NewClient(target, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("did not connect to tenant-service: %w", err)
	}
	client := tenantv1.NewTenantServiceClient(conn)
	return &grpcTenantServiceClient{client: client, conn: conn}, nil
}

func (c *grpcTenantServiceClient) Close() {
	if c.conn != nil {
		if err := c.conn.Close(); err != nil {
			log.Printf("Failed to close gRPC connection to tenant-service: %v", err)
		}
	}
}

func (c *grpcTenantServiceClient) CreateTenantWithAdmin(ctx context.Context, req *tenantv1.CreateTenantWithAdminRequest) (*tenantv1.CreateTenantWithAdminResponse, error) {
	return c.client.CreateTenantWithAdmin(ctx, req)
}

// BARU: Implementasikan metode baru untuk interface
func (c *grpcTenantServiceClient) GetTenantByName(ctx context.Context, name string) (*tenantv1.Tenant, error) {
	req := &tenantv1.GetTenantByNameRequest{Name: name}
	return c.client.GetTenantByName(ctx, req)
}
