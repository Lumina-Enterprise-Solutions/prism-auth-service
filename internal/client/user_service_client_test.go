// File: internal/client/user_service_client_test.go
package client

import (
	"context"
	"log"
	"net"
	"testing"

	userv1 "github.com/Lumina-Enterprise-Solutions/prism-protobufs/gen/go/prism/user/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

const bufSize = 1024 * 1024

// mockUserServiceServer adalah implementasi mock dari server gRPC.
type mockUserServiceServer struct {
	userv1.UnimplementedUserServiceServer
	ShouldReturnError bool
}

// Implementasi metode mock...
func (s *mockUserServiceServer) GetUserAuthDetailsByEmail(ctx context.Context, req *userv1.GetUserAuthDetailsByEmailRequest) (*userv1.UserAuthDetailsResponse, error) {
	if s.ShouldReturnError {
		return nil, status.Error(codes.NotFound, "mock user not found")
	}
	if req.Email == "test@example.com" {
		return &userv1.UserAuthDetailsResponse{
			Id:           "user-123",
			Email:        "test@example.com",
			PasswordHash: "hashed_password",
			RoleName:     "Admin",
			Status:       "active",
		}, nil
	}
	return nil, status.Error(codes.NotFound, "user not found")
}

func (s *mockUserServiceServer) Enable2FA(ctx context.Context, req *userv1.Enable2FARequest) (*userv1.Enable2FAResponse, error) {
	if s.ShouldReturnError {
		return nil, status.Error(codes.Internal, "mock DB error")
	}
	return &userv1.Enable2FAResponse{Success: true}, nil
}

// setupTestGRPCServerAndClient adalah fungsi helper yang menyatukan setup server DAN client.
func setupTestGRPCServerAndClient(t *testing.T) (UserServiceClient, func()) {
	t.Helper()

	listener := bufconn.Listen(bufSize)
	s := grpc.NewServer()
	userv1.RegisterUserServiceServer(s, &mockUserServiceServer{})

	go func() {
		if err := s.Serve(listener); err != nil {
			log.Fatalf("Server exited with error: %v", err)
		}
	}()

	// FIX: Gunakan grpc.NewClient dengan opsi yang benar.
	// Ini adalah cara yang direkomendasikan dan tidak akan memicu staticcheck.
	conn, err := grpc.NewClient("passthrough:///bufnet", // Skema "passthrough" sangat penting
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return listener.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)

	client := &grpcUserServiceClient{
		client: userv1.NewUserServiceClient(conn),
		conn:   conn,
	}

	teardown := func() {
		s.Stop()
		if err := conn.Close(); err != nil {
			t.Logf("Gagal menutup koneksi gRPC: %v", err)
		}
	}

	return client, teardown
}

func TestUserServiceClient_GetUserAuthDetailsByEmail(t *testing.T) {
	client, teardown := setupTestGRPCServerAndClient(t)
	defer teardown()

	ctx := context.Background()

	t.Run("Success", func(t *testing.T) {
		user, err := client.GetUserAuthDetailsByEmail(ctx, "test@example.com")
		require.NoError(t, err)
		require.NotNil(t, user)
		assert.Equal(t, "user-123", user.ID)
		assert.Equal(t, "Admin", user.RoleName)
	})

	t.Run("Failure - Not Found", func(t *testing.T) {
		_, err := client.GetUserAuthDetailsByEmail(ctx, "notfound@example.com")
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.NotFound, st.Code())
		assert.Equal(t, ErrUserNotFound, err)
	})
}
