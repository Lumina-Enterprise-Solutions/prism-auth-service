// File: internal/client/user_service_client_test.go
package client

import (
	"context"
	"net"
	"testing"

	userv1 "github.com/Lumina-Enterprise-Solutions/prism-protobufs/gen/go/prism/user/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

const bufSize = 1024 * 1024

var lis *bufconn.Listener

// mockUserServiceServer is a mock implementation of the gRPC server.
type mockUserServiceServer struct {
	userv1.UnimplementedUserServiceServer
	// You can add fields here to control the mock's behavior
	ShouldReturnError bool
}

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

func setupMockGRPCServer() {
	lis = bufconn.Listen(bufSize)
	s := grpc.NewServer()
	userv1.RegisterUserServiceServer(s, &mockUserServiceServer{})
	go func() {
		if err := s.Serve(lis); err != nil {
			panic(err)
		}
	}()
}

func bufDialer(context.Context, string) (net.Conn, error) {
	return lis.Dial()
}

func TestMain(m *testing.M) {
	setupMockGRPCServer()
	m.Run()
}

func TestUserServiceClient_GetUserAuthDetailsByEmail(t *testing.T) {
	ctx := context.Background()
	conn, err := grpc.DialContext(ctx, "bufnet", grpc.WithContextDialer(bufDialer), grpc.WithInsecure())
	require.NoError(t, err)
	defer conn.Close()

	client := &grpcUserServiceClient{
		client: userv1.NewUserServiceClient(conn),
		conn:   conn,
	}

	t.Run("Success", func(t *testing.T) {
		user, err := client.GetUserAuthDetailsByEmail(ctx, "test@example.com")
		require.NoError(t, err)
		assert.NotNil(t, user)
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
