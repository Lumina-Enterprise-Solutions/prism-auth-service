package client

import (
	"context"
	"log"

	"github.com/Lumina-Enterprise-Solutions/prism-common-libs/model"
	userv1 "github.com/Lumina-Enterprise-Solutions/prism-protobufs/gen/go/prism/user/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

// Definisikan error untuk konsistensi
var (
	ErrUserNotFound      = status.Error(codes.NotFound, "user not found")
	ErrUserAlreadyExists = status.Error(codes.AlreadyExists, "user with that email already exists")
)

// UserServiceClient adalah antarmuka untuk berinteraksi dengan user-service via gRPC.
type UserServiceClient interface {
	GetUserAuthDetailsByEmail(ctx context.Context, email string) (*model.User, error)
	GetUserAuthDetailsByID(ctx context.Context, id string) (*model.User, error)
	CreateUser(ctx context.Context, req *userv1.CreateUserRequest) (*model.User, error)
	CreateSocialUser(ctx context.Context, req *userv1.CreateSocialUserRequest) (*model.User, error)
	Enable2FA(ctx context.Context, userID, totpSecret string) error
	UpdatePassword(ctx context.Context, userID, newPasswordHash string) error
	Close()
}

type grpcUserServiceClient struct {
	client userv1.UserServiceClient
	conn   *grpc.ClientConn
}

// NewUserServiceClient membuat koneksi gRPC ke user-service dan mengembalikan client.
func NewUserServiceClient(target string) (UserServiceClient, error) {
	conn, err := grpc.NewClient(target, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("did not connect to user-service: %v", err)
		return nil, err
	}

	client := userv1.NewUserServiceClient(conn)
	return &grpcUserServiceClient{client: client, conn: conn}, nil
}

// Close a gRPC connection
func (c *grpcUserServiceClient) Close() {
	if c.conn != nil {
		// LINT FIX: Check the error on close.
		if err := c.conn.Close(); err != nil {
			log.Printf("[WARN] Failed to close gRPC connection to user-service: %v", err)
		}
	}
}

func mapResponseToModel(res *userv1.UserAuthDetailsResponse) *model.User {
	return &model.User{
		ID:           res.Id,
		TenantID:     res.TenantId, // <-- FIX: ADD THIS LINE
		Email:        res.Email,
		PasswordHash: res.PasswordHash,
		RoleName:     res.RoleName,
		Status:       res.Status,
		Is2FAEnabled: res.Is_2FaEnabled, // Also good to map these for consistency
		TOTPSecret:   res.TotpSecret,
	}
}

func (c *grpcUserServiceClient) GetUserAuthDetailsByEmail(ctx context.Context, email string) (*model.User, error) {
	req := &userv1.GetUserAuthDetailsByEmailRequest{Email: email}
	res, err := c.client.GetUserAuthDetailsByEmail(ctx, req)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	return mapResponseToModel(res), nil
}

func (c *grpcUserServiceClient) GetUserAuthDetailsByID(ctx context.Context, id string) (*model.User, error) {
	req := &userv1.GetUserAuthDetailsByIDRequest{Id: id}
	res, err := c.client.GetUserAuthDetailsByID(ctx, req)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	return mapResponseToModel(res), nil
}

func (c *grpcUserServiceClient) CreateUser(ctx context.Context, req *userv1.CreateUserRequest) (*model.User, error) {
	res, err := c.client.CreateUser(ctx, req)
	if err != nil {
		if status.Code(err) == codes.AlreadyExists {
			return nil, ErrUserAlreadyExists
		}
		return nil, err
	}
	return mapResponseToModel(res), nil
}

func (c *grpcUserServiceClient) CreateSocialUser(ctx context.Context, req *userv1.CreateSocialUserRequest) (*model.User, error) {
	res, err := c.client.CreateSocialUser(ctx, req)
	if err != nil {
		return nil, err
	}
	return mapResponseToModel(res), nil
}

func (c *grpcUserServiceClient) Enable2FA(ctx context.Context, userID, totpSecret string) error {
	req := &userv1.Enable2FARequest{
		UserId:     userID,
		TotpSecret: totpSecret,
	}
	_, err := c.client.Enable2FA(ctx, req)
	return err
}
func (c *grpcUserServiceClient) UpdatePassword(ctx context.Context, userID, newPasswordHash string) error {
	req := &userv1.UpdatePasswordRequest{
		UserId:          userID,
		NewPasswordHash: newPasswordHash,
	}
	_, err := c.client.UpdatePassword(ctx, req)
	return err
}
