package grpc_server

import (
	"context"

	"github.com/Lumina-Enterprise-Solutions/prism-auth-service/internal/service"
	"github.com/Lumina-Enterprise-Solutions/prism-common-libs/model"
	authv1 "github.com/Lumina-Enterprise-Solutions/prism-protobufs/gen/go/prism/auth/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type AuthServer struct {
	authv1.UnimplementedAuthServiceServer
	authService service.AuthService
}

func NewAuthServer(svc service.AuthService) *AuthServer {
	return &AuthServer{authService: svc}
}

func (s *AuthServer) GenerateImpersonationToken(ctx context.Context, req *authv1.GenerateImpersonationTokenRequest) (*authv1.GenerateImpersonationTokenResponse, error) {
	// Gunakan getter yang di-generate oleh protobuf untuk keamanan dari nil pointer.
	if req.GetTargetUser() == nil {
		return nil, status.Error(codes.InvalidArgument, "target_user is required")
	}

	protoUser := req.GetTargetUser()

	// Mapping dari tipe protobuf (UserInfoForToken) ke tipe model internal (model.User)
	targetUser := &model.User{
		ID:       protoUser.GetId(),
		Email:    protoUser.GetEmail(),
		RoleName: protoUser.GetRoleName(),
	}

	token, exp, err := s.authService.GenerateImpersonationToken(ctx, targetUser, req.GetActorId())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to generate token: %v", err)
	}

	return &authv1.GenerateImpersonationTokenResponse{
		AccessToken: token,
		ExpiresAt:   timestamppb.New(exp),
	}, nil
}
