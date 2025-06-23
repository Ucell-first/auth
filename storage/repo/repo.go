package repo

import (
	pb "auth/model/storage"
	"context"
)

type IUserStorage interface {
	CreateUser(context.Context, *pb.RegisterUserReq) (*pb.UserInfo, error)
	CreateAdmin(ctx context.Context, req *pb.RegisterAdminReq) (*pb.UserInfo, error)
	Login(ctx context.Context, email, password string) (*pb.UserInfo, error)
	GetUserByEmail(ctx context.Context, email string) (*pb.UserInfo, error)
	GetUserById(ctx context.Context, id string) (*pb.UserInfo, error)
	UserList(ctx context.Context, filter pb.UserFilter, page int64, limit int64) ([]*pb.UserInfo, int64, error)
	UpdatePassword(ctx context.Context, email, newPassword string) error
	UpdateUser(ctx context.Context, req *pb.UserInfo) (*pb.UserInfo, error)
	DeleteUser(ctx context.Context, id string) error
	IsUserExist(ctx context.Context, email, phoneNumber string) (bool, error)
}

type ITokenStorage interface {
	CreateToken(ctx context.Context, token, userID string) error
	GetUserIdFromToken(ctx context.Context, token string) (string, error)
	DeleteToken(ctx context.Context, token string) error
	DeleteExpiredTokens(ctx context.Context) error
	DeleteTokenByUserId(ctx context.Context, userID string) error
	VerifyToken(ctx context.Context, token string) (bool, error)
	GetTokensByUserID(ctx context.Context, userID string) ([]string, error)
	CreateAccessToken(ctx context.Context, token, refreshToken string) error
	GetRefreshTokenByAccesstoken(ctx context.Context, accessToken string) (string, error)
	DeleteAccessToken(ctx context.Context, token string) error
	DeleteRefreshTokenAndRelatedAccessTokens(ctx context.Context, refreshToken string) error
	DeleteAllTokensForUser(ctx context.Context, userID string) error
	VerifyAccessToken(ctx context.Context, accessToken string) (bool, error)
}

type IRedisStorage interface {
	StoreCodes(ctx context.Context, code, email string) error
	GetCodes(ctx context.Context, email string) (string, error)
}
