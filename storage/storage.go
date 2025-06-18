package storage

import (
	pb "auth/model/storage"
	"context"
)

type IStorage interface {
	User() IUserStorage
	Close() error
}

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
