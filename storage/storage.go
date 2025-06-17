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
}
