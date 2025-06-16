package storage

import (
	pb "auth/model/storage"
	"context"
)

type IStorage interface {
	User() IUserStorage
	Close()
}

type IUserStorage interface {
	CreateUser(context.Context, *pb.RegisterUserReq) (*pb.UserInfo, error)
}
