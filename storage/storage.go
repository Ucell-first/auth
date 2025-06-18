package storage

import (
	"auth/storage/postgres"
	"auth/storage/redisnosql"
	"auth/storage/repo"
	"database/sql"

	"github.com/redis/go-redis/v9"
)

type IStorage interface {
	User() repo.IUserStorage
	Token() repo.ITokenStorage
	ClosePDB() error
	CloseRDB() error
}

type databaseStorage struct {
	db  *sql.DB
	rdb *redis.Client
}

func NewStorage(db *sql.DB, rdb *redis.Client) IStorage {
	return &databaseStorage{
		db:  db,
		rdb: rdb,
	}
}

func (p *databaseStorage) ClosePDB() error {
	err := p.db.Close()
	if err != nil {
		return err
	}
	return nil
}

func (p *databaseStorage) CloseRDB() error {
	err := p.rdb.Close()
	if err != nil {
		return err
	}
	return nil
}

func (p *databaseStorage) User() repo.IUserStorage {
	return postgres.NewUserRepository(p.db)
}

func (p *databaseStorage) Token() repo.ITokenStorage {
	return postgres.NewTokenRepository(p.db)
}

func (p *databaseStorage) Redis() repo.IRedisStorage {
	return redisnosql.NewRedisRepository(p.rdb)
}
