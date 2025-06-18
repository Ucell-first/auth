package postgres

import (
	"auth/config"
	"auth/storage"
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"
)

type postgresStorage struct {
	db *sql.DB
}

func NewPostgresStorage(db *sql.DB) storage.IStorage {
	return &postgresStorage{
		db: db,
	}
}

func ConnectionPDb() (*sql.DB, error) {
	conf := config.Load()
	conDb := fmt.Sprintf(
		"host=%s port=%s user=%s dbname=%s password=%s sslmode=disable",
		conf.Postgres.PDB_HOST,
		conf.Postgres.PDB_PORT,
		conf.Postgres.PDB_USER,
		conf.Postgres.PDB_NAME,
		conf.Postgres.PDB_PASSWORD,
	)
	db, err := sql.Open("postgres", conDb)
	if err != nil {
		return nil, err
	}

	if err := db.Ping(); err != nil {
		return nil, err
	}

	return db, nil
}

func (p *postgresStorage) Close() error {
	err := p.db.Close()
	if err != nil {
		return err
	}
	return nil
}

func (p *postgresStorage) User() storage.IUserStorage {
	return NewUserRepository(p.db)
}

func (p *postgresStorage) Token() storage.ITokenStorage {
	return NewTokenRepository(p.db)
}
