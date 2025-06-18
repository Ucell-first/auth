package postgres

import (
	"auth/config"
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"
)

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
