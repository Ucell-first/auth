CREATE TYPE roles AS ENUM ('admin','user');

CREATE TYPE providers AS ENUM ('google','any');

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(50),
    surname VARCHAR(50),
    email VARCHAR(100) UNIQUE NOT NULL,
    birth_date DATE,
    gender VARCHAR(10) CHECK (gender IN ('male', 'female')),
    password_hash VARCHAR(255),
    phone_number VARCHAR(20) UNIQUE,
    address VARCHAR(255),
    role roles NOT NULL DEFAULT 'user',
    provider providers NOT NULL DEFAULT 'any',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deleted_at Bigint DEFAULT 0
);

CREATE TABLE IF NOT EXISTS refreshtokens (
    token        VARCHAR(500) UNIQUE NOT NULL,
    user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deleted_at   BIGINT DEFAULT 0
);
