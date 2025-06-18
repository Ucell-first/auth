// Package handler HTTP so'rovlarni boshqarish uchun
package handler

import (
	"auth/storage"
	"log/slog"

	"github.com/casbin/casbin/v2"
)

// Handler HTTP handler struktura.
type Handler struct {
	Cruds  storage.IStorage
	Log    *slog.Logger
	Casbin *casbin.Enforcer
}
