// Package handler HTTP so'rovlarni boshqarish uchun
package handler

import (
	"auth/storage"
	"log/slog"
)

// Handler HTTP handler struktura.
type Handler struct {
	Cruds storage.IStorage
	Log   *slog.Logger
}
