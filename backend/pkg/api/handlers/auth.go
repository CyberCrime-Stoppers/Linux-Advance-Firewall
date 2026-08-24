package handlers

import (
	"net/http"
	"github.com/labstack/echo/v4"
)

// LoginRequest holds authentication credentials
type LoginRequest struct {
	Username string `json:"username" validate:"required"`
	Password string `json:"password" validate:"required,min=8"`
}

// HealthCheck returns server status
func HealthCheck(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]interface{}{
		"status":  "healthy",
		"version": "1.0.0",
	})
}
