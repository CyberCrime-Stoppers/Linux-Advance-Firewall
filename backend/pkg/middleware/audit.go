package middleware

import (
	"fmt"
	"linux-firewall-backend/pkg/audit"
	"time"

	"github.com/labstack/echo/v4"
)

// AuditMiddleware wraps handlers with audit logging
func AuditMiddleware(logger *audit.AuditLogger) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			startTime := time.Now()

			err := next(c)

			statusCode := c.Response().Status
			duration := time.Since(startTime).Milliseconds()

			user, _ := c.Get("user").(string)

			logger.Log(
				fmt.Sprintf("%s %s", c.Request().Method, c.Path()),
				   fmt.Sprintf("status=%d duration=%dms", statusCode, duration),
				   getLogLevel(statusCode),
				   user,
			)

			return err
		}
	}
}

func getLogLevel(statusCode int) string {
	switch {
		case statusCode >= 500:
			return "error"
		case statusCode >= 400:
			return "warning"
		default:
			return "info"
	}
}
