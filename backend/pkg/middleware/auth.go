package middleware

import (
	"strings"
	"github.com/labstack/echo/v4"
	"github.com/golang-jwt/jwt/v5"
)

// UserClaims holds JWT claims for authenticated users
type UserClaims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

// AuthMiddleware validates JWT tokens from Authorization header
func AuthMiddleware(secret string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			authHeader := c.Request().Header.Get("Authorization")
			if authHeader == "" {
				return echo.ErrUnauthorized
			}

			tokenString := strings.TrimPrefix(authHeader, "Bearer ")

			// Parse token (simplified - production needs full validation)
			claims := &UserClaims{}
			token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
				return []byte(secret), nil
			})

			if err != nil || !token.Valid {
				return echo.ErrUnauthorized
			}

			c.Set("user", claims.Username)
			return next(c)
		}
	}
}
