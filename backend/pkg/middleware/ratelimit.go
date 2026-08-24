package middleware

import (
	"time"
	"github.com/labstack/echo/v4"
)

// RateLimitMiddleware limits requests per client
func RateLimitMiddleware(maxRequests int, window time.Duration) echo.MiddlewareFunc {
	requests := make(map[string][]time.Time)

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			ip := c.RealIP()
			now := time.Now()

			// Clean old entries
			windowStart := now.Add(-window)

			if reqs, ok := requests[ip]; ok {
				validReqs := make([]time.Time, 0)
				for _, t := range reqs {
					if t.After(windowStart) {
						validReqs = append(validReqs, t)
					}
				}
				requests[ip] = validReqs
			}

			// Check limit
			if len(requests[ip]) >= maxRequests {
				return echo.ErrTooManyRequests
			}

			requests[ip] = append(requests[ip], now)
			return next(c)
		}
	}
}
