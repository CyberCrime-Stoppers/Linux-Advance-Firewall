package response

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Detail  string `json:"detail,omitempty"`
}

func JSON(c echo.Context, status int, data interface{}) error {
	return c.JSON(status, data)
}

func NoContent(c echo.Context) error {
	return c.NoContent(http.StatusNoContent)
}
