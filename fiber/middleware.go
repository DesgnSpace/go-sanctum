package fiber

import (
	"strings"

	"github.com/gofiber/fiber/v2"

	sanctum "github.com/desgnspace/go-sanctum"
)

const (
	TokenKey = "sanctum_token"
)

func Middleware(validator *sanctum.Validator) fiber.Handler {
	return func(c *fiber.Ctx) error {
		bearer := extractBearer(c)
		if bearer == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized"})
		}

		token, err := validator.CheckToken(bearer)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized"})
		}

		c.Locals(TokenKey, token)
		return c.Next()
	}
}

func TokenFromContext(c *fiber.Ctx) *sanctum.TokenData {
	token, _ := c.Locals(TokenKey).(*sanctum.TokenData)
	return token
}

func extractBearer(c *fiber.Ctx) string {
	auth := c.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return ""
	}

	return strings.TrimPrefix(auth, "Bearer ")
}
