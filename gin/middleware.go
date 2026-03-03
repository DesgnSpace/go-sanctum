package gin

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	sanctum "github.com/desgnspace/go-sanctum"
)

const (
	TokenKey = "sanctum_token"
)

func Middleware(validator *sanctum.Validator) gin.HandlerFunc {
	return func(c *gin.Context) {
		bearer := extractBearer(c)
		if bearer == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			return
		}

		token, err := validator.CheckToken(bearer)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			return
		}

		c.Set(TokenKey, token)
		c.Next()
	}
}

func TokenFromContext(c *gin.Context) *sanctum.TokenData {
	val, exists := c.Get(TokenKey)
	if !exists {
		return nil
	}

	token, _ := val.(*sanctum.TokenData)
	return token
}

func extractBearer(c *gin.Context) string {
	auth := c.GetHeader("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return ""
	}

	return strings.TrimPrefix(auth, "Bearer ")
}
