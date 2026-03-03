package nethttp

import (
	"context"
	"net/http"
	"strings"

	sanctum "github.com/desgnspace/go-sanctum"
)

type contextKey string

const (
	TokenKey contextKey = "sanctum_token"
)

func Middleware(validator *sanctum.Validator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			bearer := extractBearer(r)
			if bearer == "" {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			token, err := validator.CheckToken(bearer)
			if err != nil {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), TokenKey, token)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func TokenFromContext(ctx context.Context) *sanctum.TokenData {
	token, _ := ctx.Value(TokenKey).(*sanctum.TokenData)
	return token
}

func extractBearer(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return ""
	}

	return strings.TrimPrefix(auth, "Bearer ")
}
