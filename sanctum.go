package sanctum

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"strings"
	"time"
)

var (
	ErrTokenNotFound = errors.New("sanctum: token not found")
	ErrTokenExpired  = errors.New("sanctum: token has expired")
	ErrTokenInvalid  = errors.New("sanctum: token signature is invalid")
	ErrTokenMissing  = errors.New("sanctum: bearer token is missing")
)

type Validator struct {
	config Config
}

func NewValidator(cfg Config) *Validator {
	return &Validator{config: cfg}
}

func (v *Validator) CheckToken(bearerToken string) (*TokenData, error) {
	bearerToken = strings.TrimSpace(bearerToken)
	if bearerToken == "" {
		return nil, ErrTokenMissing
	}

	if strings.Contains(bearerToken, "|") {
		return v.checkTokenWithID(bearerToken)
	}

	return v.checkTokenByHash(bearerToken)
}

func (v *Validator) checkTokenWithID(bearerToken string) (*TokenData, error) {
	parts := strings.SplitN(bearerToken, "|", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return nil, ErrTokenInvalid
	}

	id := parts[0]
	plaintext := parts[1]
	hash := hashToken(plaintext)

	token, err := v.config.Store.FindByID(id)
	if err != nil {
		return nil, err
	}

	if subtle.ConstantTimeCompare([]byte(token.Token), []byte(hash)) != 1 {
		return nil, ErrTokenInvalid
	}

	if err := v.validateExpiration(token); err != nil {
		return nil, err
	}

	v.touchLastUsedAt(token)

	return token, nil
}

func (v *Validator) checkTokenByHash(bearerToken string) (*TokenData, error) {
	hash := hashToken(bearerToken)

	token, err := v.config.Store.FindByHash(hash)
	if err != nil {
		return nil, err
	}

	if err := v.validateExpiration(token); err != nil {
		return nil, err
	}

	v.touchLastUsedAt(token)

	return token, nil
}

func (v *Validator) validateExpiration(token *TokenData) error {
	now := time.Now()

	if token.ExpiresAt.Valid && token.ExpiresAt.Time.Before(now) {
		return ErrTokenExpired
	}

	if v.config.ExpirationMinutes > 0 {
		expiresAt := token.CreatedAt.Add(time.Duration(v.config.ExpirationMinutes) * time.Minute)
		if expiresAt.Before(now) {
			return ErrTokenExpired
		}
	}

	return nil
}

func (v *Validator) touchLastUsedAt(token *TokenData) {
	if !v.config.UpdateLastUsedAt {
		return
	}

	go func() {
		v.config.Store.TouchLastUsedAt(token.ID)
	}()
}

func hashToken(plaintext string) string {
	h := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(h[:])
}
