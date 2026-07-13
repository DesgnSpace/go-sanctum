package sanctum

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"
)

const (
	maxConcurrentTouches = 16
	touchTimeout         = 5 * time.Second
)

var (
	ErrTokenNotFound = errors.New("sanctum: token not found")
	ErrTokenExpired  = errors.New("sanctum: token has expired")
	ErrTokenInvalid  = errors.New("sanctum: token signature is invalid")
	ErrTokenMissing  = errors.New("sanctum: bearer token is missing")
	// ErrTouchLastUsedAtBusy indicates that the bounded update capacity is full.
	ErrTouchLastUsedAtBusy = errors.New("sanctum: last-used update concurrency limit reached")
)

type Validator struct {
	config     Config
	touchSlots chan struct{}
}

func NewValidator(cfg Config) *Validator {
	if cfg.ErrorHandler == nil {
		cfg.ErrorHandler = func(err error) {
			log.Printf("sanctum: %v", err)
		}
	}

	return &Validator{
		config:     cfg,
		touchSlots: make(chan struct{}, maxConcurrentTouches),
	}
}

func (v *Validator) CheckToken(ctx context.Context, bearerToken string) (*TokenData, error) {
	bearerToken = strings.TrimSpace(bearerToken)
	if bearerToken == "" {
		return nil, ErrTokenMissing
	}

	if strings.Contains(bearerToken, "|") {
		return v.checkTokenWithID(ctx, bearerToken)
	}

	return v.checkTokenByHash(ctx, bearerToken)
}

func (v *Validator) checkTokenWithID(ctx context.Context, bearerToken string) (*TokenData, error) {
	parts := strings.SplitN(bearerToken, "|", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return nil, ErrTokenInvalid
	}

	id := parts[0]
	plaintext := parts[1]
	hash := hashToken(plaintext)

	token, err := v.config.Store.FindByID(ctx, id)
	if err != nil {
		return nil, err
	}

	if subtle.ConstantTimeCompare([]byte(token.Token), []byte(hash)) != 1 {
		return nil, ErrTokenInvalid
	}

	if err := v.validateExpiration(token); err != nil {
		return nil, err
	}

	v.touchLastUsedAt(ctx, token.ID)

	return token, nil
}

func (v *Validator) checkTokenByHash(ctx context.Context, bearerToken string) (*TokenData, error) {
	hash := hashToken(bearerToken)

	token, err := v.config.Store.FindByHash(ctx, hash)
	if err != nil {
		return nil, err
	}

	if err := v.validateExpiration(token); err != nil {
		return nil, err
	}

	v.touchLastUsedAt(ctx, token.ID)

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

func (v *Validator) touchLastUsedAt(ctx context.Context, tokenID string) {
	if !v.config.UpdateLastUsedAt {
		return
	}

	select {
	case v.touchSlots <- struct{}{}:
	default:
		v.reportError(ErrTouchLastUsedAtBusy)
		return
	}

	go func() {
		defer func() { <-v.touchSlots }()

		touchCtx, cancel := context.WithTimeout(detachContext{Context: ctx}, touchTimeout)
		defer cancel()

		if err := v.config.Store.TouchLastUsedAt(touchCtx, tokenID); err != nil {
			v.reportError(fmt.Errorf("updating token last used at: %w", err))
		}
	}()
}

func (v *Validator) reportError(err error) {
	v.config.ErrorHandler(err)
}

// detachContext preserves request values while allowing bounded background work
// to outlive request cancellation. It is compatible with the module's Go 1.13 floor.
type detachContext struct {
	context.Context
}

func (detachContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (detachContext) Done() <-chan struct{}       { return nil }
func (detachContext) Err() error                  { return nil }

func hashToken(plaintext string) string {
	h := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(h[:])
}
