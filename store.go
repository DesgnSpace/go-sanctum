package sanctum

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

type TokenStore interface {
	FindByID(ctx context.Context, id string) (*TokenData, error)
	FindByHash(ctx context.Context, hash string) (*TokenData, error)
	TouchLastUsedAt(ctx context.Context, id string) error
}

type PlaceholderFunc func(index int) string

func QuestionMark(_ int) string {
	return "?"
}

func DollarSign(index int) string {
	return fmt.Sprintf("$%d", index)
}

// SQLStore reads Sanctum tokens from a SQL database. Table names and placeholder
// functions are interpolated into SQL and must come from trusted developer config.
type SQLStore struct {
	db          *sql.DB
	table       string
	placeholder PlaceholderFunc
	location    *time.Location
}

type SQLStoreOption func(*SQLStore)

// WithTable sets the trusted SQL table identifier used in generated queries.
// It panics if table is empty or contains whitespace, quotes, or semicolons.
func WithTable(table string) SQLStoreOption {
	if table == "" || strings.ContainsAny(table, " \t\r\n;'\"`") {
		panic("sanctum: invalid SQL table name")
	}

	return func(s *SQLStore) {
		s.table = table
	}
}

func WithPlaceholder(fn PlaceholderFunc) SQLStoreOption {
	return func(s *SQLStore) {
		s.placeholder = fn
	}
}

func WithLocation(loc *time.Location) SQLStoreOption {
	return func(s *SQLStore) {
		s.location = loc
	}
}

func NewSQLStore(db *sql.DB, opts ...SQLStoreOption) *SQLStore {
	s := &SQLStore{
		db:          db,
		table:       "personal_access_tokens",
		placeholder: QuestionMark,
		location:    loadLocation(),
	}

	for _, opt := range opts {
		opt(s)
	}

	return s
}

func loadLocation() *time.Location {
	tz := os.Getenv("APP_TIMEZONE")
	if tz == "" {
		return time.UTC
	}

	loc, err := time.LoadLocation(tz)
	if err != nil {
		return time.UTC
	}

	return loc
}

func (s *SQLStore) FindByID(ctx context.Context, id string) (*TokenData, error) {
	query := fmt.Sprintf(
		"SELECT id, tokenable_id, tokenable_type, name, token, abilities, expires_at, created_at, last_used_at FROM %s WHERE id = %s",
		s.table, s.placeholder(1),
	)

	return s.scanToken(s.db.QueryRowContext(ctx, query, id))
}

func (s *SQLStore) FindByHash(ctx context.Context, hash string) (*TokenData, error) {
	query := fmt.Sprintf(
		"SELECT id, tokenable_id, tokenable_type, name, token, abilities, expires_at, created_at, last_used_at FROM %s WHERE token = %s",
		s.table, s.placeholder(1),
	)

	return s.scanToken(s.db.QueryRowContext(ctx, query, hash))
}

func (s *SQLStore) TouchLastUsedAt(ctx context.Context, id string) error {
	query := fmt.Sprintf(
		"UPDATE %s SET last_used_at = %s WHERE id = %s",
		s.table, s.placeholder(1), s.placeholder(2),
	)

	_, err := s.db.ExecContext(ctx, query, time.Now().In(s.location), id)

	return err
}

func (s *SQLStore) scanToken(row *sql.Row) (*TokenData, error) {
	var token TokenData
	var abilitiesJSON sql.NullString

	err := row.Scan(
		&token.ID,
		&token.TokenableID,
		&token.TokenableType,
		&token.Name,
		&token.Token,
		&abilitiesJSON,
		&token.ExpiresAt,
		&token.CreatedAt,
		&token.LastUsedAt,
	)

	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrTokenNotFound
	}

	if err != nil {
		return nil, fmt.Errorf("sanctum: database error: %w", err)
	}

	if abilitiesJSON.Valid && abilitiesJSON.String != "" {
		if err := json.Unmarshal([]byte(abilitiesJSON.String), &token.Abilities); err != nil {
			return nil, fmt.Errorf("sanctum: failed to parse abilities: %w", err)
		}
	}

	return &token, nil
}
