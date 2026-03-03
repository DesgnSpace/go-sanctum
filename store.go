package sanctum

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

type TokenStore interface {
	FindByID(id string) (*TokenData, error)
	FindByHash(hash string) (*TokenData, error)
	TouchLastUsedAt(id string) error
}

type PlaceholderFunc func(index int) string

func QuestionMark(_ int) string {
	return "?"
}

func DollarSign(index int) string {
	return fmt.Sprintf("$%d", index)
}

type SQLStore struct {
	db          *sql.DB
	table       string
	placeholder PlaceholderFunc
}

type SQLStoreOption func(*SQLStore)

func WithTable(table string) SQLStoreOption {
	return func(s *SQLStore) {
		s.table = table
	}
}

func WithPlaceholder(fn PlaceholderFunc) SQLStoreOption {
	return func(s *SQLStore) {
		s.placeholder = fn
	}
}

func NewSQLStore(db *sql.DB, opts ...SQLStoreOption) *SQLStore {
	s := &SQLStore{
		db:          db,
		table:       "personal_access_tokens",
		placeholder: QuestionMark,
	}

	for _, opt := range opts {
		opt(s)
	}

	return s
}

func (s *SQLStore) FindByID(id string) (*TokenData, error) {
	query := fmt.Sprintf(
		"SELECT id, tokenable_id, tokenable_type, name, token, abilities, expires_at, created_at, last_used_at FROM %s WHERE id = %s",
		s.table, s.placeholder(1),
	)

	return s.scanToken(s.db.QueryRow(query, id))
}

func (s *SQLStore) FindByHash(hash string) (*TokenData, error) {
	query := fmt.Sprintf(
		"SELECT id, tokenable_id, tokenable_type, name, token, abilities, expires_at, created_at, last_used_at FROM %s WHERE token = %s",
		s.table, s.placeholder(1),
	)

	return s.scanToken(s.db.QueryRow(query, hash))
}

func (s *SQLStore) TouchLastUsedAt(id string) error {
	query := fmt.Sprintf(
		"UPDATE %s SET last_used_at = %s WHERE id = %s",
		s.table, s.placeholder(1), s.placeholder(2),
	)

	_, err := s.db.Exec(query, time.Now(), id)

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
