package sanctum

import "database/sql"

type Config struct {
	Store             TokenStore
	UpdateLastUsedAt  bool
	ExpirationMinutes int
}

func DefaultConfig(db *sql.DB) Config {
	return Config{
		Store:            NewSQLStore(db),
		UpdateLastUsedAt: true,
	}
}
