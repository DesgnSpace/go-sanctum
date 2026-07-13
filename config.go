package sanctum

import "database/sql"

type Config struct {
	Store             TokenStore
	UpdateLastUsedAt  bool
	ExpirationMinutes int
	// ErrorHandler observes asynchronous last-used update failures. It must be
	// safe for concurrent use and should return quickly. NewValidator uses the
	// standard logger when ErrorHandler is nil.
	ErrorHandler func(error)
}

func DefaultConfig(db *sql.DB) Config {
	return Config{
		Store:            NewSQLStore(db),
		UpdateLastUsedAt: true,
	}
}
