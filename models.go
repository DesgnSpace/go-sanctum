package sanctum

import (
	"database/sql"
	"time"
)

type TokenData struct {
	ID            string
	TokenableID   string
	TokenableType string
	Name          string
	Token         string
	Abilities     []string
	ExpiresAt     sql.NullTime
	CreatedAt     time.Time
	LastUsedAt    sql.NullTime
}

func (t *TokenData) Can(ability string) bool {
	for _, a := range t.Abilities {
		if a == "*" || a == ability {
			return true
		}
	}

	return false
}

func (t *TokenData) Cant(ability string) bool {
	return !t.Can(ability)
}
