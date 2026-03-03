# go-sanctum

Go package for validating [Laravel Sanctum](https://laravel.com/docs/sanctum) API tokens.

## Install

```bash
go get github.com/desgnspace/go-sanctum
```

## Quick start

```go
package main

import (
    "database/sql"
    "log"
    "net/http"

    _ "github.com/go-sql-driver/mysql"

    sanctum "github.com/desgnspace/go-sanctum"
    sanctumhttp "github.com/desgnspace/go-sanctum/nethttp"
)

func main() {
    db, err := sql.Open("mysql", "user:pass@tcp(127.0.0.1:3306)/app?parseTime=true")
    if err != nil {
        log.Fatal(err)
    }

    validator := sanctum.NewValidator(sanctum.DefaultConfig(db))

    mux := http.NewServeMux()
    mux.Handle("/api/user", sanctumhttp.Middleware(validator)(http.HandlerFunc(userHandler)))

    log.Fatal(http.ListenAndServe(":8080", mux))
}

func userHandler(w http.ResponseWriter, r *http.Request) {
    token := sanctumhttp.TokenFromContext(r.Context())
    w.Write([]byte("Hello, token: " + token.Name))
}
```

## Database setup

Open a `*sql.DB` connection for your database and pass it to `NewSQLStore`.

### MySQL

```go
import _ "github.com/go-sql-driver/mysql"

dsn := os.Getenv("DB_DSN") // e.g. "user:pass@tcp(127.0.0.1:3306)/app?parseTime=true"
db, err := sql.Open("mysql", dsn)
```

### PostgreSQL

```go
import _ "github.com/lib/pq"

dsn := os.Getenv("DB_DSN") // e.g. "postgres://user:pass@localhost/app?sslmode=disable"
db, err := sql.Open("postgres", dsn)
```

PostgreSQL uses `$1, $2` placeholders instead of `?`. Set the placeholder function:

```go
store := sanctum.NewSQLStore(db, sanctum.WithPlaceholder(sanctum.DollarSign))
```

### SQLite

```go
import _ "github.com/mattn/go-sqlite3"

db, err := sql.Open("sqlite3", os.Getenv("DB_PATH")) // e.g. "./database.sqlite"
```

## Custom table name

By default, `SQLStore` queries the `personal_access_tokens` table. Override it with `WithTable`:

```go
store := sanctum.NewSQLStore(db, sanctum.WithTable("api_tokens"))
```

Options can be combined:

```go
store := sanctum.NewSQLStore(db,
    sanctum.WithTable("api_tokens"),
    sanctum.WithPlaceholder(sanctum.DollarSign),
)
```

## Full Config

Build a `Config` manually for full control:

```go
cfg := sanctum.Config{
    Store:             sanctum.NewSQLStore(db),
    UpdateLastUsedAt:  true,
    ExpirationMinutes: 60, // 0 means no global expiration
}

validator := sanctum.NewValidator(cfg)
```

`DefaultConfig(db)` returns a `Config` with `UpdateLastUsedAt: true` and no global expiration.

## Middleware

Each middleware extracts the `Bearer` token from the `Authorization` header, validates it, and stores the `*TokenData` in the request context.

### net/http

```go
import sanctumhttp "github.com/desgnspace/go-sanctum/nethttp"

mux.Handle("/api/protected", sanctumhttp.Middleware(validator)(handler))

// retrieve token in handler
token := sanctumhttp.TokenFromContext(r.Context())
```

### Gin

```go
import sanctumgin "github.com/desgnspace/go-sanctum/gin"

r.Use(sanctumgin.Middleware(validator))

// retrieve token in handler
token := sanctumgin.TokenFromContext(c)
```

### Fiber

```go
import sanctumfiber "github.com/desgnspace/go-sanctum/fiber"

app.Use(sanctumfiber.Middleware(validator))

// retrieve token in handler
token := sanctumfiber.TokenFromContext(c)
```

## Token abilities

```go
token, err := validator.CheckToken(bearerToken)

if token.Can("server:update") {
    // allowed
}

if token.Cant("server:delete") {
    // denied
}
```

A token with the `*` ability can do everything.

## Custom store

Implement the `TokenStore` interface to use any backend:

```go
type TokenStore interface {
    FindByID(id string) (*TokenData, error)
    FindByHash(hash string) (*TokenData, error)
    TouchLastUsedAt(id string) error
}
```

Example skeleton for Redis:

```go
type RedisStore struct {
    client *redis.Client
}

func (s *RedisStore) FindByID(id string) (*sanctum.TokenData, error) {
    // look up token by ID
}

func (s *RedisStore) FindByHash(hash string) (*sanctum.TokenData, error) {
    // look up token by SHA-256 hash
}

func (s *RedisStore) TouchLastUsedAt(id string) error {
    // update last_used_at timestamp
}
```

Then pass it in the config:

```go
cfg := sanctum.Config{
    Store: &RedisStore{client: rdb},
}
```

## String IDs

`TokenData.ID` and `TokenData.TokenableID` are `string` fields, so they work with auto-increment integers, UUIDs, ULIDs, or any other ID format your Laravel app uses.
