package store

import (
	"context"
	"database/sql"
	_ "embed"
	"fmt"
	"time"

	_ "github.com/lib/pq"
)

//go:embed schema.sql
var schemaSQL string

type DB struct {
	*sql.DB
}

// Open connects to Postgres and applies the (idempotent) schema. Using
// database/sql's built-in pool means we don't need a separate pooling
// dependency; lib/pq is a pure database/sql driver with zero transitive
// dependencies of its own, which keeps the supply-chain surface small for a
// security-critical component.
func Open(ctx context.Context, dsn string) (*DB, error) {
	sqlDB, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}

	sqlDB.SetMaxOpenConns(20)
	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetConnMaxLifetime(30 * time.Minute)

	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := sqlDB.PingContext(pingCtx); err != nil {
		return nil, fmt.Errorf("pinging database: %w", err)
	}

	if _, err := sqlDB.ExecContext(ctx, schemaSQL); err != nil {
		return nil, fmt.Errorf("applying schema: %w", err)
	}

	return &DB{sqlDB}, nil
}
