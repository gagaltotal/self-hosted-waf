package store

import (
	"context"
	"database/sql"
	"errors"
)

var ErrNotFound = errors.New("not found")

// Every query in this file uses $N placeholders exclusively. Never build
// SQL with fmt.Sprintf/string concatenation of caller-supplied values --
// that is exactly the SQL-injection class this whole product exists to
// stop, and it would be an embarrassing (and dangerous) mistake to
// reintroduce it in the WAF's own backend.

func (db *DB) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := db.QueryRowContext(ctx, `SELECT count(*) FROM users`).Scan(&n)
	return n, err
}

func (db *DB) CreateUser(ctx context.Context, email, passwordHash string) (*User, error) {
	u := &User{}
	err := db.QueryRowContext(ctx, `
		INSERT INTO users (email, password_hash)
		VALUES ($1, $2)
		RETURNING id, email, password_hash, created_at
	`, email, passwordHash).Scan(&u.ID, &u.Email, &u.PasswordHash, &u.CreatedAt)
	if err != nil {
		return nil, err
	}
	return u, nil
}

func (db *DB) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	u := &User{}
	err := db.QueryRowContext(ctx, `
		SELECT id, email, password_hash, created_at
		FROM users WHERE email = $1
	`, email).Scan(&u.ID, &u.Email, &u.PasswordHash, &u.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return u, nil
}

func (db *DB) GetUserByID(ctx context.Context, id string) (*User, error) {
	u := &User{}
	err := db.QueryRowContext(ctx, `
		SELECT id, email, password_hash, created_at
		FROM users WHERE id = $1
	`, id).Scan(&u.ID, &u.Email, &u.PasswordHash, &u.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return u, nil
}

func (db *DB) UpdateUserPassword(ctx context.Context, id, passwordHash string) error {
	_, err := db.ExecContext(ctx, `
		UPDATE users SET password_hash = $1, updated_at = now() WHERE id = $2
	`, passwordHash, id)
	return err
}
