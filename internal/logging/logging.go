// Package logging configures structured (JSON) logging for the whole
// process. Using structured logs means attack events and admin actions can
// be shipped to any external log pipeline / SIEM for retention and
// alerting, which matters because the database is not a substitute for
// tamper-resistant audit history.
package logging

import (
	"log/slog"
	"os"
	"strings"
)

func New(level string) *slog.Logger {
	var lvl slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn", "warning":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}

	h := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: lvl,
	})
	logger := slog.New(h)
	slog.SetDefault(logger)
	return logger
}
