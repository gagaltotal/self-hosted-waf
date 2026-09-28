package proxy

import (
	"context"
	"log/slog"
	"time"

	"waf/internal/store"
)

const (
	logQueueSize    = 2000
	logQueueWorkers = 4
)

// logQueue decouples "we found something worth recording" from the actual
// Postgres write. Under a heavy attack burst, many findings can happen per
// second; writing them inline on the request path would tie response
// latency (and therefore the WAF's own availability) to database write
// throughput. If the queue is ever full, new entries are dropped with a
// warning rather than blocking -- losing a few log rows under extreme load
// is preferable to the logging pipeline becoming the bottleneck that takes
// protected sites down.
type logQueue struct {
	db    *store.DB
	log   *slog.Logger
	items chan store.AttackLog
}

func newLogQueue(db *store.DB, log *slog.Logger) *logQueue {
	q := &logQueue{
		db:    db,
		log:   log,
		items: make(chan store.AttackLog, logQueueSize),
	}
	for i := 0; i < logQueueWorkers; i++ {
		go q.worker()
	}
	return q
}

func (q *logQueue) worker() {
	for entry := range q.items {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := q.db.InsertAttackLog(ctx, entry); err != nil {
			q.log.Warn("failed to persist attack log", "error", err, "site_id", entry.SiteID)
		}
		cancel()
	}
}

func (q *logQueue) Enqueue(entry store.AttackLog) {
	select {
	case q.items <- entry:
	default:
		q.log.Warn("attack log queue full, dropping entry",
			"site_id", entry.SiteID, "category", entry.Category, "action", entry.Action)
	}
}
