package api

import (
	"net/http"
	"strconv"
	"time"

	"waf/internal/store"
)

func (s *Server) handleListLogs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.LogFilter{
		SiteID:   q.Get("site_id"),
		Category: q.Get("category"),
		Action:   q.Get("action"),
		ClientIP: q.Get("client_ip"),
	}
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			f.Limit = n
		}
	}
	if v := q.Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			f.Offset = n
		}
	}
	if v := q.Get("since"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			f.Since = &t
		}
	}
	if v := q.Get("until"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			f.Until = &t
		}
	}

	logs, total, err := s.db.ListAttackLogs(r.Context(), f)
	if err != nil {
		s.log.Error("list attack logs failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not list logs")
		return
	}
	if logs == nil {
		logs = []*store.AttackLog{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"logs": logs, "total": total})
}
