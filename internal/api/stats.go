package api

import (
	"net/http"
	"strconv"
	"time"
)

func (s *Server) handleStatsSummary(w http.ResponseWriter, r *http.Request) {
	hours := 24
	if v := r.URL.Query().Get("hours"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 24*30 {
			hours = n
		}
	}
	since := time.Now().Add(-time.Duration(hours) * time.Hour)

	summary, err := s.db.GetStatsSummary(r.Context(), since)
	if err != nil {
		s.log.Error("stats summary failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not compute stats")
		return
	}
	writeJSON(w, http.StatusOK, summary)
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":           true,
		"sites_loaded": s.registry.Count(),
	})
}
