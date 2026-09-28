// Package webui embeds the compiled dashboard (built by Vite into web/dist,
// copied here as internal/webui/dist during the Docker build) directly
// into the Go binary. This means deploying the whole product -- reverse
// proxy, admin API, and dashboard -- is a single static binary plus its
// Postgres/Redis dependencies, with no separate web server or static file
// host required for the UI.
package webui

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed dist
var distFS embed.FS

// Handler serves the embedded static assets, falling back to index.html
// for any path that doesn't match a real file. That fallback is what lets
// client-side routes (e.g. /sites, /logs) work correctly on a hard refresh
// or direct link, since the server has no route table of its own to
// consult -- it defers entirely to the SPA's own router once loaded.
func Handler() (http.Handler, error) {
	sub, err := fs.Sub(distFS, "dist")
	if err != nil {
		return nil, err
	}
	fileServer := http.FileServer(http.FS(sub))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")

		cleanPath := strings.TrimPrefix(r.URL.Path, "/")
		if cleanPath == "" {
			cleanPath = "index.html"
		}
		if _, err := fs.Stat(sub, cleanPath); err != nil {
			// No such static asset: hand the SPA's router an index.html to
			// interpret the path client-side, rather than returning a bare 404.
			r2 := new(http.Request)
			*r2 = *r
			r2.URL.Path = "/"
			fileServer.ServeHTTP(w, r2)
			return
		}
		fileServer.ServeHTTP(w, r)
	}), nil
}
