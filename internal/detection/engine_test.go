package detection

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// qtarget builds a properly-encoded "path?param=value" target from a raw
// attack payload, since a real HTTP client would always percent-encode
// characters like spaces and angle brackets before putting them on the
// wire -- httptest.NewRequest (like http.NewRequest) rejects a raw,
// un-encoded space in the request target, exactly as a real server would
// never see one either.
func qtarget(path, param, rawValue string) string {
	return path + "?" + param + "=" + url.QueryEscape(rawValue)
}

func newEngine() *Engine {
	return NewEngine(DefaultRules)
}

func req(method, target string, body string, contentType string) *http.Request {
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, target, strings.NewReader(body))
	} else {
		r = httptest.NewRequest(method, target, nil)
	}
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	r.Header.Set("User-Agent", "Mozilla/5.0 (test)")
	return r
}

func TestDetectsSQLInjectionInQuery(t *testing.T) {
	e := newEngine()
	r := req(http.MethodGet, qtarget("/products", "id", "1' OR '1'='1"), "", "")
	v := e.Inspect(r, nil, 7)
	if !v.Block {
		t.Fatalf("expected classic tautology SQLi to be blocked, score=%d findings=%v", v.Score, v.Findings)
	}
	if v.TopCategory() != CategorySQLi {
		t.Errorf("expected category sqli, got %s", v.TopCategory())
	}
}

func TestDetectsUnionSelect(t *testing.T) {
	e := newEngine()
	r := req(http.MethodGet, qtarget("/products", "id", "1 UNION SELECT username,password FROM users--"), "", "")
	v := e.Inspect(r, nil, 7)
	if !v.Block {
		t.Fatalf("expected UNION SELECT to be blocked, score=%d", v.Score)
	}
}

func TestDetectsStackedQueryAlwaysBlocks(t *testing.T) {
	e := newEngine()
	r := req(http.MethodGet, qtarget("/products", "id", "1; DROP TABLE users;--"), "", "")
	// Even with a very high threshold, a critical finding alone must block.
	v := e.Inspect(r, nil, 1000)
	if !v.Block {
		t.Fatalf("expected stacked-query DROP TABLE to always block regardless of threshold")
	}
}

func TestDetectsXSSScriptTag(t *testing.T) {
	e := newEngine()
	r := req(http.MethodGet, qtarget("/search", "q", "<script>alert(document.cookie)</script>"), "", "")
	v := e.Inspect(r, nil, 7)
	if !v.Block {
		t.Fatalf("expected <script> XSS payload to be blocked, score=%d", v.Score)
	}
	if v.TopCategory() != CategoryXSS {
		t.Errorf("expected category xss, got %s", v.TopCategory())
	}
}

func TestDetectsImgOnErrorXSS(t *testing.T) {
	e := newEngine()
	r := req(http.MethodGet, qtarget("/comment", "text", `<img src=x onerror=alert(1)>`), "", "")
	v := e.Inspect(r, nil, 7)
	if !v.Block {
		t.Fatalf("expected img onerror XSS to be blocked, score=%d", v.Score)
	}
}

func TestDetectsCommandInjection(t *testing.T) {
	e := newEngine()
	r := req(http.MethodGet, qtarget("/ping", "host", "127.0.0.1;cat /etc/passwd"), "", "")
	v := e.Inspect(r, nil, 7)
	if !v.Block {
		t.Fatalf("expected command injection to be blocked, score=%d findings=%v", v.Score, v.Findings)
	}
}

func TestDetectsPathTraversal(t *testing.T) {
	e := newEngine()
	r := req(http.MethodGet, "/files?name=../../../../etc/passwd", "", "")
	v := e.Inspect(r, nil, 7)
	if !v.Block {
		t.Fatalf("expected path traversal to be blocked, score=%d", v.Score)
	}
	// Regression test: this payload also matches a cmdi-tagged "sensitive
	// file reference" rule (/etc/passwd), which previously caused it to be
	// mis-reported as category "cmdi" because two path-traversal-specific
	// rules split the signal while the single cmdi rule "won" on a
	// first-found tie-break. It should be attributed to path_traversal,
	// which is what the request actually is.
	if v.TopCategory() != CategoryPathTraversal {
		t.Errorf("expected category path_traversal, got %s (findings=%v)", v.TopCategory(), v.Findings)
	}
}

func TestDetectsDoubleEncodedTraversal(t *testing.T) {
	e := newEngine()
	// %252e%252e%252f decodes (after Go's automatic first pass turns this
	// into %2e%2e%2f) to ../ on our second normalization pass.
	r := req(http.MethodGet, "/files?name=%252e%252e%252fetc%252fpasswd", "", "")
	v := e.Inspect(r, nil, 7)
	if v.Score == 0 {
		t.Fatalf("expected double-encoded traversal to score at least something, got 0")
	}
}

func TestDetectsSQLiInJSONBody(t *testing.T) {
	e := newEngine()
	body := `{"username": "admin' OR '1'='1", "password": "x"}`
	r := req(http.MethodPost, "/api/login", body, "application/json")
	buf, err := BufferBody(r)
	if err != nil {
		t.Fatal(err)
	}
	v := e.Inspect(r, buf, 7)
	if !v.Block {
		t.Fatalf("expected SQLi inside JSON body to be blocked, score=%d", v.Score)
	}
}

func TestDetectsCmdiInFormBody(t *testing.T) {
	e := newEngine()
	body := "host=example.com%3Bwhoami"
	r := req(http.MethodPost, "/tools/ping", body, "application/x-www-form-urlencoded")
	buf, err := BufferBody(r)
	if err != nil {
		t.Fatal(err)
	}
	v := e.Inspect(r, buf, 7)
	if !v.Block {
		t.Fatalf("expected command injection in form body to be blocked, score=%d", v.Score)
	}
}

// --- False positive guardrails: normal traffic must pass cleanly ---------

func TestAllowsNormalSearchQuery(t *testing.T) {
	e := newEngine()
	r := req(http.MethodGet, "/search?q=best+running+shoes+for+flat+feet", "", "")
	v := e.Inspect(r, nil, 7)
	if v.Block {
		t.Fatalf("normal search query should not be blocked, findings=%v", v.Findings)
	}
}

func TestAllowsNormalJSONBody(t *testing.T) {
	e := newEngine()
	body := `{"name": "Budi Santoso", "email": "budi@example.com", "message": "Saya tertarik dengan produk Anda."}`
	r := req(http.MethodPost, "/api/contact", body, "application/json")
	buf, _ := BufferBody(r)
	v := e.Inspect(r, buf, 7)
	if v.Block {
		t.Fatalf("normal contact form JSON should not be blocked, findings=%v", v.Findings)
	}
}

func TestAllowsNormalLoginForm(t *testing.T) {
	e := newEngine()
	body := "email=user%40example.com&password=Tr0ub4dor%263"
	r := req(http.MethodPost, "/login", body, "application/x-www-form-urlencoded")
	buf, _ := BufferBody(r)
	v := e.Inspect(r, buf, 7)
	if v.Block {
		t.Fatalf("normal login form should not be blocked, findings=%v", v.Findings)
	}
}

func TestBodyBufferingPreservesFullBodyForForwarding(t *testing.T) {
	e := newEngine()
	_ = e
	body := strings.Repeat("a", 5<<20) // 5 MiB, larger than maxBodyInspect (2 MiB)
	r := req(http.MethodPost, "/upload", body, "text/plain")

	buf, err := BufferBody(r)
	if err != nil {
		t.Fatal(err)
	}
	if len(buf) != maxBodyInspect {
		t.Fatalf("expected inspected buffer capped at %d bytes, got %d", maxBodyInspect, len(buf))
	}

	// The reassembled r.Body must still yield the FULL original body when
	// read, since that is what gets forwarded to the upstream.
	full, err := readAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if len(full) != len(body) {
		t.Fatalf("expected forwarded body to be full %d bytes, got %d", len(body), len(full))
	}
}

func readAll(r *http.Request) ([]byte, error) {
	defer r.Body.Close()
	buf := make([]byte, 0, 6<<20)
	tmp := make([]byte, 32*1024)
	for {
		n, err := r.Body.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if err != nil {
			break
		}
	}
	return buf, nil
}
