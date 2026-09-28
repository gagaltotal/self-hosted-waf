package detection

import (
	"bytes"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"strings"
)

// maxBodyInspect caps how many bytes of a request body are ever buffered
// into memory for inspection. Bodies longer than this still get forwarded
// to the upstream in full (see BufferBody) -- only the inspected portion is
// capped, which bounds the WAF's own memory use per request regardless of
// how large an attacker's request body is.
const maxBodyInspect = 2 << 20 // 2 MiB

const maxJSONDepth = 6
const maxJSONStrings = 200

// headersToScan lists the request headers that are inspected. Cookie is
// included because some applications read cookie values directly into
// queries or shell commands; this is a common source of false positives if
// session tokens happen to resemble a pattern, which the score-based
// threshold (rather than single-match blocking) is designed to absorb.
var headersToScan = []string{"User-Agent", "Referer", "Cookie", "X-Forwarded-For", "Content-Type"}

type Finding struct {
	RuleID      string   `json:"rule_id"`
	Category    Category `json:"category"`
	Severity    int      `json:"severity"`
	Location    string   `json:"location"`
	Description string   `json:"description"`
	Snippet     string   `json:"snippet"`
}

type Verdict struct {
	Score    int
	Findings []Finding
	Block    bool
}

// TopCategory returns the category with the highest total severity across
// all findings (not just the single highest-severity finding), so a
// request that trips several path-traversal rules and one incidental
// cross-category rule is still reported under the category it actually
// represents. Ties go to whichever category's first finding appeared
// earliest, which keeps the result deterministic.
func (v *Verdict) TopCategory() Category {
	if len(v.Findings) == 0 {
		return "other"
	}
	sums := map[Category]int{}
	for _, f := range v.Findings {
		sums[f.Category] += f.Severity
	}
	var best Category
	bestScore := -1
	seen := map[Category]bool{}
	for _, f := range v.Findings {
		if seen[f.Category] {
			continue
		}
		seen[f.Category] = true
		if sums[f.Category] > bestScore {
			bestScore = sums[f.Category]
			best = f.Category
		}
	}
	return best
}

func (v *Verdict) RuleIDs() []string {
	ids := make([]string, 0, len(v.Findings))
	for _, f := range v.Findings {
		ids = append(ids, f.RuleID)
	}
	return ids
}

func (v *Verdict) FirstSnippet() string {
	if len(v.Findings) == 0 {
		return ""
	}
	best := v.Findings[0]
	for _, f := range v.Findings {
		if f.Severity > best.Severity {
			best = f
		}
	}
	return best.Snippet
}

type Engine struct {
	rules []Rule
}

func NewEngine(rules []Rule) *Engine {
	return &Engine{rules: rules}
}

// BufferBody reads up to maxBodyInspect bytes of the request body for
// inspection, then reassembles r.Body so the full original body (including
// any bytes beyond the cap) is still available to be forwarded upstream
// afterwards. Must be called before Inspect if the request has a body, and
// works even for bodies far larger than the cap without buffering them
// entirely in memory.
func BufferBody(r *http.Request) ([]byte, error) {
	if r.Body == nil || r.Body == http.NoBody {
		return nil, nil
	}
	original := r.Body
	buf, err := io.ReadAll(io.LimitReader(original, maxBodyInspect))
	if err != nil {
		return nil, err
	}
	r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(buf), original))
	return buf, nil
}

// Inspect runs the full rule set against path, query, headers, and (if
// bodyBuf was captured via BufferBody) the request body, and returns a
// scored verdict. blockThreshold determines Verdict.Block; a single
// SevCritical finding always blocks regardless of threshold.
func (e *Engine) Inspect(r *http.Request, bodyBuf []byte, blockThreshold int) *Verdict {
	v := &Verdict{}

	e.scanField(v, "path", r.URL.Path)

	for name, values := range r.URL.Query() {
		e.scanField(v, "query_name", name)
		for _, val := range values {
			e.scanField(v, "query:"+name, val)
		}
	}

	for _, h := range headersToScan {
		if val := r.Header.Get(h); val != "" {
			e.scanField(v, "header:"+h, val)
		}
	}

	if len(bodyBuf) > 0 {
		e.scanBody(v, r.Header.Get("Content-Type"), bodyBuf)
	}

	for _, f := range v.Findings {
		if f.Severity >= SevCritical {
			v.Block = true
		}
	}
	if v.Score >= blockThreshold {
		v.Block = true
	}
	return v
}

func (e *Engine) scanField(v *Verdict, location, raw string) {
	if raw == "" {
		return
	}
	normalized := Normalize(raw)
	for _, rl := range e.rules {
		if rl.Pattern.MatchString(normalized) {
			v.Score += rl.Severity
			v.Findings = append(v.Findings, Finding{
				RuleID:      rl.ID,
				Category:    rl.Category,
				Severity:    rl.Severity,
				Location:    location,
				Description: rl.Description,
				Snippet:     snippet(raw),
			})
		}
	}
}

func (e *Engine) scanBody(v *Verdict, contentType string, body []byte) {
	mediaType, _, _ := mime.ParseMediaType(contentType)

	switch {
	case strings.Contains(mediaType, "application/json"):
		var parsed any
		if err := json.Unmarshal(body, &parsed); err == nil {
			count := 0
			walkJSON(parsed, "body", 0, &count, func(loc, s string) {
				if count <= maxJSONStrings {
					e.scanField(v, loc, s)
				}
			})
			return
		}
		// Not valid JSON despite the content-type: fall through to raw scan.
		e.scanField(v, "body", string(body))

	case strings.Contains(mediaType, "application/x-www-form-urlencoded"):
		if vals, err := parseFormBody(body); err == nil {
			for name, values := range vals {
				for _, val := range values {
					e.scanField(v, "body:"+name, val)
				}
			}
			return
		}
		e.scanField(v, "body", string(body))

	case strings.Contains(mediaType, "multipart/form-data"):
		// Field values are extracted by the caller when needed (multipart
		// parsing mutates the request more invasively); for the common
		// case we still scan the raw body for obvious payloads in field
		// values while avoiding treating large binary file contents as text.
		if len(body) < 65536 {
			e.scanField(v, "body", string(body))
		}

	default:
		if len(body) > 0 {
			e.scanField(v, "body", string(body))
		}
	}
}

func walkJSON(v any, path string, depth int, count *int, fn func(loc, s string)) {
	if depth > maxJSONDepth || *count > maxJSONStrings {
		return
	}
	switch val := v.(type) {
	case string:
		*count++
		fn(path, val)
	case map[string]any:
		for k, vv := range val {
			walkJSON(vv, path+"."+k, depth+1, count, fn)
		}
	case []any:
		for _, vv := range val {
			walkJSON(vv, path+"[]", depth+1, count, fn)
		}
	}
}

func parseFormBody(body []byte) (map[string][]string, error) {
	req, err := http.NewRequest(http.MethodPost, "http://internal/", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := req.ParseForm(); err != nil {
		return nil, err
	}
	return req.PostForm, nil
}

func snippet(raw string) string {
	s := strings.TrimSpace(raw)
	if len(s) > 160 {
		s = s[:160] + "..."
	}
	return s
}
