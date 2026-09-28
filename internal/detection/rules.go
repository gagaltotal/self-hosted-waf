package detection

import "regexp"

type Category string

const (
	CategorySQLi          Category = "sqli"
	CategoryXSS           Category = "xss"
	CategoryCmdInjection  Category = "cmdi"
	CategoryPathTraversal Category = "path_traversal"
)

// Severity points, matched against a site's block_threshold (default 7):
//   - A single "high" finding blocks on its own (7 >= 7): these patterns
//     are specific enough (e.g. a literal quote glued to a SQL tautology,
//     a <script> tag, an img onerror=) to rarely if ever appear in
//     legitimate traffic.
//   - "medium" findings are more ambiguous alone (e.g. the bare word
//     "information_schema", an unquoted "1=1") and need to combine with
//     another finding to cross the threshold, which absorbs the occasional
//     coincidental match without ignoring a real multi-signal attack.
//   - A single "critical" finding always blocks regardless of threshold
//     (see Verdict in engine.go), because these have essentially no
//     legitimate use at all (e.g. a stacked "; DROP TABLE").
const (
	SevLow      = 3
	SevMedium   = 5
	SevHigh     = 7
	SevCritical = 10
)

type Rule struct {
	ID          string
	Category    Category
	Severity    int
	Pattern     *regexp.Regexp
	Description string
}

func rule(id string, cat Category, sev int, pattern, desc string) Rule {
	return Rule{
		ID:          id,
		Category:    cat,
		Severity:    sev,
		Pattern:     regexp.MustCompile(pattern),
		Description: desc,
	}
}

// DefaultRules returns the built-in signature set. All patterns are matched
// against normalized (lowercased, decoded) input, so patterns here are
// written in lowercase and don't need (?i).
var DefaultRules = []Rule{
	// --- SQL injection -----------------------------------------------
	rule("sqli-001", CategorySQLi, SevHigh, `union\s+(all\s+)?select`, "UNION-based SQL injection"),
	rule("sqli-002", CategorySQLi, SevHigh, `'\s*or\s*'?\d+'?\s*=\s*'?\d+`, "Classic quoted tautology (' or '1'='1)"),
	rule("sqli-003", CategorySQLi, SevMedium, `\bor\b\s+\d+\s*=\s*\d+\b`, "Numeric tautology (or 1=1)"),
	rule("sqli-004", CategorySQLi, SevMedium, `\band\b\s+\d+\s*=\s*\d+\b`, "Numeric tautology (and 1=1)"),
	rule("sqli-005", CategorySQLi, SevCritical, `;\s*(drop|alter|truncate|insert|update|delete)\s`, "Stacked query with DDL/DML"),
	rule("sqli-006", CategorySQLi, SevMedium, `'\s*(--|#)`, "Quote followed by comment terminator"),
	rule("sqli-007", CategorySQLi, SevHigh, `\b(sleep|benchmark|pg_sleep)\s*\(`, "Time-based blind SQLi function"),
	rule("sqli-008", CategorySQLi, SevHigh, `waitfor\s+delay\s+'`, "MSSQL time-based blind SQLi"),
	rule("sqli-009", CategorySQLi, SevMedium, `\b(information_schema|sysobjects|syscolumns|pg_catalog)\b`, "Database metadata reconnaissance"),
	rule("sqli-010", CategorySQLi, SevCritical, `\b(load_file|into\s+outfile|into\s+dumpfile|xp_cmdshell)\b`, "Dangerous SQL function (file/command access)"),
	rule("sqli-011", CategorySQLi, SevLow, `0x[0-9a-f]{8,}`, "Long hex literal (common SQLi encoding)"),
	rule("sqli-012", CategorySQLi, SevMedium, `['"]\s*;\s*--`, "Quote + statement terminator + comment"),
	rule("sqli-013", CategorySQLi, SevLow, `\bcast\s*\(.{0,40}\bas\b`, "Type cast, often used in blind SQLi extraction"),
	rule("sqli-014", CategorySQLi, SevMedium, `\bselect\b.{0,80}\bfrom\b.{0,80}\bwhere\b`, "Inline SELECT...FROM...WHERE"),

	// --- Cross-site scripting -----------------------------------------
	rule("xss-001", CategoryXSS, SevHigh, `<\s*script\b`, "<script> tag"),
	rule("xss-002", CategoryXSS, SevHigh, `\bon(load|error|click|mouseover|mouseout|focus|blur|change|submit|keyup|keydown|pointerdown)\s*=`, "Inline JS event handler attribute"),
	rule("xss-003", CategoryXSS, SevHigh, `javascript\s*:`, "javascript: URI scheme"),
	rule("xss-004", CategoryXSS, SevMedium, `<\s*(iframe|object|embed)\b`, "Embeddable content tag"),
	rule("xss-005", CategoryXSS, SevHigh, `<\s*img[^>]{0,80}onerror`, "<img onerror=...> payload"),
	rule("xss-006", CategoryXSS, SevMedium, `document\s*\.\s*(cookie|location|write|domain)`, "DOM cookie/location/write access"),
	rule("xss-007", CategoryXSS, SevMedium, `\b(eval|settimeout|setinterval)\s*\(`, "Dynamic JS execution function"),
	rule("xss-008", CategoryXSS, SevHigh, `<\s*svg[^>]{0,80}onload`, "<svg onload=...> payload"),
	rule("xss-009", CategoryXSS, SevMedium, `data\s*:\s*text/html`, "data: URI HTML injection"),
	rule("xss-010", CategoryXSS, SevLow, `string\.fromcharcode`, "String.fromCharCode obfuscation"),
	rule("xss-011", CategoryXSS, SevMedium, `expression\s*\(`, "CSS expression() injection (legacy IE)"),
	rule("xss-012", CategoryXSS, SevMedium, `<\s*/?\s*(script|iframe|svg|img)[^>]*>`, "Suspicious raw HTML tag in input"),

	// --- Command injection ---------------------------------------------
	rule("cmdi-001", CategoryCmdInjection, SevHigh, `[;&|]{1,2}\s*(ls|cat|whoami|id|uname|pwd|wget|curl|nc|ncat|bash|sh|python[0-9.]*|perl|chmod|rm|kill|ps|netstat|ifconfig|ipconfig)\b`, "Shell metachar followed by common command"),
	rule("cmdi-002", CategoryCmdInjection, SevHigh, `\$\([^)]{0,120}\)`, "Command substitution $(...)"),
	rule("cmdi-003", CategoryCmdInjection, SevMedium, "`[^`]{1,120}`", "Backtick command substitution"),
	rule("cmdi-004", CategoryCmdInjection, SevHigh, `/etc/(passwd|shadow|hosts)\b`, "Sensitive *nix file reference"),
	rule("cmdi-005", CategoryCmdInjection, SevHigh, `\b(cmd\.exe|powershell(\.exe)?)\b`, "Windows shell invocation"),
	rule("cmdi-006", CategoryCmdInjection, SevLow, `%00`, "NUL byte injection"),
	rule("cmdi-007", CategoryCmdInjection, SevHigh, `\b(nc|netcat|ncat)\s+-`, "Netcat invocation with flags"),
	rule("cmdi-008", CategoryCmdInjection, SevCritical, `base64\s+-d[^|]{0,20}\|\s*(ba)?sh\b`, "Base64-decode piped to shell (RCE pattern)"),
	rule("cmdi-009", CategoryCmdInjection, SevMedium, `\|\s*(tee|xargs)\b`, "Pipe into command chaining tool"),

	// --- Path traversal --------------------------------------------------
	rule("path-001", CategoryPathTraversal, SevMedium, `\.\./`, "Directory traversal sequence (../)"),
	rule("path-002", CategoryPathTraversal, SevMedium, `\.\.\\`, "Directory traversal sequence (..\\)"),
	rule("path-003", CategoryPathTraversal, SevHigh, `%2e%2e(%2f|%5c)`, "Percent-encoded traversal sequence"),
	rule("path-004", CategoryPathTraversal, SevHigh, `%252e%252e`, "Double percent-encoded traversal sequence"),
	rule("path-005", CategoryPathTraversal, SevHigh, `(\.\./){2,}etc/passwd`, "Traversal chain targeting /etc/passwd"),
	rule("path-006", CategoryPathTraversal, SevMedium, `\.\.%00`, "Traversal with NUL-byte suffix"),
}
