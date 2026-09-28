package challenge

import (
	_ "embed"
	"encoding/json"
	"html/template"
	"io"
)

//go:embed assets/sha256.js
var sha256JS string

var powPageTmpl = template.Must(template.New("pow").Parse(powPageHTML))
var turnstilePageTmpl = template.Must(template.New("turnstile").Parse(turnstilePageHTML))

type powPageData struct {
	Nonce      string
	Token      string
	Difficulty int
	VerifyPath string
	SHA256JS   template.JS
	DataJSON   template.JS
}

func RenderPoWPage(w io.Writer, nonce, token string, difficulty int, verifyPath string) error {
	dataJSON, err := json.Marshal(map[string]any{
		"nonce":      nonce,
		"token":      token,
		"difficulty": difficulty,
		"verifyPath": verifyPath,
	})
	if err != nil {
		return err
	}
	return powPageTmpl.Execute(w, powPageData{
		Nonce:      nonce,
		Token:      token,
		Difficulty: difficulty,
		VerifyPath: verifyPath,
		SHA256JS:   template.JS(sha256JS),
		DataJSON:   template.JS(dataJSON),
	})
}

type turnstilePageData struct {
	SiteKey    string
	Token      string
	VerifyPath string
}

func RenderTurnstilePage(w io.Writer, siteKey, token, verifyPath string) error {
	return turnstilePageTmpl.Execute(w, turnstilePageData{
		SiteKey:    siteKey,
		Token:      token,
		VerifyPath: verifyPath,
	})
}

const pageStyle = `
  :root{color-scheme:light dark;--bg:#0b0e14;--card:#141922;--text:#e6e9ef;--muted:#8b93a3;--accent:#4f8cff}
  *{box-sizing:border-box}
  body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
       font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
       background:var(--bg);color:var(--text);padding:24px}
  .card{max-width:420px;width:100%;background:var(--card);border-radius:16px;padding:36px 32px;
        box-shadow:0 10px 40px rgba(0,0,0,.35);text-align:center}
  .spinner{width:40px;height:40px;margin:0 auto 20px;border-radius:50%;
           border:3px solid rgba(79,140,255,.25);border-top-color:var(--accent);
           animation:spin .8s linear infinite}
  @keyframes spin{to{transform:rotate(360deg)}}
  h1{font-size:17px;font-weight:600;margin:0 0 8px}
  p{color:var(--muted);font-size:14px;line-height:1.5;margin:0 0 4px}
  .status{margin-top:18px;font-size:13px;color:var(--muted);min-height:18px}
  .err{color:#ff6b6b}
  footer{margin-top:22px;font-size:11px;color:var(--muted);opacity:.7}
`

const powPageHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Verifying your browser…</title>
<style>` + pageStyle + `</style>
</head>
<body>
<div class="card">
  <div class="spinner" aria-hidden="true"></div>
  <h1>Verifying your browser…</h1>
  <p>This automated check helps protect the site from bots and abusive traffic. It should only take a moment.</p>
  <div class="status" id="status">Starting check…</div>
  <footer>Protected by a self-hosted WAF</footer>
</div>
<script>{{.SHA256JS}}</script>
<script>
(function () {
  var DATA = {{.DataJSON}};
  var statusEl = document.getElementById('status');

  function leadingZeroBits(hex) {
    var count = 0;
    for (var i = 0; i < hex.length; i++) {
      var nibble = parseInt(hex[i], 16);
      if (nibble === 0) { count += 4; continue; }
      if (nibble < 2) return count + 3;
      if (nibble < 4) return count + 2;
      if (nibble < 8) return count + 1;
      return count;
    }
    return count;
  }

  function solve(nonce, difficulty, onDone) {
    var counter = 0;
    var startedAt = Date.now();
    function step() {
      var batchEnd = counter + 4000;
      for (; counter < batchEnd; counter++) {
        var h = sha256Hex(nonce + ':' + counter);
        if (leadingZeroBits(h) >= difficulty) {
          onDone(String(counter), Date.now() - startedAt);
          return;
        }
      }
      statusEl.textContent = 'Checking… (' + counter.toLocaleString() + ' attempts)';
      setTimeout(step, 0); // yield to keep the tab responsive
    }
    step();
  }

  function submit(counter) {
    statusEl.textContent = 'Almost there…';
    fetch(DATA.verifyPath, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      credentials: 'same-origin',
      body: JSON.stringify({token: DATA.token, counter: counter})
    }).then(function (res) { return res.json().then(function (body) { return {ok: res.ok, body: body}; }); })
      .then(function (result) {
        if (result.ok && result.body && result.body.ok) {
          statusEl.textContent = 'Verified. Redirecting…';
          window.location.reload();
        } else {
          statusEl.innerHTML = '<span class="err">Verification failed. Refresh the page to try again.</span>';
        }
      })
      .catch(function () {
        statusEl.innerHTML = '<span class="err">Network error. Refresh the page to try again.</span>';
      });
  }

  if (typeof sha256Hex !== 'function') {
    statusEl.innerHTML = '<span class="err">Your browser could not run this check.</span>';
  } else {
    solve(DATA.nonce, DATA.difficulty, function (counter) { submit(counter); });
  }
})();
</script>
</body>
</html>
`

const turnstilePageHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Verifying your browser…</title>
<style>` + pageStyle + `</style>
<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
</head>
<body>
<div class="card">
  <h1>Verifying your browser…</h1>
  <p>Please complete the check below to continue.</p>
  <div class="cf-turnstile" data-sitekey="{{.SiteKey}}" data-callback="onTurnstileSuccess"></div>
  <div class="status" id="status"></div>
  <footer>Protected by a self-hosted WAF</footer>
</div>
<script>
function onTurnstileSuccess(responseToken) {
  document.getElementById('status').textContent = 'Verifying…';
  fetch("{{.VerifyPath}}", {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    credentials: 'same-origin',
    body: JSON.stringify({token: "{{.Token}}", turnstileResponse: responseToken})
  }).then(function (res) { return res.json().then(function (body) { return {ok: res.ok, body: body}; }); })
    .then(function (result) {
      if (result.ok && result.body && result.body.ok) {
        window.location.reload();
      } else {
        document.getElementById('status').textContent = 'Verification failed. Please try again.';
      }
    })
    .catch(function () {
      document.getElementById('status').textContent = 'Network error. Please try again.';
    });
}
</script>
</body>
</html>
`
