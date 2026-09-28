package challenge

import (
	"bytes"
	"strings"
	"testing"
)

func TestRenderPoWPageProducesValidOutput(t *testing.T) {
	var buf bytes.Buffer
	err := RenderPoWPage(&buf, "test-nonce-value", "signed.token.value", 16, "/.waf-internal/challenge/verify")
	if err != nil {
		t.Fatalf("RenderPoWPage returned error: %v", err)
	}
	out := buf.String()

	if strings.Contains(out, "{{") {
		t.Fatalf("output still contains unrendered template markers:\n%s", out)
	}
	mustContain := []string{
		"<html", "sha256Hex", "test-nonce-value", "signed.token.value",
		"/.waf-internal/challenge/verify", "<style>", "border-radius",
	}
	for _, s := range mustContain {
		if !strings.Contains(out, s) {
			t.Errorf("expected rendered page to contain %q, it did not", s)
		}
	}
	// The CSS must actually have been inlined, not left as a dangling
	// reference -- this is exactly the class of bug the earlier
	// placeholder mistake introduced.
	if strings.Contains(out, "<style></style>") {
		t.Fatal("style tag is empty: CSS was not inlined")
	}
}

func TestRenderTurnstilePageProducesValidOutput(t *testing.T) {
	var buf bytes.Buffer
	err := RenderTurnstilePage(&buf, "0x4AAAsitekey", "signed.token.value", "/.waf-internal/challenge/verify")
	if err != nil {
		t.Fatalf("RenderTurnstilePage returned error: %v", err)
	}
	out := buf.String()

	if strings.Contains(out, "{{") {
		t.Fatalf("output still contains unrendered template markers:\n%s", out)
	}
	mustContain := []string{
		"<html", "0x4AAAsitekey", "signed.token.value", "turnstile",
		"waf-internal", "challenge", "<style>", "border-radius",
	}
	for _, s := range mustContain {
		if !strings.Contains(out, s) {
			t.Errorf("expected rendered page to contain %q, it did not", s)
		}
	}
	if strings.Contains(out, "<style></style>") {
		t.Fatal("style tag is empty: CSS was not inlined")
	}
}
