package main

import (
	"strings"
	"testing"
)

func TestSplitCodeAndComment(t *testing.T) {
	line := `server: "example.com#keep" # tail`
	code, comment := splitCodeAndComment(line)
	if code != `server: "example.com#keep" ` {
		t.Fatalf("unexpected code: %q", code)
	}
	if comment != "# tail" {
		t.Fatalf("unexpected comment: %q", comment)
	}
}

func TestMaskAndUnmaskRoundTrip(t *testing.T) {
	original := strings.Join([]string{
		"# comment server: real.example.com",
		`proxies:`,
		`  - {name: "node-1", server: real.example.com, port: 443, password: "abc123"} # keep comment real.example.com`,
		`  - {"server":"1.2.3.4","uuid":"1111-2222","sni":"edge.example.com"}`,
		`  - url: trojan://myPassword@proxy.example.com:443#tag`,
		"",
	}, "\n")

	s, err := NewSanitizer(Config{})
	if err != nil {
		t.Fatal(err)
	}
	masked := s.MaskText(original)
	if strings.Contains(masked, `, server: real.example.com,`) {
		t.Fatalf("host should be replaced in code: %q", masked)
	}
	if !strings.Contains(masked, `# keep comment real.example.com`) {
		t.Fatalf("tail comment should be preserved: %q", masked)
	}
	if strings.Contains(masked, "abc123") {
		t.Fatalf("password should be replaced")
	}
	if !strings.Contains(masked, "__CLASHMASK_HOST_") {
		t.Fatalf("expected host token in output")
	}
	if !strings.Contains(masked, "__CLASHMASK_SECRET_") {
		t.Fatalf("expected secret token in output")
	}

	restored := UnmaskText(masked, s.ExportMap())
	if restored != original {
		t.Fatalf("round trip mismatch\n--- original ---\n%s\n--- restored ---\n%s", original, restored)
	}
}
