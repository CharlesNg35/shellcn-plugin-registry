package registry

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/charlesng35/shellcn/sdk/plugin"
)

const validManifest = `name: demo
repo: github.com/acme/shellcn-plugin-demo
license: MIT
maintainers: [acme]
versions:
  - version: 0.2.0
    assets:
      linux/amd64:
        url: https://github.com/acme/shellcn-plugin-demo/releases/download/v0.2.0/demo-linux-amd64
        sha256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  - version: 0.1.0
    assets:
      linux/amd64:
        url: https://github.com/acme/shellcn-plugin-demo/releases/download/v0.1.0/demo-linux-amd64
        sha256: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
`

func writeManifest(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "demo.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestManifestValidates(t *testing.T) {
	m, err := Load(writeManifest(t, validManifest))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if err := m.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

func TestManifestRejections(t *testing.T) {
	cases := []struct{ name, from, to, want string }{
		{"foreign asset url", "github.com/acme/shellcn-plugin-demo/releases/download/v0.2.0/demo-linux-amd64", "github.com/evil/elsewhere/releases/download/v1/x", "release download of"},
		{"bad sha", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "nothex", "sha256"},
		{"old version first", "version: 0.2.0", "version: 0.0.1", "newest first"},
		{"missing required platform", "linux/amd64:\n        url: https://github.com/acme/shellcn-plugin-demo/releases/download/v0.2.0/demo-linux-amd64", "darwin/arm64:\n        url: https://github.com/acme/shellcn-plugin-demo/releases/download/v0.2.0/demo-linux-amd64", "linux/amd64"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, err := Load(writeManifest(t, strings.Replace(validManifest, tc.from, tc.to, 1)))
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			err = m.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestManifestRejectsUnknownFields(t *testing.T) {
	if _, err := Load(writeManifest(t, validManifest+"\nsurprise: true\n")); err == nil {
		t.Fatal("unknown fields must be rejected")
	}
}

func TestNormalizeIcon(t *testing.T) {
	ok := []plugin.Icon{
		{Type: plugin.IconLucide, Value: "database"},
		{Type: plugin.IconEmoji, Value: "🦀"},
		{Type: plugin.IconSVG, Value: `<svg viewBox="0 0 1 1"><path d="M0 0"/></svg>`},
		{Type: plugin.IconBase64, Value: "data:image/png;base64,aGk="},
		{},
	}
	for _, ic := range ok {
		if _, err := NormalizeIcon(ic); err != nil {
			t.Errorf("icon %v should pass: %v", ic, err)
		}
	}

	bad := []plugin.Icon{
		{Type: plugin.IconURL, Value: "https://example.com/logo.png"},
		{Type: plugin.IconSVG, Value: `<svg onload="alert(1)"/>`},
		{Type: plugin.IconSVG, Value: `<svg><script>alert(1)</script></svg>`},
		{Type: plugin.IconSVG, Value: `<svg><image href="https://x/y.png"/></svg>`},
		{Type: plugin.IconSVG, Value: "<svg>" + strings.Repeat("a", maxSVGBytes) + "</svg>"},
		{Type: plugin.IconBase64, Value: "data:text/html;base64,aGk="},
		{Type: plugin.IconBase64, Value: "data:image/svg+xml;base64," + b64(`<svg onclick="x"/>`)},
	}
	for _, ic := range bad {
		if _, err := NormalizeIcon(ic); err == nil {
			t.Errorf("icon %.60v should be rejected", ic.Value)
		}
	}
}

func b64(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

func TestBuildIndexSkipsUnsnapshotted(t *testing.T) {
	m, err := Load(writeManifest(t, validManifest))
	if err != nil {
		t.Fatal(err)
	}
	snaps := t.TempDir()
	if err := WriteSnapshot(snaps, &Snapshot{
		Name: "demo", Version: "0.2.0", APIVersion: 1, ProtocolVersion: 1,
		Icon:       plugin.Icon{Type: plugin.IconLucide, Value: "box"},
		Projection: plugin.Projection{Title: "Demo", Description: "A demo plugin."},
	}); err != nil {
		t.Fatal(err)
	}

	idx, skipped, err := BuildIndex([]*Manifest{m}, snaps, "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(skipped) != 1 || !strings.Contains(skipped[0], "0.1.0") {
		t.Fatalf("0.1.0 should be skipped (no snapshot): %v", skipped)
	}
	if len(idx.Plugins) != 1 || len(idx.Plugins[0].Versions) != 1 {
		t.Fatalf("index shape: %+v", idx.Plugins)
	}
	if idx.Plugins[0].DisplayName != "Demo" || idx.Plugins[0].Description != "A demo plugin." {
		t.Fatalf("index metadata should come from snapshot: %+v", idx.Plugins[0])
	}
	urls := idx.Plugins[0].Versions[0].Assets["linux/amd64"].URLs
	if len(urls) != 2 ||
		urls[0] != "https://github.com/CharlesNg35/shellcn-plugin-registry/releases/download/demo-v0.2.0/demo-linux-amd64" ||
		!strings.Contains(urls[1], "acme/shellcn-plugin-demo") {
		t.Fatalf("urls must be [mirror, upstream]: %v", urls)
	}
}

func TestBuildIndexSkipsStaleSnapshot(t *testing.T) {
	m, err := Load(writeManifest(t, validManifest))
	if err != nil {
		t.Fatal(err)
	}
	snaps := t.TempDir()
	if err := os.WriteFile(
		SnapshotPath(snaps, "demo", "0.2.0"),
		[]byte(`{"name":"demo","version":"0.2.0","projection":{"actions":[{"id":"config","config":{}}]}}`),
		0o644,
	); err != nil {
		t.Fatal(err)
	}

	idx, skipped, err := BuildIndex([]*Manifest{m}, snaps, "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(idx.Plugins) != 0 {
		t.Fatalf("stale snapshot should not produce an installable entry: %+v", idx.Plugins)
	}
	if len(skipped) != 2 || !strings.Contains(skipped[0], "stale snapshot") {
		t.Fatalf("stale snapshot should be reported as skipped: %v", skipped)
	}
}

func TestWriteSnapshotCreatesDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "snapshots")
	if err := WriteSnapshot(dir, &Snapshot{
		Name: "demo", Version: "0.2.0", APIVersion: 1, ProtocolVersion: 1,
		Projection: plugin.Projection{Title: "Demo"},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(SnapshotPath(dir, "demo", "0.2.0")); err != nil {
		t.Fatal(err)
	}
}
