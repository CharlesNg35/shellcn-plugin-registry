// Package registry implements the shellcn-plugin-registry index tooling: manifest
// validation, asset verification, binary inspection, and index generation.
package registry

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/mod/semver"
	"gopkg.in/yaml.v3"
)

// Platforms the registry accepts, matching what the gateway can run.
var allowedPlatforms = map[string]bool{
	"linux/amd64": true, "linux/arm64": true,
	"darwin/amd64": true, "darwin/arm64": true,
	"windows/amd64": true, "windows/arm64": true,
}

// RequiredPlatform is the platform CI inspects, so every plugin must ship it.
const RequiredPlatform = "linux/amd64"

var (
	nameRe   = regexp.MustCompile(`^[a-z][a-z0-9-]{1,40}$`)
	sha256Re = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

// Asset is one downloadable binary for a platform.
type Asset struct {
	URL    string `yaml:"url" json:"-"`
	SHA256 string `yaml:"sha256" json:"sha256"`
}

// Version is one released plugin version.
type Version struct {
	Version string           `yaml:"version" json:"version"`
	Yanked  bool             `yaml:"yanked,omitempty" json:"yanked,omitempty"`
	Assets  map[string]Asset `yaml:"assets" json:"-"`
}

// Manifest is one plugins/<name>.yaml registry entry.
type Manifest struct {
	Name        string    `yaml:"name" json:"name"`
	Repo        string    `yaml:"repo" json:"repo"`
	Homepage    string    `yaml:"homepage,omitempty" json:"homepage,omitempty"`
	License     string    `yaml:"license" json:"license"`
	Maintainers []string  `yaml:"maintainers" json:"maintainers"`
	Versions    []Version `yaml:"versions" json:"versions"`
}

// Load reads and strictly decodes one manifest file.
func Load(path string) (*Manifest, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	var m Manifest
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if base := strings.TrimSuffix(filepath.Base(path), ".yaml"); base != m.Name {
		return nil, fmt.Errorf("%s: file name must match plugin name %q", path, m.Name)
	}
	return &m, nil
}

// LoadAll reads every manifest in dir, sorted by name.
func LoadAll(dir string) ([]*Manifest, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)
	out := make([]*Manifest, 0, len(paths))
	for _, p := range paths {
		m, err := Load(p)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, nil
}

// Validate checks one manifest's structure and policies.
func (m *Manifest) Validate() error {
	var errs []string
	add := func(format string, args ...any) { errs = append(errs, fmt.Sprintf(format, args...)) }

	if !nameRe.MatchString(m.Name) {
		add("name %q must match %s", m.Name, nameRe)
	}
	if !strings.HasPrefix(m.Repo, "github.com/") || strings.Count(m.Repo, "/") != 2 {
		add("repo %q must be github.com/<owner>/<name>", m.Repo)
	}
	if strings.TrimSpace(m.License) == "" {
		add("license is required")
	}
	if len(m.Maintainers) == 0 {
		add("at least one maintainer (GitHub handle) is required")
	}
	if len(m.Versions) == 0 {
		add("at least one version is required")
	}

	seen := map[string]bool{}
	for i, v := range m.Versions {
		ctx := fmt.Sprintf("versions[%d] (%s)", i, v.Version)
		if !semver.IsValid("v" + v.Version) {
			add("%s: version must be semver without the v prefix", ctx)
		}
		if seen[v.Version] {
			add("%s: duplicate version", ctx)
		}
		seen[v.Version] = true
		if _, ok := v.Assets[RequiredPlatform]; !ok {
			add("%s: an asset for %s is required (CI inspects it)", ctx, RequiredPlatform)
		}
		for platform, a := range v.Assets {
			if !allowedPlatforms[platform] {
				add("%s: unknown platform %q", ctx, platform)
			}
			if err := validateAssetURL(m.Repo, a.URL); err != nil {
				add("%s/%s: %v", ctx, platform, err)
			}
			if !sha256Re.MatchString(a.SHA256) {
				add("%s/%s: sha256 must be 64 lowercase hex chars", ctx, platform)
			}
		}
	}
	// Newest first keeps the index and human review aligned.
	for i := 1; i < len(m.Versions); i++ {
		if semver.Compare("v"+m.Versions[i-1].Version, "v"+m.Versions[i].Version) < 0 {
			add("versions must be ordered newest first (%s before %s)", m.Versions[i-1].Version, m.Versions[i].Version)
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("manifest %s:\n  - %s", m.Name, strings.Join(errs, "\n  - "))
	}
	return nil
}

// validateAssetURL pins asset URLs to release downloads of the declared repo:
// a manifest cannot point installs at a foreign location.
func validateAssetURL(repo, raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host != "github.com" {
		return fmt.Errorf("url must be https://github.com/...: %q", raw)
	}
	prefix := "/" + strings.TrimPrefix(repo, "github.com/") + "/releases/download/"
	if !strings.HasPrefix(u.Path, prefix) {
		return fmt.Errorf("url must be a release download of %s", repo)
	}
	return nil
}

// MirrorTag is the release tag a version mirrors to on the registry repo.
func MirrorTag(name, version string) string { return name + "-v" + version }

// AssetFileName is the file name an asset keeps on the mirror release.
func AssetFileName(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return filepath.Base(u.Path)
}
