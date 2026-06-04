package registry

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/charlesng35/shellcn/sdk/plugin"
)

// MirrorRepo is where verified binaries are republished. Asset URLs in the
// index put the mirror first so installs survive upstream deletions.
const MirrorRepo = "CharlesNg35/shellcn-plugins"

// IndexAsset is one platform binary as the gateway consumes it.
type IndexAsset struct {
	SHA256 string   `json:"sha256"`
	URLs   []string `json:"urls"` // mirror first, upstream second
}

// IndexVersion is one installable version in the index.
type IndexVersion struct {
	Version         string                `json:"version"`
	APIVersion      int                   `json:"apiVersion"`
	ProtocolVersion int                   `json:"protocolVersion"`
	Yanked          bool                  `json:"yanked,omitempty"`
	Assets          map[string]IndexAsset `json:"assets"`
	Icon            plugin.Icon           `json:"icon"`
	Projection      *plugin.Projection    `json:"projection,omitempty"`
}

// IndexEntry is one plugin in index.json.
type IndexEntry struct {
	Name        string         `json:"name"`
	DisplayName string         `json:"displayName"`
	Description string         `json:"description"`
	Repo        string         `json:"repo"`
	Homepage    string         `json:"homepage,omitempty"`
	License     string         `json:"license"`
	Maintainers []string       `json:"maintainers"`
	Versions    []IndexVersion `json:"versions"`
}

// Index is the document the gateway fetches.
type Index struct {
	SchemaVersion int          `json:"schemaVersion"`
	GeneratedBy   string       `json:"generatedBy"`
	Plugins       []IndexEntry `json:"plugins"`
}

// SnapshotPath is where a version's inspection snapshot lives.
func SnapshotPath(dir, name, version string) string {
	return filepath.Join(dir, MirrorTag(name, version)+".json")
}

// LoadSnapshot reads one inspection snapshot, returning nil when absent.
func LoadSnapshot(dir, name, version string) (*Snapshot, error) {
	raw, err := os.ReadFile(SnapshotPath(dir, name, version))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var s Snapshot
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// WriteSnapshot stores an inspection snapshot.
func WriteSnapshot(dir string, s *Snapshot) error {
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(SnapshotPath(dir, s.Name, s.Version), append(raw, '\n'), 0o644)
}

// BuildIndex composes index.json from the manifests and their snapshots. A
// version without a snapshot is skipped: it has not been mirror-verified yet
// and must not be installable.
func BuildIndex(manifests []*Manifest, snapshotDir, generatedBy string) (*Index, []string, error) {
	idx := &Index{SchemaVersion: 1, GeneratedBy: generatedBy, Plugins: []IndexEntry{}}
	var skipped []string

	for _, m := range manifests {
		entry := IndexEntry{
			Name: m.Name, DisplayName: m.DisplayName, Description: m.Description,
			Repo: m.Repo, Homepage: m.Homepage, License: m.License, Maintainers: m.Maintainers,
			Versions: []IndexVersion{},
		}
		for _, v := range m.Versions {
			snap, err := LoadSnapshot(snapshotDir, m.Name, v.Version)
			if err != nil {
				return nil, nil, fmt.Errorf("%s %s: %w", m.Name, v.Version, err)
			}
			if snap == nil {
				skipped = append(skipped, fmt.Sprintf("%s %s (no snapshot yet)", m.Name, v.Version))
				continue
			}
			iv := IndexVersion{
				Version: v.Version, Yanked: v.Yanked,
				APIVersion: snap.APIVersion, ProtocolVersion: snap.ProtocolVersion,
				Assets: map[string]IndexAsset{},
				Icon:   snap.Icon, Projection: &snap.Projection,
			}
			for platform, a := range v.Assets {
				iv.Assets[platform] = IndexAsset{
					SHA256: a.SHA256,
					URLs: []string{
						fmt.Sprintf("https://github.com/%s/releases/download/%s/%s",
							MirrorRepo, MirrorTag(m.Name, v.Version), AssetFileName(a.URL)),
						a.URL,
					},
				}
			}
			entry.Versions = append(entry.Versions, iv)
		}
		if len(entry.Versions) > 0 {
			idx.Plugins = append(idx.Plugins, entry)
		}
	}
	return idx, skipped, nil
}

// WriteIndex stores index.json.
func WriteIndex(idx *Index, path string) error {
	raw, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o644)
}
