package registry

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const maxAssetBytes = 256 << 20 // a plugin binary is ~16MB; 256MB is a hard stop

var httpClient = &http.Client{Timeout: 5 * time.Minute}

// FetchVerified downloads an asset and verifies its sha256 against the
// manifest before the bytes are trusted for anything. The file is written to
// dir under its release file name; dir may be "" to verify without keeping.
func FetchVerified(a Asset, dir string) (path string, err error) {
	resp, err := httpClient.Get(a.URL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET %s: %s", a.URL, resp.Status)
	}

	var out io.Writer = io.Discard
	var f *os.File
	if dir != "" {
		name := AssetFileName(a.URL)
		if name == "" || name == "." || name == "/" {
			return "", fmt.Errorf("cannot derive file name from %s", a.URL)
		}
		path = filepath.Join(dir, name)
		f, err = os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
		if err != nil {
			return "", err
		}
		defer f.Close()
		out = f
	}

	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(h, out), io.LimitReader(resp.Body, maxAssetBytes)); err != nil {
		return "", err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != a.SHA256 {
		if path != "" {
			_ = os.Remove(path)
		}
		return "", fmt.Errorf("sha256 mismatch for %s: manifest %s, downloaded %s", a.URL, a.SHA256, got)
	}
	return path, nil
}

// VerifyVersion checks every asset of a version (download + hash, kept in dir
// when dir != "").
func VerifyVersion(v Version, dir string) error {
	for platform, a := range v.Assets {
		if _, err := FetchVerified(a, dir); err != nil {
			return fmt.Errorf("%s: %w", platform, err)
		}
	}
	return nil
}
