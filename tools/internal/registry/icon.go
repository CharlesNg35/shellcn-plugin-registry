package registry

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/charlesng35/shellcn/sdk/plugin"
)

const (
	maxSVGBytes    = 16 << 10
	maxBase64Bytes = 48 << 10
)

// svgForbidden rejects SVG capable of running code or reaching the network.
// The registry rejects rather than rewrites: authors fix their icon, reviewers
// never have to reason about a sanitizer's blind spots.
var svgForbidden = []*regexp.Regexp{
	regexp.MustCompile(`(?i)<\s*script`),
	regexp.MustCompile(`(?i)\son[a-z]+\s*=`),
	regexp.MustCompile(`(?i)javascript\s*:`),
	regexp.MustCompile(`(?i)<\s*foreignobject`),
	regexp.MustCompile(`(?i)(xlink:)?href\s*=\s*["']\s*https?:`),
	regexp.MustCompile(`(?i)url\s*\(\s*["']?\s*https?:`),
	regexp.MustCompile(`(?i)data:text/html`),
	regexp.MustCompile(`(?i)<\s*!entity`),
}

// NormalizeIcon enforces the registry icon policy: self-contained (no remote
// fetches from admin browsers), bounded, and free of active content. IconURL is
// rejected outright — an indexed icon must not be mutable after review.
func NormalizeIcon(ic plugin.Icon) (plugin.Icon, error) {
	switch ic.Type {
	case plugin.IconLucide:
		if !regexp.MustCompile(`^[a-z0-9-]{1,64}$`).MatchString(ic.Value) {
			return ic, fmt.Errorf("lucide icon name %q is invalid", ic.Value)
		}
		return ic, nil
	case plugin.IconEmoji:
		if ic.Value == "" || utf8.RuneCountInString(ic.Value) > 4 {
			return ic, fmt.Errorf("emoji icon must be 1-4 runes")
		}
		return ic, nil
	case plugin.IconSVG:
		if err := checkSVG(ic.Value); err != nil {
			return ic, err
		}
		return ic, nil
	case plugin.IconBase64:
		return checkDataURI(ic)
	case plugin.IconURL:
		return ic, fmt.Errorf("remote icon URLs are not allowed in the registry; inline the image (svg/base64) or use a lucide name")
	case "":
		// No icon declared: the gateway falls back to a generic glyph.
		return plugin.Icon{}, nil
	default:
		return ic, fmt.Errorf("unknown icon type %q", ic.Type)
	}
}

func checkSVG(svg string) error {
	if len(svg) > maxSVGBytes {
		return fmt.Errorf("svg icon exceeds %d bytes", maxSVGBytes)
	}
	if !strings.Contains(strings.ToLower(svg), "<svg") {
		return fmt.Errorf("svg icon has no <svg> element")
	}
	for _, re := range svgForbidden {
		if re.MatchString(svg) {
			return fmt.Errorf("svg icon contains forbidden content (%s)", re)
		}
	}
	return nil
}

func checkDataURI(ic plugin.Icon) (plugin.Icon, error) {
	if len(ic.Value) > maxBase64Bytes {
		return ic, fmt.Errorf("base64 icon exceeds %d bytes", maxBase64Bytes)
	}
	rest, ok := strings.CutPrefix(ic.Value, "data:")
	if !ok {
		return ic, fmt.Errorf("base64 icon must be a data: URI")
	}
	meta, data, ok := strings.Cut(rest, ",")
	if !ok {
		return ic, fmt.Errorf("malformed data URI")
	}
	mime, _, _ := strings.Cut(meta, ";")
	switch mime {
	case "image/png", "image/webp", "image/jpeg":
		if !strings.Contains(meta, "base64") {
			return ic, fmt.Errorf("data URI must be base64-encoded")
		}
		if _, err := base64.StdEncoding.DecodeString(data); err != nil {
			return ic, fmt.Errorf("invalid base64 payload: %w", err)
		}
		return ic, nil
	case "image/svg+xml":
		payload := data
		if strings.Contains(meta, "base64") {
			raw, err := base64.StdEncoding.DecodeString(data)
			if err != nil {
				return ic, fmt.Errorf("invalid base64 payload: %w", err)
			}
			payload = string(raw)
		}
		if err := checkSVG(payload); err != nil {
			return ic, err
		}
		return ic, nil
	default:
		return ic, fmt.Errorf("data URI mime %q not allowed (png, webp, jpeg, svg+xml)", mime)
	}
}
