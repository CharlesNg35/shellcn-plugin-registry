package registry

import (
	"fmt"
	"strings"
)

const (
	TrustFirstParty         = "first_party"
	TrustContribReviewed    = "contrib_reviewed"
	TrustExternalVerified   = "external_verified"
	TrustExternalUnreviewed = "external_unreviewed"
	TrustBlocked            = "blocked"
	TrustDeprecated         = "deprecated"
)

var allowedTrustLevels = map[string]bool{
	TrustFirstParty:         true,
	TrustContribReviewed:    true,
	TrustExternalVerified:   true,
	TrustExternalUnreviewed: true,
	TrustBlocked:            true,
	TrustDeprecated:         true,
}

// Trust is generated into the registry index so gateways and users can make
// install decisions from the same evidence maintainers reviewed.
type Trust struct {
	Level                   string   `json:"level"`
	SourceReviewed          bool     `json:"sourceReviewed"`
	ChecksumsVerified       bool     `json:"checksumsVerified"`
	SignatureVerified       bool     `json:"signatureVerified"`
	ProvenanceVerified      bool     `json:"provenanceVerified"`
	SBOMAvailable           bool     `json:"sbomAvailable"`
	SandboxInspectionPassed bool     `json:"sandboxInspectionPassed"`
	Warnings                []string `json:"warnings,omitempty"`
}

// TrustForVersion summarizes registry-owned evidence for one installable plugin
// version. Manifest security fields are contributor claims; they never upgrade
// a plugin to external_verified by themselves.
func TrustForVersion(m *Manifest, snap *Snapshot) Trust {
	tr := Trust{
		Level:              inferredTrustLevel(m),
		SourceReviewed:     hasSourceEvidence(m),
		ChecksumsVerified:  true,
		SignatureVerified:  false,
		ProvenanceVerified: false,
		SBOMAvailable:      false,
	}
	if snap != nil && snap.Inspection.Sandbox != "" && snap.Inspection.Sandbox != SandboxNone {
		tr.SandboxInspectionPassed = true
	}
	tr.Warnings = trustWarnings(m, tr)
	return tr
}

// Policy checks whether a manifest has enough registry-verified evidence for
// the requested mode. Non-strict mode reports a trust summary; strict mode
// rejects external plugins until automated signature/provenance/SBOM
// verification is implemented and recorded by registry-owned checks.
func Policy(m *Manifest, strict bool) (Trust, error) {
	tr := TrustForVersion(m, nil)
	if !strict {
		return tr, nil
	}
	if tr.Level == TrustBlocked || tr.Level == TrustDeprecated {
		return tr, fmt.Errorf("plugin is %s", tr.Level)
	}
	if isOwnedBy(m, "CharlesNg35") {
		return tr, nil
	}
	var errs []string
	if !tr.SourceReviewed {
		errs = append(errs, "source.repo, source.commit, source.tag, and source.workflow are required")
	}
	errs = append(errs, "external signatures, provenance, and SBOM must be verified by registry automation, not declared in the manifest")
	if len(errs) > 0 {
		return tr, fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return tr, nil
}

func inferredTrustLevel(m *Manifest) string {
	if isOwnedBy(m, "CharlesNg35") {
		return TrustContribReviewed
	}
	return TrustExternalUnreviewed
}

func hasSourceEvidence(m *Manifest) bool {
	return m.Source.Repo != "" && m.Source.Commit != "" && m.Source.Tag != "" && m.Source.Workflow != ""
}

func isOwnedBy(m *Manifest, owner string) bool {
	parts := strings.Split(m.Repo, "/")
	return len(parts) == 3 && strings.EqualFold(parts[1], owner)
}

func trustWarnings(m *Manifest, tr Trust) []string {
	var warnings []string
	if !tr.SourceReviewed {
		warnings = append(warnings, "source evidence is incomplete")
	}
	if !tr.SignatureVerified {
		warnings = append(warnings, "artifact signatures were not registry-verified")
	}
	if !tr.ProvenanceVerified {
		warnings = append(warnings, "build provenance was not registry-verified")
	}
	if !tr.SBOMAvailable {
		warnings = append(warnings, "SBOM was not registry-verified")
	}
	if m.Security.Signatures || m.Security.Provenance || m.Security.SBOM || m.Security.Review != "" {
		warnings = append(warnings, "manifest security fields are contributor claims, not registry verification")
	}
	if !isOwnedBy(m, "CharlesNg35") && tr.Level != TrustExternalVerified {
		warnings = append(warnings, "external plugin is not fully verified")
	}
	return warnings
}
