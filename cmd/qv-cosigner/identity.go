package main

import (
	"fmt"
	"strings"

	"github.com/ws4charlie/quorum-vault/internal/pki"
)

// Cosigners B and C each have a name of their own (signing/cosigner-b, signing/cosigner-c, and the business-issued links cosigner-link-b, cosigner-link-c),
// so the guard database, the Kafka ACL, the audit trail and the metrics tell them apart and a certificate of one is no use as the other.
// The process learns which one it is from its certificate; there is no flag to set wrongly.
const (
	cosignerPrefix     = "cosigner-"
	cosignerLinkPrefix = "cosigner-link-"
)

// cosignerIdentity checks that the signing certificate is cosigner-<role> and the link certificate is cosigner-link-<same role>, makes both sources
// hold those names (a reload that brings another name is refused), renames them for messages and metrics, and returns the role ("b" or "c").
// Both sources nil (the development plain-text switch) gives "".
func cosignerIdentity(tsrc, lsrc *pki.Source) (string, error) {
	if tsrc == nil && lsrc == nil {
		return "", nil
	}
	if tsrc == nil || lsrc == nil {
		return "", fmt.Errorf("the signing and the link certificate are both required")
	}
	svc := tsrc.Service()
	role := strings.TrimPrefix(svc, cosignerPrefix)
	if svc == role || (role != "b" && role != "c") || strings.HasPrefix(svc, cosignerLinkPrefix) {
		return "", fmt.Errorf("the signing certificate is named %q: a cosigner needs signing/cosigner-b or signing/cosigner-c (the shared name \"cosigner\" is retired; docs/runbooks/certificates.md, \"Cosigner names\")", svc)
	}
	if err := tsrc.HoldName(cosignerPrefix + role); err != nil {
		return "", err
	}
	if err := lsrc.HoldName(cosignerLinkPrefix + role); err != nil {
		return "", fmt.Errorf("the link certificate must be business/%s%s to go with signing/%s%s: %w", cosignerLinkPrefix, role, cosignerPrefix, role, err)
	}
	tsrc.Rename("qv-cosigner-" + role)
	lsrc.Rename("qv-cosigner-link-" + role)
	return role, nil
}

// hasSourceFlag reports whether args name -source (or --source), with a value either as -source=x or as the next argument.
func hasSourceFlag(args []string) bool {
	for i, a := range args {
		a = strings.TrimLeft(a, "-")
		if a == "source" && i+1 < len(args) || strings.HasPrefix(a, "source=") && len(a) > len("source=") {
			return true
		}
	}
	return false
}
