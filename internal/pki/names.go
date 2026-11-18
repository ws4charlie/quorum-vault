// Package pki is how QuorumVault services prove who they are to each other: one private certificate authority per trust zone,
// short-lived certificates whose URI SAN is a SPIFFE-shaped name (spiffe://quorumvault/<zone>/<service>), hot reloading of rotated
// files, and a per-endpoint allow-list of names that a server checks after the usual "signed by my CA" check.
//
// Nothing here holds a key at rest in the repository: cmd/qv-pki makes the authorities and certificates at setup time, into
// gitignored paths. Production gets its certificates from the operator's own PKI; the files have the same shape (docs/runbooks/certificates.md).
package pki

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// TrustDomain is the SPIFFE trust domain of every name.
const TrustDomain = "quorumvault"

// The two trust zones. A certificate of one zone's authority is not accepted on the other zone's endpoints; the few links between
// the zones are explicit (see Catalog: the "-link" services are issued by the business authority to signing-zone callers).
const (
	ZoneBusiness = "business"
	ZoneSigning  = "signing"
)

// ID returns spiffe://quorumvault/<zone>/<service>.
func ID(zone, service string) string {
	return "spiffe://" + TrustDomain + "/" + zone + "/" + service
}

// ParseID splits a name made by ID. Anything else is an error: another trust domain, another scheme, extra path parts, a query.
func ParseID(s string) (zone, service string, err error) {
	u, err := url.Parse(s)
	if err != nil {
		return "", "", fmt.Errorf("pki: %q is not a URI", s)
	}
	return parseURI(u)
}

func parseURI(u *url.URL) (zone, service string, err error) {
	if u.Scheme != "spiffe" || u.Host != TrustDomain || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return "", "", fmt.Errorf("pki: %q is not a spiffe://%s/<zone>/<service> name", u.String(), TrustDomain)
	}
	parts := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("pki: %q is not a spiffe://%s/<zone>/<service> name", u.String(), TrustDomain)
	}
	if parts[0] != ZoneBusiness && parts[0] != ZoneSigning {
		return "", "", fmt.Errorf("pki: %q names an unknown zone %q", u.String(), parts[0])
	}
	return parts[0], parts[1], nil
}

// ValidZone reports whether z is one of the two zones.
func ValidZone(z string) error {
	if z != ZoneBusiness && z != ZoneSigning {
		return errors.New("pki: zone must be \"business\" or \"signing\"")
	}
	return nil
}
