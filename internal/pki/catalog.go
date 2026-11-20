package pki

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// The clusters of the Kubernetes deployment (research/K8s-deployment.md section 2): one cluster per trust domain. The attestation broker runs in its
// own trust zone (docs/runbooks/tee-broker.md), so it is a fifth place. The kind and CI lane runs all of them in one cluster (chart value cluster: all).
const (
	ClusterBusiness    = "business"
	ClusterSigningCore = "signing-core" // the gateway and party A
	ClusterPartyB      = "party-b"      // party B and its cosigner
	ClusterPartyC      = "party-c"      // party C and its cosigner
	ClusterBroker      = "broker"       // the attestation release broker
)

// Clusters lists every cluster name, in the order the chart documents them.
var Clusters = []string{ClusterBusiness, ClusterSigningCore, ClusterPartyB, ClusterPartyC, ClusterBroker}

// Entry is one identity the development setup issues. Production asks its own PKI for the same names (docs/runbooks/certificates.md).
type Entry struct {
	Zone    string // the zone whose authority issues it
	Service string // the name in the URI SAN
	CN      string // subject common name; empty means Service. Postgres client certificates map it to a role
	DNS     []string
	IPs     []string
	Usage   Usage
	// Clusters are the Kubernetes clusters that hold this identity (deploy/helm/qv-certs renders one Certificate for it in each). Every entry names at
	// least one. An entry in several clusters is the same NAME in each, with a key of its own per cluster (admin, signing-db, cosigner-socket).
	// Cosigners B and C do NOT share a name: each has its own (cosigner-b, cosigner-c and their links), so a certificate of one is refused where the
	// other's is expected.
	Clusters []string
	// Pinned marks an identity that peers pin by public key (docs/runbooks/certificates.md, "Printing a pin"): no CA vouches for it, so its Certificate
	// must keep its key across renewals (cert-manager rotationPolicy Never) or every renewal would break the pin.
	Pinned bool
	// Operator marks an identity that belongs to a person or a tool, not to a pod: the production chart does not make it in a cluster (an owner-level
	// client certificate must not sit in a Secret); the operator gets one from the issuer when needed. The kind and CI lane makes them (operatorCertificates).
	Operator bool
}

// SecretName is the name of the Kubernetes Secret (keys tls.crt, tls.key, ca.crt) that holds the identity (zone, service). The charts agree on it by this
// rule: a business-zone name is qv-<service>-tls, a signing-zone name is qv-signing-<service>-tls (the two zones both have an admin).
func SecretName(zone, service string) string {
	if zone == ZoneSigning {
		return "qv-signing-" + service + "-tls"
	}
	return "qv-" + service + "-tls"
}

var localNames = []string{"localhost"}
var localIPs = []string{"127.0.0.1", "::1"}

// Catalog is every service identity. Server entries carry the DNS names and IPs a client may dial (compose service names and localhost).
//
// The entries whose name ends in -link are certificates of the BUSINESS authority for signing-zone programs that must reach a business
// service (the gateway reads the job queue in the business database; the gateway and the cosigner publish audit heads to the business
// Kafka). They are the explicit links between the zones: the business side admits the visitor by a name it issued, and trusts no signing-zone authority.
var Catalog = []Entry{
	// business zone
	{Zone: ZoneBusiness, Service: "core", DNS: append([]string{"qv-core"}, localNames...), IPs: localIPs, Usage: Server | Client, Clusters: biz},
	{Zone: ZoneBusiness, Service: "worker", Usage: Client, Clusters: biz},
	{Zone: ZoneBusiness, Service: "relay", Usage: Client, Clusters: biz},
	{Zone: ZoneBusiness, Service: "archiver", Usage: Client, Clusters: biz},
	{Zone: ZoneBusiness, Service: "guardian", Usage: Client, Clusters: biz},
	{Zone: ZoneBusiness, Service: "admin", Usage: Client, Operator: true, Clusters: biz}, // operators and tests: creates databases, Kafka superuser, Temporal client (Postgres role qv)
	{Zone: ZoneBusiness, Service: "migrator", Usage: Client, Clusters: biz},              // the migration Job only: Postgres role qv (owner), no other rights anywhere
	{Zone: ZoneBusiness, Service: "postgres", DNS: append([]string{"postgres"}, localNames...), IPs: localIPs, Usage: Server, Clusters: biz},
	{Zone: ZoneBusiness, Service: "temporal-db", DNS: append([]string{"temporal-db"}, localNames...), IPs: localIPs, Usage: Server, Clusters: biz},
	{Zone: ZoneBusiness, Service: "kafka", DNS: append([]string{"redpanda"}, localNames...), IPs: localIPs, Usage: Server, Clusters: biz},
	{Zone: ZoneBusiness, Service: "temporal", DNS: append([]string{"temporal"}, localNames...), IPs: localIPs, Usage: Server | Client, Clusters: biz},
	{Zone: ZoneBusiness, Service: "keycloak", DNS: append([]string{"keycloak"}, localNames...), IPs: localIPs, Usage: Server, Clusters: biz},
	{Zone: ZoneBusiness, Service: "seaweedfs", DNS: append([]string{"seaweedfs"}, localNames...), IPs: localIPs, Usage: Server, Clusters: biz},
	// the links: issued by the business authority, held by signing-zone programs. Each cosigner has its own link name (the Kafka ACL names both).
	{Zone: ZoneBusiness, Service: "gateway-link", Usage: Client, Clusters: signingCore},
	{Zone: ZoneBusiness, Service: "cosigner-link-b", Usage: Client, Clusters: []string{ClusterPartyB}},
	{Zone: ZoneBusiness, Service: "cosigner-link-c", Usage: Client, Clusters: []string{ClusterPartyC}},
	// signing zone
	{Zone: ZoneSigning, Service: "gateway", Usage: Client, Clusters: signingCore},
	{Zone: ZoneSigning, Service: "cosigner-b", Usage: Client, Clusters: []string{ClusterPartyB}},                                                       // the cosigner next to party B: guard database client; its own name
	{Zone: ZoneSigning, Service: "cosigner-c", Usage: Client, Clusters: []string{ClusterPartyC}},                                                       // the cosigner next to party C
	{Zone: ZoneSigning, Service: "signing-db", DNS: append([]string{"signing-db"}, localNames...), IPs: localIPs, Usage: Server, Clusters: allSigning}, // the Postgres of the guard databases: one per signing cluster
	{Zone: ZoneSigning, Service: "admin", Usage: Client, Operator: true, Clusters: allSigning},
	// the MPC parties: peers pin each other's public key (docs/mpc.md), so no CA vouches for these identities and a renewal must keep the key (Pinned).
	// A party presents its certificate on the peer port, on the caller port and, in parties B and C, to its cosigner.
	{Zone: ZoneSigning, Service: "mpc-party-a", DNS: []string{"mpc-party-a", "localhost"}, IPs: localIPs, Usage: Server | Client, Pinned: true, Clusters: signingCore},
	{Zone: ZoneSigning, Service: "mpc-party-b", DNS: []string{"mpc-party-b", "localhost"}, IPs: localIPs, Usage: Server | Client, Pinned: true, Clusters: []string{ClusterPartyB}},
	{Zone: ZoneSigning, Service: "mpc-party-c", DNS: []string{"mpc-party-c", "localhost"}, IPs: localIPs, Usage: Server | Client, Pinned: true, Clusters: []string{ClusterPartyC}},
	// the other pinned links
	{Zone: ZoneSigning, Service: "gateway-party", Usage: Client, Pinned: true, Clusters: signingCore},        // the gateway's client certificate on the parties' caller ports (mpc.cert_file)
	{Zone: ZoneSigning, Service: "cosigner-socket", Usage: Server | Client, Pinned: true, Clusters: partyBC}, // the cosigner's certificate on the unix socket its party pins (-socket-cert)
	// the attestation release broker (docs/runbooks/tee-broker.md): its server certificate, which every party pins, and one caller certificate per party,
	// which the broker pins (config parties.<role>.caller_pins; the caller's key is also bound into the attestation evidence)
	{Zone: ZoneSigning, Service: "attest-broker", DNS: []string{"attest-broker", "localhost"}, IPs: localIPs, Usage: Server, Pinned: true, Clusters: []string{ClusterBroker}},
	{Zone: ZoneSigning, Service: "attest-caller-a", Usage: Client, Pinned: true, Clusters: signingCore},
	{Zone: ZoneSigning, Service: "attest-caller-b", Usage: Client, Pinned: true, Clusters: []string{ClusterPartyB}},
	{Zone: ZoneSigning, Service: "attest-caller-c", Usage: Client, Pinned: true, Clusters: []string{ClusterPartyC}},
}

var (
	biz         = []string{ClusterBusiness}
	signingCore = []string{ClusterSigningCore}
	partyBC     = []string{ClusterPartyB, ClusterPartyC}
	allSigning  = []string{ClusterSigningCore, ClusterPartyB, ClusterPartyC}
)

// Dir is where the certificate files of an entry live under a PKI root: <root>/<zone>/<service>/{tls.crt,tls.key,ca.crt}.
func Dir(root, zone, service string) string { return filepath.Join(root, zone, service) }

// Init makes the two zone authorities under root, each valid for caTTL. An authority that already exists is left alone.
func Init(root string, caTTL time.Duration, now time.Time) error {
	for _, z := range []string{ZoneBusiness, ZoneSigning} {
		if _, err := os.Stat(filepath.Join(root, z, "ca.key")); err == nil {
			continue
		}
		ca, err := NewCA(z, caTTL, now)
		if err != nil {
			return err
		}
		if err := ca.Save(root); err != nil {
			return err
		}
	}
	return nil
}

// IssueAll issues (or re-issues: that is rotation) every catalog certificate, valid for ttl, into root. Files are replaced atomically.
func IssueAll(root string, ttl time.Duration, now time.Time) error {
	cas := map[string]*CA{}
	for _, z := range []string{ZoneBusiness, ZoneSigning} {
		ca, err := LoadCA(root, z)
		if err != nil {
			return err
		}
		cas[z] = ca
	}
	for _, e := range Catalog {
		ca := cas[e.Zone]
		l, err := ca.Issue(IssueRequest{Service: e.Service, CN: e.CN, DNS: e.DNS, IPs: e.IPs, Usage: e.Usage, TTL: ttl, Now: now})
		if err != nil {
			return fmt.Errorf("%s/%s: %w", e.Zone, e.Service, err)
		}
		if err := WriteLeaf(Dir(root, e.Zone, e.Service), l, ca); err != nil {
			return err
		}
	}
	return nil
}
