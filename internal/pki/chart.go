package pki

//go:generate go run ./gen -o ../../deploy/helm/qv-certs/catalog.json

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ChartEntry is one identity as the Helm chart deploy/helm/qv-certs reads it. Names and policy only: nothing secret.
type ChartEntry struct {
	Name       string   `json:"name"`     // the service name (URI SAN last part)
	Zone       string   `json:"zone"`     // the zone whose authority issues it
	URI        string   `json:"uri"`      // spiffe://quorumvault/<zone>/<name>
	CN         string   `json:"cn"`       // subject common name
	DNS        []string `json:"dnsNames"` // names a client may dial
	IPs        []string `json:"ipAddresses"`
	Usages     []string `json:"usages"`     // cert-manager key usages: "server auth", "client auth"
	Clusters   []string `json:"clusters"`   // where the chart makes it
	Pinned     bool     `json:"pinned"`     // peers pin its public key: the key never rotates on renewal
	Operator   bool     `json:"operator"`   // a person's or tool's identity: not made in production clusters
	SecretName string   `json:"secretName"` // SecretName(zone, name)
}

// ChartCatalog is the catalog in the shape the chart reads.
func ChartCatalog() []ChartEntry {
	out := make([]ChartEntry, 0, len(Catalog))
	for _, e := range Catalog {
		cn := e.CN
		if cn == "" {
			cn = e.Service
		}
		var u []string
		if e.Usage&Server != 0 {
			u = append(u, "server auth")
		}
		if e.Usage&Client != 0 {
			u = append(u, "client auth")
		}
		dns, ips := append([]string{}, e.DNS...), append([]string{}, e.IPs...)
		out = append(out, ChartEntry{
			Name: e.Service, Zone: e.Zone, URI: ID(e.Zone, e.Service), CN: cn,
			DNS: dns, IPs: ips, Usages: u, Clusters: e.Clusters,
			Pinned: e.Pinned, Operator: e.Operator, SecretName: SecretName(e.Zone, e.Service),
		})
	}
	return out
}

// ChartCatalogJSON is the exact content of deploy/helm/qv-certs/catalog.json: one entry per line, so a review diff reads like the catalog.
func ChartCatalogJSON() ([]byte, error) {
	var b strings.Builder
	b.WriteString("{\n  \"generatedFrom\": \"internal/pki/catalog.go (go generate ./internal/pki): do not edit\",\n  \"entries\": [\n")
	es := ChartCatalog()
	for i, e := range es {
		line, err := json.Marshal(e)
		if err != nil {
			return nil, fmt.Errorf("pki: %s: %w", e.Name, err)
		}
		b.WriteString("    ")
		b.Write(line)
		if i < len(es)-1 {
			b.WriteString(",")
		}
		b.WriteString("\n")
	}
	b.WriteString("  ]\n}\n")
	return []byte(b.String()), nil
}
