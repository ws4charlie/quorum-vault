package pki_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ws4charlie/quorum-vault/internal/pki"
)

const chartCatalog = "../../deploy/helm/qv-certs/catalog.json"

// The chart's list is generated from the catalog; a hand edit of either side fails here. Fix: go generate ./internal/pki
func TestChartCatalogIsInSyncWithTheCatalog(t *testing.T) {
	want, err := pki.ChartCatalogJSON()
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(chartCatalog)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("deploy/helm/qv-certs/catalog.json differs from internal/pki/catalog.go: run `go generate ./internal/pki` and commit the result")
	}
}

func TestCatalogEntriesAreWellFormed(t *testing.T) {
	valid := map[string]bool{}
	for _, c := range pki.Clusters {
		valid[c] = true
	}
	seen := map[string]bool{}
	secrets := map[string]bool{}
	for _, e := range pki.Catalog {
		id := pki.ID(e.Zone, e.Service)
		if seen[id] {
			t.Errorf("%s is in the catalog twice", id)
		}
		seen[id] = true
		if err := pki.ValidZone(e.Zone); err != nil {
			t.Errorf("%s: %v", id, err)
		}
		if e.Usage == 0 {
			t.Errorf("%s has no usage", id)
		}
		if len(e.Clusters) == 0 {
			t.Errorf("%s names no cluster", id)
		}
		dup := map[string]bool{}
		for _, c := range e.Clusters {
			if !valid[c] {
				t.Errorf("%s: unknown cluster %q", id, c)
			}
			if dup[c] {
				t.Errorf("%s: cluster %q twice", id, c)
			}
			dup[c] = true
		}
		sn := pki.SecretName(e.Zone, e.Service)
		if secrets[sn] {
			t.Errorf("%s: secret name %s is not unique", id, sn)
		}
		secrets[sn] = true
	}
}

// Zone and cluster must agree: a business-zone name outside the business cluster is a link (named -link, issued by the business authority), and the
// business cluster holds no signing-zone name. Names in more than one cluster are only the ones the backlog note lists.
func TestClustersFollowTheZones(t *testing.T) {
	shared := map[string]bool{"cosigner": true, "cosigner-link": true, "cosigner-socket": true, "signing-db": true, "admin": true}
	for _, e := range pki.Catalog {
		id := pki.ID(e.Zone, e.Service)
		for _, c := range e.Clusters {
			switch {
			case e.Zone == pki.ZoneSigning && c == pki.ClusterBusiness:
				t.Errorf("%s: a signing-zone name in the business cluster", id)
			case e.Zone == pki.ZoneBusiness && c != pki.ClusterBusiness && !strings.HasSuffix(e.Service, "-link"):
				t.Errorf("%s: a business-zone name outside the business cluster must be a -link name", id)
			}
		}
		if len(e.Clusters) > 1 && !shared[e.Service] {
			t.Errorf("%s is in %d clusters: only %v may be shared (one name, a key per cluster)", id, len(e.Clusters), shared)
		}
	}
}

// Every pinned link is Pinned, and nothing else is: the chart turns Pinned into rotationPolicy Never (the key, hence the pin, survives a renewal).
func TestPinnedIdentities(t *testing.T) {
	want := []string{"mpc-party-a", "mpc-party-b", "mpc-party-c", "gateway-party", "cosigner-socket", "attest-broker", "attest-caller-a", "attest-caller-b", "attest-caller-c"}
	got := map[string]bool{}
	for _, e := range pki.Catalog {
		if e.Pinned {
			got[e.Service] = true
			if e.Zone != pki.ZoneSigning {
				t.Errorf("%s: a pinned identity outside the signing zone", e.Service)
			}
		}
	}
	for _, n := range want {
		if !got[n] {
			t.Errorf("%s must be Pinned", n)
		}
		delete(got, n)
	}
	for n := range got {
		t.Errorf("%s is Pinned but not in the list of pinned links (update this test and docs/runbooks/certificates.md)", n)
	}
}

func TestSecretNames(t *testing.T) {
	for _, c := range []struct{ zone, svc, want string }{
		{pki.ZoneBusiness, "core", "qv-core-tls"}, // the names the business chart already uses
		{pki.ZoneBusiness, "worker", "qv-worker-tls"},
		{pki.ZoneBusiness, "gateway-link", "qv-gateway-link-tls"},
		{pki.ZoneSigning, "gateway", "qv-signing-gateway-tls"},
		{pki.ZoneSigning, "admin", "qv-signing-admin-tls"},
		{pki.ZoneBusiness, "migrator", "qv-migrator-tls"},
	} {
		if got := pki.SecretName(c.zone, c.svc); got != c.want {
			t.Errorf("SecretName(%s, %s) = %s, want %s", c.zone, c.svc, got, c.want)
		}
	}
}

// The migration Job has a name of its own, mapped to the owner role like admin; no other name is the owner.
func TestMigratorIsTheOwnerRoleInThePostgresMap(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "deploy", "postgres", "business.pg_ident.conf"))
	if err != nil {
		t.Fatal(err)
	}
	owners := map[string]bool{}
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Fields(l)
		if len(f) == 3 && !strings.HasPrefix(f[0], "#") && f[2] == "qv" {
			owners[f[1]] = true
		}
	}
	if !owners["migrator"] || !owners["admin"] || len(owners) != 2 {
		t.Errorf("owner role qv must be reached by exactly migrator and admin, got %v", owners)
	}
	found := false
	for _, e := range pki.Catalog {
		if e.Zone == pki.ZoneBusiness && e.Service == "migrator" && e.Usage == pki.Client && !e.Operator {
			found = true
		}
	}
	if !found {
		t.Error("business/migrator must be a client certificate made in the cluster")
	}
}
