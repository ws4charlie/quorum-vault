package auth_test

import (
	"encoding/json"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/ws4charlie/quorum-vault/internal/auth"
	"github.com/ws4charlie/quorum-vault/internal/auth/authtest"
)

// The dev realm's test clients are refused in production, as audience, as service client and as the azp of a token.
func TestProductionRefusesTheDevRealmTestClients(t *testing.T) {
	for _, id := range auth.E2EClients {
		if _, err := auth.New(auth.Config{Issuer: iss, Audience: id}, auth.Production, false); err == nil {
			t.Errorf("production accepted audience %q", id)
		}
		if _, err := auth.New(auth.Config{Issuer: iss, Audience: aud, ServiceClients: []string{"qv-guardian", id}}, auth.Production, false); err == nil {
			t.Errorf("production accepted service client %q", id)
		}
		if _, err := auth.New(auth.Config{Issuer: iss, Audience: aud, ServiceClients: []string{id}, StaticJWKS: authtest.New(iss, aud).JWKS()}, auth.Test, false); err != nil {
			t.Errorf("test environment refused service client %q: %v", id, err)
		}
	}
}

func TestProductionRefusesATokenOfADevRealmTestClient(t *testing.T) {
	is := authtest.New(iss, aud)
	srv := is.Serve()
	defer srv.Close()
	// Production needs an https issuer and refuses static keys: the issuer name is https, the keys come from the test server.
	a, err := auth.New(auth.Config{Issuer: iss, Audience: aud, JWKSURL: srv.URL + "/jwks"}, auth.Production, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, fail := a.Authenticate(bearer(is.Token(authtest.Spec{Sub: "u", Client: "qv-cli"}))); fail != nil {
		t.Fatalf("a token of a real client was refused: %v", fail)
	}
	for _, id := range auth.E2EClients {
		_, fail := a.Authenticate(bearer(is.Token(authtest.Spec{Sub: "u", Client: id})))
		if fail == nil || fail.Status != 401 {
			t.Errorf("production accepted a token with azp %q: %v", id, fail)
		}
		// A real azp does not hide an e2e client_id.
		_, fail = a.Authenticate(bearer(is.Token(authtest.Spec{Sub: "u", Client: "qv-cli", Claims: map[string]any{"client_id": id}})))
		if fail == nil || fail.Status != 401 {
			t.Errorf("production accepted azp qv-cli with client_id %q: %v", id, fail)
		}
		// Case and surrounding space do not matter.
		odd := " " + strings.ToUpper(id) + " "
		_, fail = a.Authenticate(bearer(is.Token(authtest.Spec{Sub: "u", Client: odd})))
		if fail == nil || fail.Status != 401 {
			t.Errorf("production accepted azp %q: %v", odd, fail)
		}
		if _, err := auth.New(auth.Config{Issuer: iss, Audience: odd}, auth.Production, false); err == nil {
			t.Errorf("production accepted audience %q", odd)
		}
		// Without azp the verifier names the client by client_id.
		_, fail = a.Authenticate(bearer(is.Token(authtest.Spec{Sub: "u", Client: id, Claims: map[string]any{"azp": "", "client_id": id}})))
		if fail == nil || fail.Status != 401 {
			t.Errorf("production accepted a token with client_id %q: %v", id, fail)
		}
	}

	dev, err := auth.New(is.Config(), auth.Test, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range auth.E2EClients {
		if _, fail := dev.Authenticate(bearer(is.Token(authtest.Spec{Sub: "u", Client: id}))); fail != nil {
			t.Errorf("the test environment refused azp %q: %v", id, fail)
		}
	}
}

// Every test client of the dev realm must be in auth.E2EClients, so a new one cannot slip past the production check. A test client is one
// named "TEST ONLY", one whose id says e2e, or one with any mapper that sets the acr claim.
func TestE2EClientsMatchesTheDevRealm(t *testing.T) {
	raw, err := os.ReadFile("../../deploy/keycloak/quorumvault-realm.json")
	if err != nil {
		t.Fatal(err)
	}
	var realm struct {
		Clients []struct {
			ClientID string `json:"clientId"`
			Name     string `json:"name"`
			Mappers  []struct {
				Mapper string            `json:"protocolMapper"`
				Config map[string]string `json:"config"`
			} `json:"protocolMappers"`
		} `json:"clients"`
	}
	if err := json.Unmarshal(raw, &realm); err != nil {
		t.Fatal(err)
	}
	var found []string
	for _, c := range realm.Clients {
		test := strings.HasPrefix(c.Name, "TEST ONLY") || strings.Contains(strings.ToLower(c.ClientID), "e2e")
		for _, m := range c.Mappers {
			test = test || m.Config["claim.name"] == "acr" // any mapper that sets acr, whatever its type
		}
		if test {
			found = append(found, c.ClientID)
		}
	}
	if len(found) == 0 {
		t.Fatal("no test client found in the realm file: the markers changed, update this test")
	}
	have := append([]string(nil), auth.E2EClients...)
	sort.Strings(found)
	sort.Strings(have)
	if strings.Join(found, ",") != strings.Join(have, ",") {
		t.Fatalf("realm test clients %v, auth.E2EClients %v: keep them equal", found, have)
	}
}
