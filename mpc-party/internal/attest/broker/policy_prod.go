//go:build !teesim

package broker

import (
	"crypto/x509"
	"errors"
	"strings"
)

// Simulation is false in the production build: no mock attester, no test root, no debug evidence.
const Simulation = false

// checkBuildPolicy is what the production build adds to the start checks: debug evidence is off and a test root is refused.
func checkBuildPolicy(c Config, roots []*x509.Certificate) error {
	if c.AllowDebug {
		return errors.New("broker: allow_debug is set: a production build never accepts debug evidence")
	}
	for _, r := range roots {
		if strings.Contains(r.Subject.String(), testRootMarker) {
			return errors.New("broker: trust root " + r.Subject.CommonName + " is marked TEST ONLY: a production build refuses a test root")
		}
	}
	return nil
}
