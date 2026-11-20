//go:build teesim

package broker

import "crypto/x509"

// Simulation is true when built with -tags teesim: debug evidence and the test root may be configured. Never ship such a build.
const Simulation = true

func checkBuildPolicy(Config, []*x509.Certificate) error { return nil }
