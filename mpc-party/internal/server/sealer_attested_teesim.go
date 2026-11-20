//go:build teesim

package server

import (
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/ws4charlie/quorum-vault/mpc-party/internal/attest"
)

// Simulation builds only (-tags teesim): the "mock" attester writes Nitro-format documents signed by a test CA (internal/attest/mock_teesim.go). It proves
// our code handles attestation; it proves nothing about isolation. A production build does not contain this file.

// SimulatedEnclave is true in a build that contains the mock attester.
const SimulatedEnclave = true

func init() {
	attesterFactories["mock"] = func(c AttesterConfig) (attest.Attester, error) {
		if c.CADir == "" {
			return nil, errors.New("attester.ca_dir is required for the mock attester")
		}
		ca, err := attest.LoadMockCA(c.CADir)
		if err != nil {
			return nil, err
		}
		var pcr0 []byte
		switch {
		case c.PCR0 != "":
			if pcr0, err = hex.DecodeString(c.PCR0); err != nil || len(pcr0) != 48 {
				return nil, fmt.Errorf("attester.pcr0 must be 96 hex characters")
			}
		case c.MeasureBinary != "" && c.MeasureConfig != "":
			if pcr0, err = attest.MeasureFiles(c.MeasureBinary, c.MeasureConfig); err != nil {
				return nil, err
			}
		default:
			return nil, errors.New("attester: set pcr0, or measure_binary and measure_config")
		}
		return &attest.MockAttester{CA: ca, PCR0: pcr0, PCR8: attest.MeasureCert([]byte("mock signing cert"))}, nil
	}
}
