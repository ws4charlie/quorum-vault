//go:build teesim

package server

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"

	"github.com/ws4charlie/quorum-vault/mpc-party/internal/attest"
)

// Simulation builds only (-tags teesim): the "mock" attester writes Nitro-format documents signed by a test CA (internal/attest/mock_teesim.go). It proves
// our code handles attestation; it proves nothing about isolation. A production build does not contain this file.

// SimulatedEnclave is true in a build that contains the mock attester.
const SimulatedEnclave = true

// SimulationMarker is printed at start and is in the binary's text: a tee-sim binary can be told from a production one by it.
const SimulationMarker = "QV-SIMULATED-ENCLAVE: this binary contains the mock attester (-tags teesim); it proves nothing about isolation"

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
		default:
			// What actually runs: this process's own executable and the config file it was started with, unless the config names other files
			// (tests do). A real enclave's PCR0 covers the whole image, config included; changing one byte of either file changes the measurement.
			bin, cfgPath := c.MeasureBinary, c.MeasureConfig
			if bin == "" {
				if bin, err = os.Executable(); err != nil {
					return nil, fmt.Errorf("attester: cannot find the running binary: %w", err)
				}
			}
			if cfgPath == "" {
				cfgPath = RunningConfigPath
			}
			if cfgPath == "" {
				return nil, errors.New("attester: set pcr0, or measure_config (the running party measures the config file it was started with)")
			}
			if pcr0, err = attest.MeasureFiles(bin, cfgPath); err != nil {
				return nil, err
			}
		}
		return &attest.MockAttester{CA: ca, PCR0: pcr0, Debug: c.Debug, PCR8: attest.MeasureCert([]byte("mock signing cert"))}, nil
	}
}
