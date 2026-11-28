//go:build !teesim

package server

// SimulatedEnclave is false in the production build: it has no mock attester. Its only attester is the Nitro one (sealer_attested_nitro.go, Linux
// only; outside an enclave /dev/nsm is missing and the party refuses to start).
const SimulatedEnclave = false

// SimulationMarker is empty in the production build.
const SimulationMarker = ""
