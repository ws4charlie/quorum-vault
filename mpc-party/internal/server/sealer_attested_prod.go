//go:build !teesim

package server

// SimulatedEnclave is false in the production build: it has no mock attester (and no real one yet: the Nitro attester is task TEE-T7), so
// sealer.type "attested" refuses to start.
const SimulatedEnclave = false
