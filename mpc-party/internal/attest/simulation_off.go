//go:build !teesim

package attest

// SimulationBuild is false in the production build: it has no mock attester and no test root. Build with -tags teesim for development and CI.
const SimulationBuild = false
