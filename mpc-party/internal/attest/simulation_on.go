//go:build teesim

package attest

// SimulationBuild is true when built with -tags teesim: MockAttester and MockCA are compiled in. Never ship such a build.
const SimulationBuild = true
