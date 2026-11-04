// Package cosigner is the wire format between party B's mpc-party and the qv-cosigner process next to it: JSON over HTTP
// on a unix socket of mode 0600. It lives in the pure-Go api module so both the mpc-party module and the root module
// (which cannot import mpc-party/internal) share it. The intent package is opaque to mpc-party.
package cosigner

// Request asks the cosigner whether party B may join a signing session.
type Request struct {
	JobID         string `json:"job_id"`
	KeyID         string `json:"key_id"`
	KeysetID      string `json:"keyset_id"`
	Algorithm     int32  `json:"algorithm"` // mpcpartyv1.Algorithm
	Digest        []byte `json:"digest"`
	IntentPackage []byte `json:"intent_package"`
	PublicKey     []byte `json:"public_key"` // compressed point of the key that will sign
}

// Response is the answer. Allow=true allows. Allow=false with Unavailable=false is a DECISION: a policy refusal (Reason has
// the code and detail). Unavailable=true means the cosigner could not decide (its guard database failed, a deadline
// passed): nothing is allowed, but it is an outage, not a refusal. The two are separate fields on purpose: nobody
// matches on reason strings. A transport failure, a non-200 answer or a malformed body count as unavailable too.
type Response struct {
	Allow       bool   `json:"allow"`
	Unavailable bool   `json:"unavailable,omitempty"`
	Reason      string `json:"reason"`
}

// Path of the only endpoint.
const Path = "/authorize"
