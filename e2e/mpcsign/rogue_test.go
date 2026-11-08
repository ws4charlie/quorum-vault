package mpcsign_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/proto"

	"github.com/ws4charlie/quorum-vault/internal/gateway"
	"github.com/ws4charlie/quorum-vault/internal/gateway/gatewaytest"
	"github.com/ws4charlie/quorum-vault/internal/signjob"
	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
)

// rogue speaks the peer protocol to party B or to party C with party A's REAL certificate: what an attacker who owns A's host has.
// Each of the two asks ITS OWN cosigner (own process, config and replay guard): the same attacks must be refused by both.
type rogue struct {
	s  *stack
	cl pb.PeerClient
}

func (s *stack) rogue(t *testing.T, to string) *rogue {
	addr, pin := s.peerB, s.certB.pin
	if to == "C" {
		addr, pin = s.peerC, s.certC.pin
	}
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(pinnedTLS(s.certA, pin))))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return &rogue{s: s, cl: pb.NewPeerClient(conn)}
}

// bothTargets runs a rogue-party test against party B's cosigner, and again against party C's with party B DOWN (so the only
// pair left is A+C and C's cosigner is the independent check).
func bothTargets(t *testing.T, f func(t *testing.T, to string)) {
	for _, to := range []string{"B", "C"} {
		to := to
		t.Run("to_"+to, func(t *testing.T) { f(t, to) })
	}
}

func (s *stack) targetSetup(to string) {
	if to == "C" {
		s.b.kill()
	}
}

// open sends OPEN and returns B's first answer: an ACK (B accepted: a protocol run would start) or a FIN with the refusal.
func (r *rogue) open(t *testing.T, o *pb.Open) (ack bool, fin *pb.Fin) {
	t.Helper()
	c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel() // cancelling after an ACK abandons the session: B's run ends with a transport error
	st, err := r.cl.Session(c)
	if err != nil {
		t.Fatal(err)
	}
	var sid [16]byte
	rand.Read(sid[:])
	b, _ := proto.Marshal(o)
	if err := st.Send(&pb.Frame{SessionId: hex.EncodeToString(sid[:]), Kind: pb.FrameKind_FRAME_KIND_OPEN, Payload: b}); err != nil {
		t.Fatal(err)
	}
	f, err := st.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if f.Kind == pb.FrameKind_FRAME_KIND_ACK {
		return true, nil
	}
	var fn pb.Fin
	if err := proto.Unmarshal(f.Payload, &fn); err != nil {
		t.Fatal(err)
	}
	return false, &fn
}

func (r *rogue) signOpen(j signjob.Job, expected []byte) *pb.Open {
	pkg, err := gateway.EncodePackage(j)
	if err != nil {
		r.s.t.Fatal(err)
	}
	return &pb.Open{Op: pb.Op_OP_SIGN, Scheme: pb.Scheme_SCHEME_ECDSA_2OF3, Initiator: "A", Generation: 1, KeysetId: r.s.keysetID, KeyId: r.s.keyID,
		Algorithm: pb.Algorithm_ALGORITHM_ECDSA_SECP256K1, Digest: j.Digest, JobId: j.ID, IntentPackage: pkg, ExpectedPublicKey: expected}
}

// refused asserts B refused with kind and a reason containing want, and never ACKed (so no protocol run began).
func (r *rogue) refused(t *testing.T, o *pb.Open, kind pb.ErrorKind, want string) {
	t.Helper()
	ack, fin := r.open(t, o)
	if ack {
		t.Fatalf("B accepted the session (a protocol run would start); wanted refusal %q", want)
	}
	if fin.Ok || fin.Kind != kind || !strings.Contains(fin.Message, want) {
		t.Fatalf("B answered ok=%v kind=%v %q; want kind %v containing %q", fin.Ok, fin.Kind, fin.Message, kind, want)
	}
	t.Logf("refused: %s", fin.Message)
}

func (s *stack) signRequest(j signjob.Job) *pb.SignRequest {
	pkg, err := gateway.EncodePackage(j)
	if err != nil {
		s.t.Fatal(err)
	}
	return &pb.SignRequest{KeyId: s.keyID, Algorithm: pb.Algorithm_ALGORITHM_ECDSA_SECP256K1, Digest: j.Digest, JobId: j.ID, IntentPackage: pkg}
}

func TestRogueParty_Decisions(t *testing.T) { bothTargets(t, rogueDecisions) }

func rogueDecisions(t *testing.T, to string) {
	s := newStack(t, stackOpts{})
	s.provision(t, false)
	s.targetSetup(to)
	r := s.rogue(t, to)
	user, evil := gatewaytest.AddrUser, gatewaytest.AddrEvil

	t.Run("unapproved intent", func(t *testing.T) {
		j := s.h.Withdrawal("rogue-1", user, 500, 10) // no approvers
		r.refused(t, r.signOpen(j, s.pub33), pb.ErrorKind_ERROR_KIND_REFUSED, gateway.ReasonApprovals)
	})
	t.Run("approved intent with a changed payload", func(t *testing.T) {
		j := s.h.Withdrawal("rogue-2", user, 500, 11, "alice")
		e := s.h.Withdrawal("rogue-2e", evil, 500, 11, "alice") // other destination, same nonce
		j.Payload, j.Digest = e.Payload, e.Digest
		r.refused(t, r.signOpen(j, s.pub33), pb.ErrorKind_ERROR_KIND_REFUSED, gateway.ReasonTx)
	})
	t.Run("OPEN digest differs from the approved package", func(t *testing.T) {
		j := s.h.Withdrawal("rogue-2b", user, 500, 12, "alice")
		o := r.signOpen(j, s.pub33)
		o.Digest = crypto.Keccak256([]byte("something else"))
		r.refused(t, o, pb.ErrorKind_ERROR_KIND_REFUSED, gateway.ReasonTx)
	})
	t.Run("fee above the cap", func(t *testing.T) {
		in := signjob.Intent{Kind: "withdrawal", ID: "w-fee", Asset: "ETH", To: user.Hex(), Amount: "500"}
		spec := gatewaytest.ETH(user, 500, 13)
		spec.FeeCap, spec.Tip = bigInt(1e12), bigInt(1e12)
		r.refused(t, r.signOpen(s.h.Job("rogue-fee", in, spec, "alice"), s.pub33), pb.ErrorKind_ERROR_KIND_REFUSED, gateway.ReasonTx)
	})
	t.Run("empty expected key", func(t *testing.T) {
		j := s.h.Withdrawal("rogue-3", user, 500, 14, "alice")
		r.refused(t, r.signOpen(j, nil), pb.ErrorKind_ERROR_KIND_REFUSED, "without an expected public key")
	})
	t.Run("expected key is not the sender's", func(t *testing.T) {
		other, _ := crypto.GenerateKey()
		j := s.h.Withdrawal("rogue-4", user, 500, 15, "alice")
		r.refused(t, r.signOpen(j, crypto.CompressPubkey(&other.PublicKey)), pb.ErrorKind_ERROR_KIND_REFUSED, "signer_key_mismatch")
	})
	t.Run("unknown key id path: package for another job id", func(t *testing.T) {
		j := s.h.Withdrawal("rogue-5", user, 500, 16, "alice")
		o := r.signOpen(j, s.pub33)
		o.JobId = "rogue-5-other"
		r.refused(t, o, pb.ErrorKind_ERROR_KIND_REFUSED, gateway.ReasonIntent)
	})
	t.Run("valid approved intent replayed at nonce+1", func(t *testing.T) {
		// The legitimate signing goes through party A as the gateway would ask for it.
		j := s.h.Withdrawal("replay", user, 500, 0, "alice")
		x := ctx(t, 30*time.Second)
		if _, err := s.client.Sign(x, s.signRequest(j)); err != nil {
			t.Fatalf("legitimate signing failed: %v", err)
		}
		// Same approved intent (same id, same hash), next nonce: B's OWN guard remembers nonce 0.
		// The same intent bytes, not a rebuilt one: a rebuilt intent gets a new not_after if a second boundary passes.
		var in signjob.Intent
		if err := json.Unmarshal(j.Intent, &in); err != nil {
			t.Fatal(err)
		}
		again := s.h.Job("replay-n1", in, gatewaytest.ETH(user, 500, 1), "alice")
		r.refused(t, r.signOpen(again, s.pub33), pb.ErrorKind_ERROR_KIND_REFUSED, gateway.ReasonNonceChanged)
		// And the original digest again is a retry: B accepts it (it would sign the same digest again, never a new one).
		if ack, fin := r.open(t, r.signOpen(j, s.pub33)); !ack {
			t.Fatalf("an identical retry was refused: %+v", fin)
		}
	})
}

// A rogue party A asks party B to take part in hot-to-cold moves it should refuse: B's cosigner holds its own copy of the cold
// address, rate and daily cap, so owning A (or the gateway) does not let anyone move funds anywhere but the cold address.
func TestRogueParty_ToCold(t *testing.T) { bothTargets(t, rogueToCold) }

func rogueToCold(t *testing.T, to string) {
	s := newStack(t, stackOpts{})
	s.provision(t, false)
	s.targetSetup(to)
	r := s.rogue(t, to)
	cold, evil := gatewaytest.AddrCold, gatewaytest.AddrEvil

	t.Run("another destination, no approvals needed to ask", func(t *testing.T) {
		r.refused(t, r.signOpen(s.h.ToCold("tc-1", evil, evil, 100, 20), s.pub33), pb.ErrorKind_ERROR_KIND_REFUSED, gateway.ReasonTx)
	})
	t.Run("intent says cold, transaction pays the attacker", func(t *testing.T) {
		r.refused(t, r.signOpen(s.h.ToCold("tc-2", cold, evil, 100, 21), s.pub33), pb.ErrorKind_ERROR_KIND_REFUSED, gateway.ReasonTx)
	})
	t.Run("approvals do not rescue a wrong destination", func(t *testing.T) {
		r.refused(t, r.signOpen(s.h.ToCold("tc-3", evil, evil, 100, 22, "alice", "bob"), s.pub33), pb.ErrorKind_ERROR_KIND_REFUSED, gateway.ReasonTx)
	})
	t.Run("over the daily cap with approvals attached", func(t *testing.T) {
		r.refused(t, r.signOpen(s.h.ToCold("tc-4", cold, cold, 7000, 23, "alice", "bob"), s.pub33), pb.ErrorKind_ERROR_KIND_REFUSED, gateway.ReasonToColdCap)
	})
	t.Run("a legitimate move is accepted, then the rate limit holds", func(t *testing.T) {
		for i, n := range []int{2000, 2000} {
			ack, fin := r.open(t, r.signOpen(s.h.ToCold(fmt.Sprintf("tc-ok-%d", i), cold, cold, int64(n), uint64(30+i)), s.pub33))
			if !ack {
				t.Fatalf("legitimate move %d refused: %+v", i, fin)
			}
		}
		r.refused(t, r.signOpen(s.h.ToCold("tc-rate", cold, cold, 100, 32), s.pub33), pb.ErrorKind_ERROR_KIND_REFUSED, gateway.ReasonToColdRate)
	})
}

// A rogue party A asks party B to take part in rebalances it should refuse: B's cosigner holds its own list of hot shards, rate and
// daily cap, so owning A (or the gateway) does not let anyone move hot funds anywhere but to another shard of the pool.
func TestRogueParty_Rebalance(t *testing.T) { bothTargets(t, rogueRebalance) }

func rogueRebalance(t *testing.T, to string) {
	s := newStack(t, stackOpts{})
	s.provision(t, false)
	s.targetSetup(to)
	r := s.rogue(t, to)
	shard2, evil := gatewaytest.AddrShard2, gatewaytest.AddrEvil

	t.Run("destination outside the pinned shards", func(t *testing.T) {
		r.refused(t, r.signOpen(s.h.Rebalance("rb-1", evil, evil, 100, 40), s.pub33), pb.ErrorKind_ERROR_KIND_REFUSED, gateway.ReasonTx)
	})
	t.Run("intent says a shard, transaction pays the attacker", func(t *testing.T) {
		r.refused(t, r.signOpen(s.h.Rebalance("rb-2", shard2, evil, 100, 41), s.pub33), pb.ErrorKind_ERROR_KIND_REFUSED, gateway.ReasonTx)
	})
	t.Run("approvals do not rescue a wrong destination", func(t *testing.T) {
		r.refused(t, r.signOpen(s.h.Rebalance("rb-3", evil, evil, 100, 42, "alice", "bob"), s.pub33), pb.ErrorKind_ERROR_KIND_REFUSED, gateway.ReasonTx)
	})
	t.Run("a shard of another pool", func(t *testing.T) {
		r.refused(t, r.signOpen(s.h.Rebalance("rb-4", gatewaytest.AddrOtherPl, gatewaytest.AddrOtherPl, 100, 43), s.pub33), pb.ErrorKind_ERROR_KIND_REFUSED, gateway.ReasonTx)
	})
	t.Run("over the daily cap with approvals attached", func(t *testing.T) {
		r.refused(t, r.signOpen(s.h.Rebalance("rb-5", shard2, shard2, 7000, 44, "alice", "bob"), s.pub33), pb.ErrorKind_ERROR_KIND_REFUSED, gateway.ReasonRebalanceCap)
	})
	t.Run("a legitimate rebalance is accepted, then the rate limit holds", func(t *testing.T) {
		for i, n := range []int{2000, 2000} {
			ack, fin := r.open(t, r.signOpen(s.h.Rebalance(fmt.Sprintf("rb-ok-%d", i), shard2, shard2, int64(n), uint64(50+i)), s.pub33))
			if !ack {
				t.Fatalf("legitimate rebalance %d refused: %+v", i, fin)
			}
		}
		r.refused(t, r.signOpen(s.h.Rebalance("rb-rate", shard2, shard2, 100, 52), s.pub33), pb.ErrorKind_ERROR_KIND_REFUSED, gateway.ReasonRebalanceRate)
	})
}

func TestRogueParty_DailyCapSplitting(t *testing.T) { bothTargets(t, rogueDailyCapSplitting) }

func rogueDailyCapSplitting(t *testing.T, to string) {
	s := newStack(t, stackOpts{})
	s.provision(t, false)
	s.targetSetup(to)
	r := s.rogue(t, to)
	// Policy: 8000 per day, 5000 per transaction, two approvals above 1000. Split 12000 into three approved withdrawals.
	for i := 0; i < 2; i++ {
		j := s.h.Withdrawal(fmt.Sprintf("split-%d", i), gatewaytest.AddrUser, 4000, uint64(i), "alice", "bob")
		if ack, fin := r.open(t, r.signOpen(j, s.pub33)); !ack {
			t.Fatalf("withdrawal %d refused: %+v", i, fin)
		}
	}
	j := s.h.Withdrawal("split-2", gatewaytest.AddrUser, 4000, 2, "alice", "bob")
	r.refused(t, r.signOpen(j, s.pub33), pb.ErrorKind_ERROR_KIND_REFUSED, gateway.ReasonDailyCap)
}

func TestRogueParty_AdminOperations(t *testing.T) { bothTargets(t, rogueAdminOperations) }

func rogueAdminOperations(t *testing.T, to string) {
	s := newStack(t, stackOpts{})
	s.provision(t, false)
	s.targetSetup(to)
	r := s.rogue(t, to)
	otherPub, otherPriv := newAdminKey()
	// The keyset is a 2-of-3 one (and party C holds 2-of-3 keysets only), so these admin operations are three-party ones (a group id,
	// the scheme); B is also asked to create a 2-party keyset, the old way.
	mk := func(o *pb.Open) *pb.Open {
		if to == "C" || o.Op != pb.Op_OP_DKG { // the keyset is a 2-of-3 one; B is also asked to create a 2-party keyset the old way
			var g [16]byte
			rand.Read(g[:])
			o.Scheme, o.Initiator, o.Group = pb.Scheme_SCHEME_ECDSA_2OF3, "A", hex.EncodeToString(g[:])
		}
		return o
	}
	_ = otherPub
	for _, op := range []struct {
		name string
		op   pb.Op
		str  string
	}{{"refresh", pb.Op_OP_REFRESH, "refresh"}, {"dkg", pb.Op_OP_DKG, "dkg"}, {"unfreeze", pb.Op_OP_UNFREEZE, "unfreeze"}} {
		keyset := s.keysetID
		if op.op == pb.Op_OP_DKG {
			keyset = "rogue-keyset"
		}
		t.Run(op.name+" without a signature", func(t *testing.T) {
			r.refused(t, mk(&pb.Open{Op: op.op, KeysetId: keyset, Curve: pb.Curve_CURVE_SECP256K1}), pb.ErrorKind_ERROR_KIND_REFUSED, "admin authorization")
		})
		t.Run(op.name+" signed by a key B does not know", func(t *testing.T) {
			r.refused(t, mk(&pb.Open{Op: op.op, KeysetId: keyset, Curve: pb.Curve_CURVE_SECP256K1, Admin: signWith(otherPriv, op.str, keyset, time.Now())}),
				pb.ErrorKind_ERROR_KIND_REFUSED, "not a configured admin key")
		})
		t.Run(op.name+" with a stale timestamp", func(t *testing.T) {
			r.refused(t, mk(&pb.Open{Op: op.op, KeysetId: keyset, Curve: pb.Curve_CURVE_SECP256K1, Admin: s.adminAuth(op.str, keyset, time.Now().Add(-time.Hour))}),
				pb.ErrorKind_ERROR_KIND_REFUSED, "outside the accepted window")
		})
		t.Run(op.name+" with a signature for another operation", func(t *testing.T) {
			wrong := "refresh"
			if op.str == "refresh" {
				wrong = "dkg"
			}
			r.refused(t, mk(&pb.Open{Op: op.op, KeysetId: keyset, Curve: pb.Curve_CURVE_SECP256K1, Admin: s.adminAuth(wrong, keyset, adminNow())}),
				pb.ErrorKind_ERROR_KIND_REFUSED, "bad signature")
		})
	}
	// The same operations through party A's caller port are refused by A as well (A checks its own admin keys).
	x := ctx(t, 20*time.Second)
	if _, err := s.client.Refresh(x, &pb.RefreshRequest{KeysetId: s.keysetID}); err == nil {
		t.Fatal("A accepted a Refresh without an admin signature")
	}
}
