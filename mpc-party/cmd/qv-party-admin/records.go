package main

// The two versioned records of the parties, changed by an admin request every member verifies itself:
//
//	qv-party-admin admin-set request    <party flags> [-add HEX]... [-remove HEX]... [-threshold M] [-finish] [-domain NAME] [-valid-for 1h] [-out F]
//	qv-party-admin admin-set send       <party flags> -auth F [policy flags]
//	qv-party-admin recovery-key request <party flags> -current-public FILE [-retire FPR]... [-valid-for 1h] [-out F]
//	qv-party-admin recovery-key send    <party flags> -auth F
//	qv-party-admin recovery-key status  <party flags> [-keyset ID]
//	qv-party-admin recovery-key registry <party flags> -out FILE
//
// `sign -in F` and `verify -in F` work on these files as on any other request. A request names the version it creates and the hash of the record
// it replaces, so it is read from the parties' own state (`request` asks them); the signatures of the current admin set, and for an admin-set
// request those of the new set too, make it valid. See docs/runbooks/key-ceremony.md and docs/runbooks/mpc-backup-restore.md.

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/ws4charlie/quorum-vault/mpc-party/api/admin"
	pb "github.com/ws4charlie/quorum-vault/mpc-party/api/mpcparty/v1"
)

func recordsCmd(group string, args []string, out, errw io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: qv-party-admin %s request|send%s (see the file header of cmd/qv-party-admin/records.go)", group, map[string]string{"recovery-key": "|status|registry"}[group])
	}
	sub, rest := args[0], args[1:]
	switch {
	case group == "admin-set" && sub == "request":
		return adminSetRequestCmd(rest, out, errw)
	case group == "admin-set" && sub == "send", group == "recovery-key" && sub == "send":
		return recordSendCmd(group, rest, out, errw)
	case group == "recovery-key" && sub == "request":
		return recoveryRequestCmd(rest, out, errw)
	case group == "recovery-key" && sub == "status":
		return recoveryStatusCmd(rest, out)
	case group == "recovery-key" && sub == "registry":
		return recoveryRegistryCmd(rest, out)
	}
	return fmt.Errorf("unknown command %q %q", group, sub)
}

// ---- reading the parties' records ----

func shortHex(b []byte) string {
	if len(b) == 0 {
		return "-"
	}
	h := hex.EncodeToString(b)
	return h[:min(len(h), 12)]
}

// answered are the views of the parties that answered.
func answered(vs []view) []view {
	var l []view
	for _, v := range vs {
		if v.err == nil {
			l = append(l, v)
		}
	}
	return l
}

// adminSetProblems lists every way the parties' admin sets (and recovery registries) disagree, and every party that does not report them.
func recordProblems(vs []view) []string {
	var bad []string
	var ref *view
	for i := range vs {
		v := &vs[i]
		if v.err != nil {
			continue // "did not answer" is reported by compare
		}
		if v.health.AdminSet == nil {
			bad = append(bad, fmt.Sprintf("party %s reports no admin set (an older version, or its state cannot be read)", v.name))
			continue
		}
		if ref == nil {
			ref = v
			continue
		}
		a, b := v.health.AdminSet, ref.health.AdminSet
		if a.Version != b.Version || !bytes.Equal(a.SetHash, b.SetHash) {
			bad = append(bad, fmt.Sprintf("admin set: party %s is at version %d (%s) but party %s at version %d (%s): the change is not on every party; finish it with `admin-set request -finish`", v.name, a.Version, shortHex(a.SetHash), ref.name, b.Version, shortHex(b.SetHash)))
		}
	}
	ref = nil
	for i := range vs {
		v := &vs[i]
		if v.err != nil || v.health.RecoveryKey == nil && v.health.AdminSet == nil {
			continue
		}
		rk := v.health.RecoveryKey
		if rk == nil {
			bad = append(bad, fmt.Sprintf("party %s reports no recovery-key registry (its record cannot be read)", v.name))
			continue
		}
		if ref == nil {
			ref = v
			continue
		}
		b := ref.health.RecoveryKey
		if rk.Version != b.Version || !bytes.Equal(rk.Hash, b.Hash) {
			bad = append(bad, fmt.Sprintf("recovery-key registry: party %s is at version %d but party %s at version %d: send the change again", v.name, rk.Version, ref.name, b.Version))
		}
	}
	return bad
}

func printRecords(out io.Writer, h *pb.HealthResponse) {
	if a := h.AdminSet; a != nil {
		src := "bootstrap list of the configuration"
		if a.FromState {
			src = "durable state"
		}
		extra := ""
		if a.ConfigDiffers {
			extra = ", the configuration's list is IGNORED"
		}
		fmt.Fprintf(out, "  admin set: version %d, %d of %d keys, hash %s (%s%s)\n", a.Version, a.Threshold, len(a.Keys), shortHex(a.SetHash), src, extra)
	}
	if r := h.RecoveryKey; r != nil {
		cur := r.Current
		if cur == "" {
			cur = "none registered"
		} else {
			cur = cur[:12]
		}
		fmt.Fprintf(out, "  recovery keys: registry version %d, current %s, %d retired\n", r.Version, cur, len(r.Retired))
	}
}

// liveSet is the admin set the coordinator (the first party) reports, with the check that every party that answered is at the same version.
func liveSet(vs []view) (*pb.AdminSetStatus, error) {
	if len(vs) == 0 || vs[0].err != nil {
		return nil, errors.New("the coordinator (party A) did not answer: it forwards the request to the others")
	}
	a := vs[0].health.AdminSet
	if a == nil {
		return nil, errors.New("party A reports no admin set: it is an older version, or its admin state cannot be read")
	}
	return a, nil
}

func policyOfStatus(a *pb.AdminSetStatus) admin.Policy {
	p := admin.Policy{Threshold: int(a.Threshold), MaxValidity: time.Duration(a.MaxValiditySeconds) * time.Second, Skew: time.Duration(a.MaxAgeSeconds) * time.Second, Domain: a.Domain}
	for _, k := range a.Keys {
		p.Keys = append(p.Keys, k)
	}
	return p
}

// ---- admin-set request ----

func adminSetRequestCmd(args []string, out, errw io.Writer) error {
	fs := flag.NewFlagSet("admin-set request", flag.ContinueOnError)
	fs.SetOutput(errw)
	var c common
	c.flags(fs)
	var add, remove stringList
	fs.Var(&add, "add", "an admin public key (64 hex) to add to the set (repeat)")
	fs.Var(&remove, "remove", "an admin public key (64 hex) to take out of the set (repeat)")
	threshold := fs.Int("threshold", 0, "the new threshold (default: keep the current one)")
	finish := fs.Bool("finish", false, "make the request that brings the parties that are one version behind to where party A is (the same set, signed by the set they still have)")
	domain := fs.String("domain", "", "the parties' admin_domain (default: what party A reports)")
	validFor := fs.Duration("valid-for", admin.DefaultValidity, "how long the request stays valid")
	outFile := fs.String("out", "", "write the file here (default stdout)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := c.check(); err != nil {
		return err
	}
	cs, err := c.dial()
	if err != nil {
		return err
	}
	defer closeAll(cs)
	vs := healthOf(context.Background(), cs)
	printStatus(errw, vs, "")
	a, err := liveSet(vs)
	if err != nil {
		return err
	}
	dom := *domain
	if dom == "" {
		dom = a.Domain
	}
	var r admin.Request
	if *finish {
		if len(add)+len(remove) > 0 || *threshold != 0 {
			return errors.New("-finish makes the request for the change party A already has: do not give -add, -remove or -threshold")
		}
		var prev []byte
		for _, v := range answered(vs) {
			s := v.health.AdminSet
			if s == nil || s.Version == a.Version {
				continue
			}
			if s.Version+1 != a.Version {
				return fmt.Errorf("party %s is at version %d and party A at %d: it is more than one change behind. Send it the earlier requests, in order (each one still needs the signatures of the set it replaces)", v.name, s.Version, a.Version)
			}
			if prev != nil && !bytes.Equal(prev, s.SetHash) {
				return errors.New("the parties that are behind do not hold the same set: look at `status` and finish them one by one")
			}
			prev = s.SetHash
		}
		if prev == nil {
			return errors.New("no party that answered is behind party A: nothing to finish")
		}
		var h [32]byte
		copy(h[:], prev)
		keys := make([][]byte, len(a.Keys))
		copy(keys, a.Keys)
		// version = A's, predecessor = the behind parties' set
		body := admin.AdminSetBody(a.Version, keys, int(a.Threshold), h)
		r, err = requestFromBody(body, dom, *validFor)
		if err != nil {
			return err
		}
	} else {
		keys, thr, err := newSet(a, add, remove, *threshold)
		if err != nil {
			return err
		}
		for _, v := range answered(vs) {
			if s := v.health.AdminSet; s != nil && (s.Version != a.Version || !bytes.Equal(s.SetHash, a.SetHash)) {
				return fmt.Errorf("party %s is at admin set version %d and party A at %d: finish the earlier change first (`admin-set request -finish`)", v.name, s.Version, a.Version)
			}
		}
		var h [32]byte
		copy(h[:], a.SetHash)
		r, err = admin.NewSetRequest(dom, a.Version, h, keys, thr, time.Now(), *validFor)
		if err != nil {
			return err
		}
	}
	ch, _ := r.SetChange()
	fmt.Fprintf(errw, "request: admin set version %d: %d keys, threshold %d\n%s\nvalid until %s: it needs %d signature(s) of the CURRENT admin set (%d keys) and %d of the NEW set (qv-party-admin sign), then admin-set send\n",
		ch.SetVersion, len(ch.SetKeys), ch.SetThreshold, describe(r), time.Unix(r.ExpiresUnix, 0).Format("2006-01-02 15:04:05 MST"), requiredFrom(vs, *finish, a), len(a.Keys), ch.SetThreshold)
	return writeRequest(r, *outFile, out)
}

func requiredFrom(vs []view, finish bool, a *pb.AdminSetStatus) int {
	if finish { // the behind parties' own set signs: its threshold
		for _, v := range answered(vs) {
			if s := v.health.AdminSet; s != nil && s.Version != a.Version {
				return int(s.Threshold)
			}
		}
	}
	return int(a.Threshold)
}

func requestFromBody(body *pb.AdminSetRequest, domain string, validFor time.Duration) (admin.Request, error) {
	if err := admin.CheckAdminSet(body.SetKeys, int(body.SetThreshold)); err != nil {
		return admin.Request{}, err
	}
	var h [32]byte
	copy(h[:], body.SetPrevHash)
	// NewSetRequest makes version curVersion+1
	return admin.NewSetRequest(domain, body.SetVersion-1, h, body.SetKeys, int(body.SetThreshold), time.Now(), validFor)
}

// newSet is the current set with the keys added and removed and the threshold changed, checked.
func newSet(a *pb.AdminSetStatus, add, remove []string, threshold int) ([][]byte, int, error) {
	cur := map[string]bool{}
	var keys [][]byte
	for _, k := range a.Keys {
		cur[string(k)] = true
		keys = append(keys, k)
	}
	dec := func(s string) ([]byte, error) {
		b, err := hex.DecodeString(strings.TrimSpace(s))
		if err != nil || len(b) != 32 {
			return nil, fmt.Errorf("%q is not 32 bytes of hex", s)
		}
		return b, nil
	}
	for _, s := range remove {
		b, err := dec(s)
		if err != nil {
			return nil, 0, err
		}
		if !cur[string(b)] {
			return nil, 0, fmt.Errorf("-remove %s: not in the current admin set", s)
		}
		delete(cur, string(b))
	}
	var next [][]byte
	for _, k := range keys {
		if cur[string(k)] {
			next = append(next, k)
		}
	}
	for _, s := range add {
		b, err := dec(s)
		if err != nil {
			return nil, 0, err
		}
		if cur[string(b)] {
			return nil, 0, fmt.Errorf("-add %s: already in the admin set", s)
		}
		cur[string(b)] = true
		next = append(next, b)
	}
	if threshold == 0 {
		threshold = int(a.Threshold)
	}
	if len(add)+len(remove) == 0 && threshold == int(a.Threshold) {
		return nil, 0, errors.New("nothing to change: give -add, -remove or a different -threshold")
	}
	if err := admin.CheckAdminSet(next, threshold); err != nil {
		return nil, 0, err
	}
	return next, threshold, nil
}

func writeRequest(r admin.Request, outFile string, out io.Writer) error {
	if outFile == "" {
		_, err := out.Write(r.JSON())
		return err
	}
	return os.WriteFile(outFile, r.JSON(), 0o600)
}

// ---- recovery-key request / status / registry ----

func recoveryRequestCmd(args []string, out, errw io.Writer) error {
	fs := flag.NewFlagSet("recovery-key request", flag.ContinueOnError)
	fs.SetOutput(errw)
	var c common
	c.flags(fs)
	pub := fs.String("current-public", "", "the recovery PUBLIC key file backups must be made under from now on")
	var retire stringList
	fs.Var(&retire, "retire", "a recovery key fingerprint (64 hex) to retire (repeat; default: the key that is current now, when it is another one)")
	domain := fs.String("domain", "", "the parties' admin_domain (default: what party A reports)")
	validFor := fs.Duration("valid-for", admin.DefaultValidity, "how long the request stays valid")
	outFile := fs.String("out", "", "write the file here (default stdout)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *pub == "" {
		return errors.New("-current-public is required")
	}
	raw, err := os.ReadFile(*pub)
	if err != nil {
		return err
	}
	fpr, err := admin.RecoveryFingerprint(raw)
	if err != nil {
		return fmt.Errorf("%s: %w", *pub, err)
	}
	if err := c.check(); err != nil {
		return err
	}
	cs, err := c.dial()
	if err != nil {
		return err
	}
	defer closeAll(cs)
	vs := healthOf(context.Background(), cs)
	printStatus(errw, vs, "")
	a, err := liveSet(vs)
	if err != nil {
		return err
	}
	for _, v := range answered(vs) {
		if v.health.RecoveryKey == nil {
			return fmt.Errorf("party %s reports no recovery-key registry", v.name)
		}
	}
	reg := vs[0].health.RecoveryKey
	for _, v := range answered(vs) {
		if v.health.RecoveryKey.Version != reg.Version || !bytes.Equal(v.health.RecoveryKey.Hash, reg.Hash) {
			return fmt.Errorf("party %s and party A hold different recovery-key registries (versions %d and %d): send the last change again before a new one", v.name, v.health.RecoveryKey.Version, reg.Version)
		}
	}
	ret := []string(retire)
	if len(ret) == 0 && reg.Current != "" && reg.Current != fpr {
		ret = []string{reg.Current}
	}
	dom := *domain
	if dom == "" {
		dom = a.Domain
	}
	var h [32]byte
	copy(h[:], reg.Hash)
	r, err := admin.NewRecoveryRequest(dom, reg.Version, h, fpr, ret, time.Now(), *validFor)
	if err != nil {
		return err
	}
	fmt.Fprintf(errw, "request: recovery-key registry version %d: current key %s, retire %s\n%s\nvalid until %s: it needs the signatures of the party's admin_threshold admin keys (qv-party-admin sign), then recovery-key send\n",
		reg.Version+1, fpr, orNone(ret), describe(r), time.Unix(r.ExpiresUnix, 0).Format("2006-01-02 15:04:05 MST"))
	return writeRequest(r, *outFile, out)
}

func orNone(l []string) string {
	if len(l) == 0 {
		return "nothing"
	}
	return strings.Join(l, ", ")
}

// recordSendCmd sends an admin-set or recovery-key request through party A and says what every member did.
func recordSendCmd(group string, args []string, out, errw io.Writer) error {
	fs := flag.NewFlagSet(group+" send", flag.ContinueOnError)
	fs.SetOutput(errw)
	var c common
	c.flags(fs)
	authFile := fs.String("auth", "", "the request file, signed (`sign -in`)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *authFile == "" {
		return errors.New("-auth is required: a request file signed by the admins; this command holds no signing key")
	}
	if err := c.check(); err != nil {
		return err
	}
	raw, err := os.ReadFile(*authFile)
	if err != nil {
		return err
	}
	if admin.FileVersion(raw) != 2 {
		return fmt.Errorf("%s is not a v2 request file", *authFile)
	}
	r, err := admin.ParseRequest(raw)
	if err != nil {
		return fmt.Errorf("%s: %w", *authFile, err)
	}
	if r.Op != group {
		return fmt.Errorf("%s is a request for %s, not for %s", *authFile, r.Op, group)
	}
	auth, err := r.Auth()
	if err != nil {
		return fmt.Errorf("%s: %w (sign it first)", *authFile, err)
	}
	cs, err := c.dial()
	if err != nil {
		return err
	}
	defer closeAll(cs)
	ctx := context.Background()
	before := healthOf(ctx, cs)
	printStatus(out, before, "")
	if _, err := liveSet(before); err != nil {
		return err
	}
	// Before anything is sent: would any party that is not already there take it? A party that is behind judges the file by its OWN set.
	now := time.Now()
	var would, wont []string
	for _, v := range answered(before) {
		s := v.health.AdminSet
		if s == nil {
			continue
		}
		if r.Op == admin.OpAdminSet {
			ch, _ := r.SetChange()
			if s.Version == ch.SetVersion && bytes.Equal(s.SetHash, admin.SetHashOf(ch)) {
				would = append(would, v.name+" (already has it)")
				continue
			}
		}
		if err := r.Check(policyOfStatus(s), now); err != nil {
			wont = append(wont, fmt.Sprintf("party %s would refuse it: %v", v.name, err))
		} else {
			would = append(would, v.name)
		}
	}
	if len(would) == 0 {
		return fmt.Errorf("%s would be refused by every party that answered:\n  - %s\nnothing was sent", *authFile, strings.Join(wont, "\n  - "))
	}
	for _, w := range wont {
		fmt.Fprintln(errw, "WARNING:", w)
	}
	x, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	var members []*pb.RecordMember
	switch r.Op {
	case admin.OpAdminSet:
		ch, _ := r.SetChange()
		ch.Admin = auth
		resp, err := cs[0].client.AdminSet(x, ch)
		if err != nil {
			return fmt.Errorf("admin-set through party %s: %w", cs[0].name, err)
		}
		members = resp.Members
	case admin.OpRecoveryKey:
		ch, _ := r.RecoveryChange()
		ch.Admin = auth
		resp, err := cs[0].client.RecoveryKey(x, ch)
		if err != nil {
			return fmt.Errorf("recovery-key through party %s: %w", cs[0].name, err)
		}
		members = resp.Members
	}
	notDone := 0
	for _, m := range members {
		fmt.Fprintf(out, "party %s: %s", m.Name, outcomeName(m.Outcome))
		if m.Detail != "" {
			fmt.Fprintf(out, ": %s", m.Detail)
		}
		if m.Version > 0 || m.Outcome == pb.RecordOutcome_RECORD_OUTCOME_APPLIED || m.Outcome == pb.RecordOutcome_RECORD_OUTCOME_ALREADY {
			fmt.Fprintf(out, " (version %d)", m.Version)
		}
		fmt.Fprintln(out)
		if m.Outcome != pb.RecordOutcome_RECORD_OUTCOME_APPLIED && m.Outcome != pb.RecordOutcome_RECORD_OUTCOME_ALREADY {
			notDone++
		}
	}
	after := healthOf(ctx, cs)
	printStatus(out, after, "")
	problems := recordProblems(after)
	if notDone > 0 || len(problems) > 0 {
		hint := "send the same file again once the party is back (a party that already has the change answers \"already\"); if the file expired or the party restarted since, make the same change again: `admin-set request -finish`"
		if r.Op == admin.OpRecoveryKey {
			hint = "send the same file again once the party is back, or make a new request (it names the registry's version)"
		}
		return fmt.Errorf("%d member(s) did not take the change. The parties that did keep it; the others stay on their old state, which `status` shows.\n  - %s\n%s", notDone, strings.Join(append(problems, "next: "+hint), "\n  - "), "")
	}
	fmt.Fprintf(out, "OK %s: all %d parties are on the same state\n", r.Op, len(after))
	return nil
}

func outcomeName(o pb.RecordOutcome) string {
	switch o {
	case pb.RecordOutcome_RECORD_OUTCOME_APPLIED:
		return "applied"
	case pb.RecordOutcome_RECORD_OUTCOME_ALREADY:
		return "already had it"
	case pb.RecordOutcome_RECORD_OUTCOME_REFUSED:
		return "REFUSED"
	case pb.RecordOutcome_RECORD_OUTCOME_UNREACHABLE:
		return "UNREACHABLE"
	}
	return "unknown"
}

// recoveryRows says, per keyset and party, where the replacement of the recovery key stands: one line each, and the next step.
type recoveryRow struct {
	keyset, party string
	state         string // ok, stale, retired, none
	detail        string
}

func recoveryRows(vs []view, want string) (rows []recoveryRow, cur string, regOK bool) {
	regOK = true
	for _, v := range answered(vs) {
		if v.health.RecoveryKey == nil {
			regOK = false
			continue
		}
		if cur == "" {
			cur = v.health.RecoveryKey.Current
		}
	}
	ids := map[string]bool{}
	for _, v := range answered(vs) {
		for id := range keysetMap(v.health) {
			if want == "" || id == want {
				ids[id] = true
			}
		}
	}
	var sorted []string
	for id := range ids {
		sorted = append(sorted, id)
	}
	sort.Strings(sorted)
	for _, id := range sorted {
		for _, v := range answered(vs) {
			k := keysetMap(v.health)[id]
			if k == nil {
				continue
			}
			row := recoveryRow{keyset: id, party: v.name}
			switch {
			case k.BackupGeneration == 0:
				row.state, row.detail = "none", "no verified backup"
			case k.BackupStale:
				row.state, row.detail = "stale", fmt.Sprintf("newest backup is generation %d, the keyset is at %d (under %s)", k.BackupGeneration, k.Generation, fprOrUnknown(k.BackupRecoveryKey))
			case k.BackupKeyRetired:
				row.state, row.detail = "retired", fmt.Sprintf("newest backup is under %s, not the current recovery key", fprOrUnknown(k.BackupRecoveryKey))
			default:
				row.state, row.detail = "ok", fmt.Sprintf("generation %d under %s", k.BackupGeneration, fprOrUnknown(k.BackupRecoveryKey))
			}
			rows = append(rows, row)
		}
	}
	return rows, cur, regOK
}

func fprOrUnknown(f string) string {
	if f == "" {
		return "an unrecorded key"
	}
	return f[:12]
}

func recoveryStatusCmd(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("recovery-key status", flag.ContinueOnError)
	var c common
	c.flags(fs)
	keyset := fs.String("keyset", "", "show only this keyset")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := c.check(); err != nil {
		return err
	}
	cs, err := c.dial()
	if err != nil {
		return err
	}
	defer closeAll(cs)
	vs := healthOf(context.Background(), cs)
	for _, v := range vs {
		if v.err != nil {
			fmt.Fprintf(out, "party %s: UNREACHABLE: %v\n", v.name, v.err)
			continue
		}
		fmt.Fprintf(out, "party %s:\n", v.name)
		printRecords(out, v.health)
	}
	rows, cur, regOK := recoveryRows(vs, *keyset)
	fmt.Fprintf(out, "\ncurrent recovery key: %s\n", func() string {
		if cur == "" {
			return "none registered (a registry change names it: recovery-key request)"
		}
		return cur
	}())
	todo := map[string][]string{}
	pending := 0
	for _, r := range rows {
		fmt.Fprintf(out, "  keyset %-24s party %s  %-8s %s\n", r.keyset, r.party, strings.ToUpper(r.state), r.detail)
		if r.state != "ok" {
			pending++
			todo[r.keyset] = append(todo[r.keyset], r.party)
		}
	}
	problems := recordProblems(vs)
	for _, v := range vs {
		if v.err != nil {
			problems = append(problems, fmt.Sprintf("party %s did not answer", v.name))
		}
	}
	if cur == "" || !regOK {
		problems = append(problems, "no current recovery key is registered on every party")
	}
	if len(problems) == 0 && pending == 0 && len(rows) > 0 {
		fmt.Fprintln(out, "\nCOMPLETE: every keyset has a verified, current backup under the current recovery key on every party")
		return nil
	}
	var ids []string
	for id := range todo {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	fmt.Fprintln(out, "\nnext:")
	for _, id := range ids {
		stale := false
		for _, r := range rows {
			if r.keyset == id && (r.state == "stale" || r.state == "retired") {
				stale = true
			}
		}
		if stale {
			fmt.Fprintf(out, "  keyset %s: if its shares may have been exposed with the old recovery key, REFRESH it first (qv-party-admin request -op refresh -keyset %s, sign, send): old backups then stop working; then on each of %s: mpc-party backup export -config PARTY.json -keyset %s -recovery-public NEW.public -out FILE\n", id, id, strings.Join(todo[id], ", "), id)
		} else {
			fmt.Fprintf(out, "  keyset %s: on each of %s: mpc-party backup export -config PARTY.json -keyset %s -recovery-public NEW.public -out FILE\n", id, strings.Join(todo[id], ", "), id)
		}
	}
	for _, p := range problems {
		fmt.Fprintf(out, "  %s\n", p)
	}
	return errors.New("the replacement of the recovery key is not complete")
}

// recoveryRegistryCmd writes the registry the parties agree on, for the offline machine that restores backups (`mpc-party backup restore -registry`).
func recoveryRegistryCmd(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("recovery-key registry", flag.ContinueOnError)
	var c common
	c.flags(fs)
	outFile := fs.String("out", "", "write the registry here (public data: no secret)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := c.check(); err != nil {
		return err
	}
	if *outFile == "" {
		return errors.New("-out is required")
	}
	cs, err := c.dial()
	if err != nil {
		return err
	}
	defer closeAll(cs)
	vs := healthOf(context.Background(), cs)
	if p := recordProblems(vs); len(p) > 0 {
		return disagree(p)
	}
	for _, v := range vs {
		if v.err != nil {
			return fmt.Errorf("party %s did not answer: write the registry when every party is reachable", v.name)
		}
	}
	rk := vs[0].health.RecoveryKey
	if rk == nil {
		return errors.New("party A reports no recovery-key registry")
	}
	b, _ := json.MarshalIndent(struct {
		Version uint64   `json:"version"`
		Current string   `json:"current"`
		Retired []string `json:"retired"`
	}{rk.Version, rk.Current, rk.Retired}, "", "  ")
	if err := os.WriteFile(*outFile, append(b, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(out, "registry version %d written to %s (current %s, %d retired)\n", rk.Version, *outFile, rk.Current, len(rk.Retired))
	return nil
}
