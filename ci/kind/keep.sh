#!/usr/bin/env bash
# Keep mode for Gate's keyset hot-1 (QV_KIND_KEEP_GATE=1 or make KEEP=1; README "Keep mode"). Sourced by gate.sh after lib.sh, with $G (gate work dir) and
# fwd/log set. Gate's shard-1 address must stay the same across kind-down / kind-up (a testnet faucet funds it once), so the keyset is kept OUTSIDE .work:
#   save:    after the DKG, each party exports its own encrypted share of hot-1 (`mpc-party backup export`, inside its pod, under a recovery key made once
#            in the keep dir), and the keep dir gets the three backups, the recovery key pair, hot-1.json (public) and wallet_id
#   restore: on a cluster whose parties have no hot-1, each party restores its share (`mpc-party backup restore -no-records`: the lane never changes
#            its admin set or recovery-key registry), the three parties restart, reconcile and prove the keyset, and party A's status must give the
#            address the keep dir recorded. Nothing makes a new keyset on that path (kindctl status, not dkg).
# The three backups plus the recovery private key are the whole signing key. This is a testnet-only lane: the keep dir is 0700, its files 0600, and its
# README says what it holds. Nothing here prints key material.
KEEP=""
PARTY_TMP=/var/lib/qv/party/keep-tmp   # on the party's data volume, outside data_dir; removed after every step
CFG_IN_POD=/etc/qv/config/party.json

party_ns() { case "$1" in a) echo "$NS_SIGN";; b) echo "$NS_B";; c) echo "$NS_C";; esac; }
pexec() { local r="$1"; shift; kn "$(party_ns "$r")" exec -i "qv-party-$r-0" -c mpc-party -- "$@"; }
ptmp_clear() { pexec "$1" rm -rf "$PARTY_TMP" < /dev/null; }
pput() { pexec "$1" sh -c "umask 077; mkdir -p $PARTY_TMP && cat > $PARTY_TMP/$2" < "$3"; }   # role name src: a 0600 file in the party's tmp
pget() { ( umask 077; pexec "$1" cat "$PARTY_TMP/$2" < /dev/null > "$3" ); }

# keep_open: resolves the keep dir and makes it (0700, with its README and mark) or checks that an existing one is the lane's own
keep_open() {
  KEEP="$(keep_dir)"
  if [ -d "$KEEP" ] && [ -n "$(ls -A "$KEEP")" ] && [ ! -e "$KEEP/$KEEP_MARK" ]; then
    echo "gate.sh: keep dir $KEEP exists, is not empty and is not a lane keep dir (no $KEEP_MARK): refused. Set QV_KIND_KEEP_DIR to another path" >&2; return 1
  fi
  ( umask 077; mkdir -p "$KEEP" ); chmod 700 "$KEEP"
  ( umask 077; echo "$QV_KIND_NAME" > "$KEEP/$KEEP_MARK"
    cat > "$KEEP/README" <<EOF
QuorumVault kind lane, cluster $QV_KIND_NAME: AgentGate's keyset hot-1 (hot shard 1), kept across make kind-down / kind-up (keep mode).

TESTNET ONLY. These files are SECRET: the three party backups (hot-1-a/b/c.backup) together with recovery.private are the whole signing
key of the address in hot-1.json. Never use this key or address on a mainnet, never copy these files into a repository, never share them.

  hot-1.json         public: keyset id, public key, address
  wallet_id          public: the Gate wallet id
  recovery.*         the lane's recovery key pair (made by mpc-party backup gen-recovery-key)
  hot-1-*.backup     each party's share, encrypted to recovery.public (mpc-party backup export)

make kind-gate KEEP=1 restores the keyset into a new cluster; make kind-gate-forget deletes this directory.
EOF
  )
}

# keep_save: backs up the hot-1 the parties hold now into the keep dir (files land in tmp first; hot-1.json last, as the mark of a complete save)
keep_save() {
  local t="$KEEP/tmp" r out
  log "keep mode: back up keyset hot-1 (parties A, B, C) into $KEEP"
  rm -rf "$t"; ( umask 077; mkdir "$t" )
  if [ ! -s "$KEEP/recovery.private" ] || [ ! -s "$KEEP/recovery.public" ]; then
    ptmp_clear a
    pexec a sh -c "umask 077; mkdir -p $PARTY_TMP && mpc-party backup gen-recovery-key -private $PARTY_TMP/r.private -public $PARTY_TMP/r.public > /dev/null" < /dev/null
    pget a r.private "$t/recovery.private"; pget a r.public "$t/recovery.public"
    ptmp_clear a
    [ -s "$t/recovery.private" ] && [ -s "$t/recovery.public" ] || { echo "gate.sh: keep: no recovery key came back from party A" >&2; return 1; }
    mv "$t/recovery.public" "$KEEP/recovery.public"; mv "$t/recovery.private" "$KEEP/recovery.private"
  fi
  for r in a b c; do
    ptmp_clear "$r"
    pput "$r" r.public "$KEEP/recovery.public"
    out="$(pexec "$r" mpc-party backup export -config "$CFG_IN_POD" -keyset hot-1 -recovery-public "$PARTY_TMP/r.public" -out "$PARTY_TMP/b" < /dev/null 2>&1)" || {
      ptmp_clear "$r"; echo "gate.sh: keep: export on party $r failed: $out" >&2; return 1; }
    grep -q 'VERIFIED' <<< "$out" || { ptmp_clear "$r"; echo "gate.sh: keep: export on party $r did not report VERIFIED: $out" >&2; return 1; }
    pget "$r" b "$t/hot-1-$r.backup"
    ptmp_clear "$r"
    [ -s "$t/hot-1-$r.backup" ] || { echo "gate.sh: keep: no backup came back from party $r" >&2; return 1; }
    echo "keep: party $r: $(head -1 <<< "$out" | sed 's/ written to .* and VERIFIED/ VERIFIED/')" >&2
  done
  ( umask 077; cp "$G/wallet_id" "$t/wallet_id"; cp "$G/hot-1.json" "$t/hot-1.json" )
  for r in a b c; do mv "$t/hot-1-$r.backup" "$KEEP/"; done
  mv "$t/wallet_id" "$KEEP/wallet_id"; mv "$t/hot-1.json" "$KEEP/hot-1.json"
  rm -rf "$t"
}

# keep_restore: restores hot-1 from the keep dir into this cluster's parties (party A has none: the caller checked with kindctl status) and restarts them.
# The caller then reads the keyset back from party A with kindctl status (never dkg) and checks its address (keep_check_address).
keep_restore() {
  local r out rc
  log "keep mode: restore keyset hot-1 from $KEEP into parties A, B, C"
  for r in a b c; do [ -s "$KEEP/hot-1-$r.backup" ] || { echo "gate.sh: keep: $KEEP/hot-1-$r.backup is missing" >&2; return 1; }; done
  for r in a b c; do
    ptmp_clear "$r"
    pput "$r" r.private "$KEEP/recovery.private"
    pput "$r" b "$KEEP/hot-1-$r.backup"
    rc=0; out="$(pexec "$r" mpc-party backup restore -config "$CFG_IN_POD" -recovery-private "$PARTY_TMP/r.private" -file "$PARTY_TMP/b" -no-records < /dev/null 2>&1)" || rc=$?
    ptmp_clear "$r"
    if [ "$rc" != 0 ]; then
      # a run that died after this party's restore: the share is there already (the tool refuses to write it twice)
      grep -q 'already has keyset "hot-1"' <<< "$out" || { echo "gate.sh: keep: restore on party $r failed: $out" >&2; return 1; }
      echo "keep: party $r already holds hot-1" >&2
    else
      echo "keep: party $r: $(grep '^restored' <<< "$out" | head -1)" >&2
    fi
  done
  log "keep mode: restart parties A, B, C (they reconcile and prove hot-1 at start)"
  for r in a b c; do kn "$(party_ns "$r")" rollout restart "statefulset/qv-party-$r" > /dev/null; done
  for r in a b c; do kn "$(party_ns "$r")" rollout status "statefulset/qv-party-$r" --timeout=240s > /dev/null; done
}

# keep_check_address FILE: fails when FILE's address is not the one the keep dir recorded
keep_check_address() {
  local want got
  want="$(jq -r .address "$KEEP/hot-1.json")"; got="$(jq -r .address "$1")"
  [ -n "$want" ] && [ "$want" != null ] || { echo "gate.sh: keep: $KEEP/hot-1.json has no address" >&2; return 1; }
  if [ "$(tr A-Z a-z <<< "$got")" != "$(tr A-Z a-z <<< "$want")" ]; then
    echo "gate.sh: keep: keyset hot-1 on cluster $QV_KIND_NAME is $got, but the keep dir $KEEP holds $want. Either make kind-down and kind-up (the keep dir is restored into a fresh cluster) or make kind-gate-forget (a new key and address)" >&2
    return 1
  fi
  echo "keep: hot-1 address $got is the kept one" >&2
}
