// C ABI over cb-mpc (pinned in ../../cbmpc.pin). See shim.h for conventions.
//
// This file mirrors two things that the public cb-mpc API does not expose. Both are covered by golden tests
// (golden_test.go) so that an upgrade which changes them fails loudly:
//   1. the HD keyset blob layout: src/cbmpc/api/hd_keyset_ecdsa_2p.cpp and hd_keyset_eddsa_2p.cpp (keyset_blob_v1_t),
//   2. the hardened-step (VRF) derivation that yields the node's chain code:
//      src/cbmpc/protocol/hd_keyset_ecdsa_2p.cpp and hd_keyset_eddsa_2p.cpp (derive_keys).
#include "shim.h"

#include <openssl/crypto.h>
#include <sys/mman.h>

#include <cstdlib>
#include <cstring>
#include <new>
#include <stdexcept>
#include <vector>

#include <cbmpc/api/ecdsa_2p.h>
#include <cbmpc/api/eddsa_2p.h>
#include <cbmpc/api/hd_keyset_ecdsa_2p.h>
#include <cbmpc/api/hd_keyset_eddsa_2p.h>
#include <cbmpc/api/pve_base_pke.h>
#include <cbmpc/api/pve_batch_single_recipient.h>
#include <cbmpc/api/schnorr_2p.h>
#include <cbmpc/internal/core/convert.h>
#include <cbmpc/internal/crypto/base_paillier.h>
#include <cbmpc/internal/crypto/ro.h>
#include <cbmpc/internal/protocol/hd_keyset_ecdsa_2p.h>
#include <cbmpc/internal/protocol/hd_keyset_eddsa_2p.h>
#include <cbmpc/internal/protocol/sid.h>
#include <cbmpc/internal/zk/zk_ec.h>

#include "job_util.h"

using namespace coinbase;
using coinbase::api::curve_id;

// Every entry point body goes between QV_TRY and QV_CATCH. cb_assert throws assertion_failed_t, and the C++ HD API
// does not catch it: an exception escaping into cgo would call std::terminate.
#define QV_TRY try {
#define QV_CATCH                                            \
  }                                                         \
  catch (const std::bad_alloc&) { return (int)QV_E_BADALLOC; } \
  catch (const coinbase::assertion_failed_t&) { return (int)QV_E_ASSERT; } \
  catch (const std::exception&) { return (int)QV_E_EXCEPTION; } \
  catch (...) { return (int)QV_E_EXCEPTION; }

namespace {

// cb-mpc prints every error (and the stack of log frames) to std::cerr by default. A hostile peer can trigger that at
// will, so it is silenced; callers get the numeric code (and Go-side context) in *cbmpc.Error instead.
const int silence_cbmpc_log = (coinbase::out_log_fun = [](int, const char*) {}, 0);

class go_transport : public api::data_transport_i {
 public:
  explicit go_transport(uintptr_t h) : h_(h) {}
  error_t send(api::party_idx_t, mem_t msg) override {
    return qv_go_send(h_, (void*)msg.data, (size_t)msg.size) ? (error_t)QV_E_TRANSPORT : 0;
  }
  error_t receive(api::party_idx_t, buf_t& msg) override {
    void* p = nullptr;
    size_t n = 0;
    if (qv_go_recv(h_, &p, &n)) return (error_t)QV_E_TRANSPORT;
    msg = buf_t((const uint8_t*)p, (int)n);
    free(p);
    return 0;
  }
  error_t receive_all(const std::vector<api::party_idx_t>& senders, std::vector<buf_t>& msgs) override {
    msgs.resize(senders.size());
    for (size_t i = 0; i < senders.size(); i++)
      if (error_t rv = receive(senders[i], msgs[i])) return rv;
    return 0;
  }

 private:
  uintptr_t h_;
};

struct ctx_t {
  go_transport tr;
  api::job_2p_t job;
  ctx_t(int role, uintptr_t h)
      : tr(h), job{role == 0 ? api::party_2p_t::p1 : api::party_2p_t::p2, "p1", "p2", tr} {}
};

int out(const uint8_t* d, size_t n, uint8_t** p, size_t* pn) {
  uint8_t* m = (uint8_t*)malloc(n ? n : 1);
  if (!m) return (int)QV_E_BADALLOC;
  if (n) memcpy(m, d, n);
  *p = m;
  *pn = n;
  return 0;
}
int out(const buf_t& b, uint8_t** p, size_t* n) { return out(b.data(), (size_t)b.size(), p, n); }

mem_t M(const uint8_t* p, size_t n) { return mem_t(p, (int)n); }
api::bip32_path_t P(const uint32_t* p, size_t n) { return api::bip32_path_t{std::vector<uint32_t>(p, p + n)}; }

// Mirrors of the HD keyset blobs (see header comment). Field order is the wire order.
struct ks_ecdsa_t {
  uint32_t version = 1, role = 0, curve = 0;
  buf_t root_Q, root_K;
  crypto::bn_t x_share, k_share;
  crypto::paillier_t paillier;
  crypto::bn_t c_key;
  void convert(converter_t& c) { c.convert(version, role, curve, root_Q, root_K, x_share, k_share, paillier, c_key); }
};
struct ks_eddsa_t {
  uint32_t version = 1, role = 0, curve = 0;
  buf_t root_Q, root_K;
  crypto::bn_t x_share, k_share;
  void convert(converter_t& c) { c.convert(version, role, curve, root_Q, root_K, x_share, k_share); }
};

ecurve_t curve_of(int alg) { return alg == QV_ALG_ECDSA ? crypto::curve_secp256k1 : crypto::curve_ed25519; }
int curve_id_of(int alg) { return alg == QV_ALG_ECDSA ? QV_CURVE_SECP256K1 : QV_CURVE_ED25519; }
int point_len(int alg) { return alg == QV_ALG_ECDSA ? 33 : 32; }
bool is_hd_alg(int alg) { return alg == QV_ALG_ECDSA || alg == QV_ALG_EDDSA; }

// Parse + validate a keyset blob exactly as upstream's blob_to_keyset does (same range checks).
error_t parse_ks(int alg, mem_t in, ks_ecdsa_t& e, ks_eddsa_t& d) {
  if (!is_hd_alg(alg)) return (error_t)QV_E_UNSUPPORTED;
  if (in.size <= 0 || in.size > (1 << 20)) return (error_t)QV_E_LAYOUT;
  ecurve_t curve = curve_of(alg);
  const mod_t& q = curve.order();
  ecc_point_t Q, K;
  if (alg == QV_ALG_ECDSA) {
    if (error_t rv = convert(e, in)) return rv;
    if (e.version != 1 || e.role > 1 || (int)e.curve != QV_CURVE_SECP256K1) return (error_t)QV_E_LAYOUT;
    if (!q.is_in_range(e.k_share) || !e.paillier.get_N().is_in_range(e.x_share)) return (error_t)QV_E_LAYOUT;
    if (error_t rv = Q.from_bin(curve, e.root_Q)) return rv;
    return K.from_bin(curve, e.root_K);
  }
  if (error_t rv = convert(d, in)) return rv;
  if (d.version != 1 || d.role > 1 || (int)d.curve != QV_CURVE_ED25519) return (error_t)QV_E_LAYOUT;
  if (!q.is_in_range(d.x_share) || !q.is_in_range(d.k_share)) return (error_t)QV_E_LAYOUT;
  if (error_t rv = Q.from_bin(curve, d.root_Q)) return rv;
  return K.from_bin(curve, d.root_K);
}

}  // namespace

extern "C" {

void qv_free(void* p) { free(p); }
void qv_wipe(void* p, size_t n) {
  if (p && n) OPENSSL_cleanse(p, n);
}
int qv_mlock(void* p, size_t n) { return (p && n) ? mlock(p, n) : 0; }
const char* qv_layout_id(void) { return "cbmpc-v0.2.x/hd-keyset-blob-v1+vrf-node-v1"; }

int qv_test_throw(int kind) {
  QV_TRY
  switch (kind) {
    case 0: throw std::runtime_error("test: runtime_error");
    case 1: cb_assert(kind == 12345 && "test: cb_assert");  // a real coinbase::assertion_failed_t
    case 2: throw std::bad_alloc();
    case 3: throw 42;
    default: return 0;
  }
  return 0;
  QV_CATCH
}

int qv_hd_dkg(int alg, int role, uintptr_t h, uint8_t** ks, size_t* ksl) {
  QV_TRY
  if (!is_hd_alg(alg)) return (int)QV_E_UNSUPPORTED;
  ctx_t c(role, h);
  buf_t b;
  error_t rv = alg == QV_ALG_ECDSA ? api::hd_keyset_ecdsa_2p::dkg(c.job, curve_id::secp256k1, b)
                                   : api::hd_keyset_eddsa_2p::dkg(c.job, curve_id::ed25519, b);
  return rv ? rv : out(b, ks, ksl);
  QV_CATCH
}

int qv_hd_refresh(int alg, int role, uintptr_t h, const uint8_t* ks, size_t ksl, uint8_t** nks, size_t* nksl) {
  QV_TRY
  if (!is_hd_alg(alg)) return (int)QV_E_UNSUPPORTED;
  ctx_t c(role, h);
  buf_t b;
  error_t rv = alg == QV_ALG_ECDSA ? api::hd_keyset_ecdsa_2p::refresh(c.job, M(ks, ksl), b)
                                   : api::hd_keyset_eddsa_2p::refresh(c.job, M(ks, ksl), b);
  return rv ? rv : out(b, nks, nksl);
  QV_CATCH
}

int qv_hd_derive(int alg, int role, uintptr_t h, const uint8_t* ks, size_t ksl, const uint32_t* hp, size_t hpn,
                 const uint32_t* nhp, size_t nhpn, uint8_t** key, size_t* keyl) {
  QV_TRY
  if (!is_hd_alg(alg)) return (int)QV_E_UNSUPPORTED;
  ctx_t c(role, h);
  buf_t sid;  // empty: generated jointly
  std::vector<api::bip32_path_t> nh{P(nhp, nhpn)};
  std::vector<buf_t> keys;
  error_t rv = alg == QV_ALG_ECDSA
                   ? api::hd_keyset_ecdsa_2p::derive_ecdsa_2p_keys(c.job, M(ks, ksl), P(hp, hpn), nh, sid, keys)
                   : api::hd_keyset_eddsa_2p::derive_eddsa_2p_keys(c.job, M(ks, ksl), P(hp, hpn), nh, sid, keys);
  if (rv) return rv;
  if (keys.size() != 1) return (int)QV_E_LAYOUT;
  return out(keys[0], key, keyl);
  QV_CATCH
}

// Copy of the VRF step of key_share_*_hdmpc_2p_t::derive_keys, exporting the node (Q_derived, chain_code) that the
// public API discards. The result is checked against Derive in golden_test.go and bip32_test.go.
int qv_hd_node(int alg, int role, uintptr_t h, const uint8_t* ks, size_t ksl, const uint32_t* hp, size_t hpn,
               uint8_t Q[33], size_t* ql, uint8_t cc32[32]) {
  QV_TRY
  ks_ecdsa_t e;
  ks_eddsa_t d;
  if (error_t rv = parse_ks(alg, M(ks, ksl), e, d)) return rv;
  const uint32_t blob_role = alg == QV_ALG_ECDSA ? e.role : d.role;
  if ((int)blob_role != role) return (int)E_BADARG;
  const buf_t& rootQ = alg == QV_ALG_ECDSA ? e.root_Q : d.root_Q;
  const buf_t& rootK = alg == QV_ALG_ECDSA ? e.root_K : d.root_K;
  const crypto::bn_t& k_share = alg == QV_ALG_ECDSA ? e.k_share : d.k_share;

  ctx_t c(role, h);
  ecurve_t curve = curve_of(alg);
  const mod_t& q = curve.order();
  const auto& G = curve.generator();
  mpc::job_2p_t job = api::detail::to_internal_job(c.job);
  mpc::bip32_path_t hpath(hp, (int)hpn);

  ecc_point_t Qr, K;
  if (error_t rv = Qr.from_bin(curve, rootQ)) return rv;
  if (error_t rv = K.from_bin(curve, rootK)) return rv;
  ecc_point_t K_share = curve.mul_to_generator(k_share);
  ecc_point_t other_K_share = K - K_share;

  buf_t sidb;
  error_t rv = alg == QV_ALG_ECDSA ? mpc::generate_sid_fixed_mp(job, sidb)
                                   : mpc::generate_sid_fixed_2p(job, mpc::party_t::p2, sidb);
  if (rv) return rv;
  const buf256_t derive_sid = crypto::sha256_t::hash(
      std::string(alg == QV_ALG_ECDSA ? "ecdsa-hd-keyset-2p-derive-node" : "eddsa-hd-keyset-2p-derive-node"),
      uint64_t(sidb.size()), sidb, hpath);

  ecc_point_t P_ = crypto::ro::hash_curve(hpath.get()).curve(curve);
  ecc_point_t Z1, Z2, Z_share = k_share * P_;
  zk::dh_t zk_dh1, zk_dh2;
  if (job.is_p1()) {
    Z1 = Z_share;
    zk_dh1.prove(P_, K_share, Z1, k_share, derive_sid, 1);
  } else {
    Z2 = Z_share;
  }
  if (rv = job.p1_to_p2(Z1, zk_dh1)) return rv;
  if (job.is_p2()) {
    if (rv = zk_dh1.verify(P_, other_K_share, Z1, derive_sid, 1)) return rv;
    zk_dh2.prove(P_, K_share, Z2, k_share, derive_sid, 2);
  }
  if (rv = job.p2_to_p1(Z2, zk_dh2)) return rv;
  if (job.is_p1())
    if (rv = zk_dh2.verify(P_, other_K_share, Z2, derive_sid, 2)) return rv;
  ecc_point_t Z = Z1 + Z2;
  const int delta_size = curve.size() + 16;  // 256 + 128 bits
  buf_t y = crypto::ro::hash_string(Z).bitlen(bytes_to_bits(delta_size) + 256);
  bn_t delta = bn_t::from_bin(y.take(delta_size)) % q;
  buf_t cc = y.skip(delta_size);
  ecc_point_t Qd = Qr + delta * G;
  buf_t qb = Qd.to_compressed_bin();
  if (qb.size() != point_len(alg) || cc.size() != 32) return (int)QV_E_LAYOUT;
  memcpy(Q, qb.data(), qb.size());
  *ql = (size_t)qb.size();
  memcpy(cc32, cc.data(), 32);
  return 0;
  QV_CATCH
}

int qv_hd_root_pub(int alg, const uint8_t* ks, size_t ksl, uint8_t** q, size_t* ql) {
  QV_TRY
  ks_ecdsa_t e;
  ks_eddsa_t d;
  if (error_t rv = parse_ks(alg, M(ks, ksl), e, d)) return rv;
  buf_t b;
  error_t rv = alg == QV_ALG_ECDSA ? api::hd_keyset_ecdsa_2p::extract_root_public_key_compressed(M(ks, ksl), b)
                                   : api::hd_keyset_eddsa_2p::extract_root_public_key_compressed(M(ks, ksl), b);
  return rv ? rv : out(b, q, ql);
  QV_CATCH
}

int qv_hd_info(int alg, const uint8_t* ks, size_t ksl, int* role, int* curve) {
  QV_TRY
  ks_ecdsa_t e;
  ks_eddsa_t d;
  if (error_t rv = parse_ks(alg, M(ks, ksl), e, d)) return rv;
  *role = (int)(alg == QV_ALG_ECDSA ? e.role : d.role);
  *curve = (int)(alg == QV_ALG_ECDSA ? e.curve : d.curve);
  return 0;
  QV_CATCH
}

int qv_2p_dkg(int alg, int role, uintptr_t h, int curve, uint8_t** key, size_t* keyl) {
  QV_TRY
  ctx_t c(role, h);
  buf_t b;
  error_t rv = alg == QV_ALG_ECDSA   ? api::ecdsa_2p::dkg(c.job, (curve_id)curve, b)
               : alg == QV_ALG_EDDSA ? api::eddsa_2p::dkg(c.job, (curve_id)curve, b)
                                     : api::schnorr_2p::dkg(c.job, (curve_id)curve, b);
  return rv ? rv : out(b, key, keyl);
  QV_CATCH
}

int qv_2p_refresh(int alg, int role, uintptr_t h, const uint8_t* key, size_t keyl, uint8_t** nkey, size_t* nkeyl) {
  QV_TRY
  ctx_t c(role, h);
  buf_t b;
  error_t rv = alg == QV_ALG_ECDSA   ? api::ecdsa_2p::refresh(c.job, M(key, keyl), b)
               : alg == QV_ALG_EDDSA ? api::eddsa_2p::refresh(c.job, M(key, keyl), b)
                                     : api::schnorr_2p::refresh(c.job, M(key, keyl), b);
  return rv ? rv : out(b, nkey, nkeyl);
  QV_CATCH
}

int qv_2p_sign(int alg, int role, uintptr_t h, const uint8_t* key, size_t keyl, const uint8_t* msg, size_t msgl,
               uint8_t** sig, size_t* sigl) {
  QV_TRY
  ctx_t c(role, h);
  buf_t s, sid;  // sid empty: agreed jointly (SECURE_USAGE.md requires a jointly generated session id)
  // Never the internal sign_with_global_abort variant: only the public sign(), which runs the full proof mode.
  error_t rv = alg == QV_ALG_ECDSA   ? api::ecdsa_2p::sign(c.job, M(key, keyl), M(msg, msgl), sid, s)
               : alg == QV_ALG_EDDSA ? api::eddsa_2p::sign(c.job, M(key, keyl), M(msg, msgl), s)
                                     : api::schnorr_2p::sign(c.job, M(key, keyl), M(msg, msgl), s);
  if (rv) return rv;
  if (role != 0) {
    *sig = nullptr;
    *sigl = 0;
    return 0;
  }
  return out(s, sig, sigl);
  QV_CATCH
}

int qv_2p_pub(int alg, const uint8_t* key, size_t keyl, uint8_t** pub, size_t* publ) {
  QV_TRY
  buf_t b;
  error_t rv = alg == QV_ALG_ECDSA   ? api::ecdsa_2p::get_public_key_compressed(M(key, keyl), b)
               : alg == QV_ALG_EDDSA ? api::eddsa_2p::get_public_key_compressed(M(key, keyl), b)
                                     : api::schnorr_2p::get_public_key_compressed(M(key, keyl), b);
  return rv ? rv : out(b, pub, publ);
  QV_CATCH
}

int qv_schnorr_xonly(const uint8_t* key, size_t keyl, uint8_t** pub, size_t* publ) {
  QV_TRY
  buf_t b;
  error_t rv = api::schnorr_2p::extract_public_key_xonly(M(key, keyl), b);
  return rv ? rv : out(b, pub, publ);
  QV_CATCH
}

int qv_ks_split(int alg, const uint8_t* ks, size_t ksl, uint8_t** stripped, size_t* sl, uint8_t** xq, uint8_t** k,
                uint8_t Qx[33], uint8_t Qk[33], size_t* ql, int* x_reduced) {
  QV_TRY
  ks_ecdsa_t e;
  ks_eddsa_t d;
  if (error_t rv = parse_ks(alg, M(ks, ksl), e, d)) return rv;
  ecurve_t curve = curve_of(alg);
  const mod_t& q = curve.order();
  crypto::bn_t& x_share = alg == QV_ALG_ECDSA ? e.x_share : d.x_share;
  crypto::bn_t& k_share = alg == QV_ALG_ECDSA ? e.k_share : d.k_share;
  const uint32_t role = alg == QV_ALG_ECDSA ? e.role : d.role;
  // p1 (ECDSA) keeps x as a Paillier plaintext representative that can exceed q after a refresh; only x mod q goes into
  // PVE, the exact value is recovered from c_key by qv_ks_join. Every other share must already be < q or it would be
  // silently truncated.
  const bool p1_ecdsa = alg == QV_ALG_ECDSA && role == 0;
  if (!p1_ecdsa && !q.is_in_range(x_share)) return (int)QV_E_LAYOUT;
  bn_t x_mod = x_share % q;
  const int reduced = (x_mod == x_share) ? 0 : 1;
  buf_t xb = x_mod.to_bin(32), kb = k_share.to_bin(32);
  ecc_point_t PX = curve.mul_to_generator(x_mod), PK = curve.mul_to_generator(k_share);
  buf_t px = PX.to_compressed_bin(), pk = PK.to_compressed_bin();
  if (px.size() != point_len(alg) || pk.size() != point_len(alg)) return (int)QV_E_LAYOUT;
  // Strip both scalars from the blob.
  x_share = 0;
  k_share = 0;
  buf_t stripped_b = alg == QV_ALG_ECDSA ? convert(e) : convert(d);
  uint8_t *s_p = nullptr, *x_p = nullptr, *k_p = nullptr;
  size_t s_n = 0, tmp = 0;
  int rv = out(stripped_b, &s_p, &s_n);
  if (!rv) rv = out(xb, &x_p, &tmp);
  if (!rv) rv = out(kb, &k_p, &tmp);
  if (rv) {
    for (uint8_t* p : {s_p, x_p, k_p}) {
      if (p) free(p);
    }
    return rv;
  }
  memcpy(Qx, px.data(), px.size());
  memcpy(Qk, pk.data(), pk.size());
  *ql = (size_t)px.size();
  *x_reduced = reduced;
  *stripped = s_p;
  *sl = s_n;
  *xq = x_p;
  *k = k_p;
  return 0;
  QV_CATCH
}

int qv_ks_join(int alg, const uint8_t* stripped, size_t sl, const uint8_t* xq, const uint8_t* k, const uint8_t* Qx,
               const uint8_t* Qk, size_t ql, uint8_t** ks, size_t* ksl) {
  QV_TRY
  if (!is_hd_alg(alg)) return (int)QV_E_UNSUPPORTED;
  if ((int)ql != point_len(alg)) return (int)E_BADARG;
  ks_ecdsa_t e;
  ks_eddsa_t d;
  // Parse without the range checks of parse_ks: the stripped blob holds zero scalars.
  if (sl == 0 || sl > (1 << 20)) return (int)QV_E_LAYOUT;
  if (alg == QV_ALG_ECDSA) {
    if (error_t rv = convert(e, M(stripped, sl))) return rv;
    if (e.version != 1 || e.role > 1 || (int)e.curve != QV_CURVE_SECP256K1) return (int)QV_E_LAYOUT;
  } else {
    if (error_t rv = convert(d, M(stripped, sl))) return rv;
    if (d.version != 1 || d.role > 1 || (int)d.curve != QV_CURVE_ED25519) return (int)QV_E_LAYOUT;
  }
  ecurve_t curve = curve_of(alg);
  const mod_t& q = curve.order();
  bn_t x = bn_t::from_bin(M(xq, 32)), kk = bn_t::from_bin(M(k, 32));
  if (!q.is_in_range(x) || !q.is_in_range(kk)) return (int)E_RANGE;
  // The restored scalars must match the public share points recorded at backup time.
  buf_t px = curve.mul_to_generator(x).to_compressed_bin(), pk = curve.mul_to_generator(kk).to_compressed_bin();
  if (px.size() != (int)ql || memcmp(px.data(), Qx, ql) != 0) return (int)E_CRYPTO;
  if (pk.size() != (int)ql || memcmp(pk.data(), Qk, ql) != 0) return (int)E_CRYPTO;

  if (alg == QV_ALG_ECDSA) {
    if (e.role == 0) {
      // p1: exact x = Paillier plaintext of c_key (see SECURE_USAGE.md "ECDSA-2P P1 backup limitations").
      // decrypt() cb_asserts (-> QV_E_ASSERT via the guard) if the blob has no Paillier private key.
      bn_t exact = e.paillier.decrypt(e.c_key);
      if (!(exact % q == x)) return (int)E_CRYPTO;
      e.x_share = exact;
    } else {
      e.x_share = x;
    }
    e.k_share = kk;
    return out(convert(e), ks, ksl);
  }
  d.x_share = x;
  d.k_share = kk;
  return out(convert(d), ks, ksl);
  QV_CATCH
}

int qv_pve_keygen(uint8_t** ek, size_t* ekl, uint8_t** dk, size_t* dkl) {
  QV_TRY
  buf_t e, d;
  if (error_t rv = api::pve::generate_base_pke_rsa_keypair(e, d)) return rv;
  uint8_t* ep = nullptr;
  size_t en = 0;
  if (int rv = out(e, &ep, &en)) return rv;
  if (int rv = out(d, dk, dkl)) {
    free(ep);
    return rv;
  }
  *ek = ep;
  *ekl = en;
  return 0;
  QV_CATCH
}

int qv_pve_encrypt(int curve, const uint8_t* ek, size_t ekl, const uint8_t* label, size_t labell, const uint8_t* xs32,
                   size_t n, uint8_t** ct, size_t* ctl) {
  QV_TRY
  if (n == 0 || n > 16) return (int)E_BADARG;
  std::vector<mem_t> v;
  for (size_t i = 0; i < n; i++) v.push_back(mem_t(xs32 + 32 * i, 32));
  buf_t b;
  error_t rv = api::pve::encrypt_batch((curve_id)curve, M(ek, ekl), M(label, labell), v, b);
  return rv ? rv : out(b, ct, ctl);
  QV_CATCH
}

int qv_pve_verify(int curve, const uint8_t* ek, size_t ekl, const uint8_t* ct, size_t ctl, const uint8_t* Qs,
                  size_t ql, size_t n, const uint8_t* label, size_t labell) {
  QV_TRY
  if (n == 0 || n > 16) return (int)E_BADARG;
  std::vector<mem_t> v;
  for (size_t i = 0; i < n; i++) v.push_back(mem_t(Qs + ql * i, (int)ql));
  return api::pve::verify_batch((curve_id)curve, M(ek, ekl), M(ct, ctl), v, M(label, labell));
  QV_CATCH
}

int qv_pve_decrypt(int curve, const uint8_t* dk, size_t dkl, const uint8_t* ek, size_t ekl, const uint8_t* ct,
                   size_t ctl, const uint8_t* label, size_t labell, uint8_t** xs32, size_t* n) {
  QV_TRY
  std::vector<buf_t> v;
  error_t rv = api::pve::decrypt_batch((curve_id)curve, M(dk, dkl), M(ek, ekl), M(ct, ctl), M(label, labell), v);
  if (rv) return rv;
  if (v.empty() || v.size() > 16) return (int)QV_E_LAYOUT;
  uint8_t* m = (uint8_t*)calloc(v.size(), 32);
  if (!m) return (int)QV_E_BADALLOC;
  for (size_t i = 0; i < v.size(); i++) {
    if (v[i].size() > 32) {
      OPENSSL_cleanse(m, v.size() * 32);
      free(m);
      return (int)QV_E_LAYOUT;
    }
    memcpy(m + 32 * i + (32 - v[i].size()), v[i].data(), v[i].size());  // left-pad to 32 bytes
  }
  *xs32 = m;
  *n = v.size();
  return 0;
  QV_CATCH
}

}  // extern "C"
