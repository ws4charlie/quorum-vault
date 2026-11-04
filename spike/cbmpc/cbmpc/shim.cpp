// Spike shim: C ABI over cb-mpc v0.2.2. Uses a few internal headers (blob mirror, VRF node export).
#include "shim.h"

#include <cstdlib>
#include <new>
#include <cstring>
#include <vector>

#include <cbmpc/api/ecdsa_2p.h>
#include <cbmpc/api/eddsa_2p.h>
#include <cbmpc/api/hd_keyset_ecdsa_2p.h>
#include <cbmpc/api/hd_keyset_eddsa_2p.h>
#include <cbmpc/api/pve_batch_single_recipient.h>
#include <cbmpc/api/pve_base_pke.h>
#include <cbmpc/api/schnorr_2p.h>
#include <cbmpc/internal/core/convert.h>
#include <cbmpc/internal/protocol/hd_keyset_ecdsa_2p.h>
#include <cbmpc/internal/protocol/sid.h>
#include <cbmpc/internal/zk/zk_ec.h>
#include <cbmpc/internal/crypto/ro.h>
#include <cbmpc/internal/crypto/base_paillier.h>
#include "job_util.h"

using namespace coinbase;
using coinbase::api::curve_id;

// Implemented in Go (cgo //export): blocking transport for one protocol session.
extern "C" int qv_go_send(uintptr_t h, int receiver, void* msg, size_t len);
extern "C" int qv_go_recv(uintptr_t h, int sender, void** out, size_t* outlen);

namespace {

class go_transport : public api::data_transport_i {
 public:
  explicit go_transport(uintptr_t h) : h_(h) {}
  error_t send(api::party_idx_t receiver, mem_t msg) override {
    return qv_go_send(h_, receiver, (void*)msg.data, (size_t)msg.size);
  }
  error_t receive(api::party_idx_t sender, buf_t& msg) override {
    void* p = nullptr;
    size_t n = 0;
    int rv = qv_go_recv(h_, sender, &p, &n);
    if (rv) return rv;
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
  ctx_t(int role, uintptr_t h) : tr(h), job{role == 0 ? api::party_2p_t::p1 : api::party_2p_t::p2, "p1", "p2", tr} {}
};

int out(const buf_t& b, uint8_t** p, size_t* n) {
  *p = (uint8_t*)malloc(b.size() ? b.size() : 1);
  memcpy(*p, b.data(), b.size());
  *n = b.size();
  return 0;
}
int out(const std::vector<uint8_t>& b, uint8_t** p, size_t* n) {
  *p = (uint8_t*)malloc(b.size() ? b.size() : 1);
  memcpy(*p, b.data(), b.size());
  *n = b.size();
  return 0;
}
mem_t M(const uint8_t* p, size_t n) { return mem_t(p, (int)n); }
api::bip32_path_t P(const uint32_t* p, size_t n) { return api::bip32_path_t{std::vector<uint32_t>(p, p + n)}; }

// Mirror of the ECDSA HD keyset blob (src/cbmpc/api/hd_keyset_ecdsa_2p.cpp keyset_blob_v1_t).
struct ks_blob_t {
  uint32_t version = 1, role = 0, curve = 0;
  buf_t root_Q, root_K;
  crypto::bn_t x_share, k_share;
  crypto::paillier_t paillier;
  crypto::bn_t c_key;
  void convert(converter_t& c) { c.convert(version, role, curve, root_Q, root_K, x_share, k_share, paillier, c_key); }
};

}  // namespace

extern "C" {

void qv_free(void* p) { free(p); }
void qv_wipe(void* p, size_t n) { volatile uint8_t* v = (volatile uint8_t*)p; while (n--) *v++ = 0; }

int qv_hd_dkg(int ecdsa, int role, uintptr_t h, int curve, uint8_t** ks, size_t* ksl) {
  try {
  ctx_t c(role, h);
  buf_t b;
  error_t rv = ecdsa ? api::hd_keyset_ecdsa_2p::dkg(c.job, (curve_id)curve, b)
                     : api::hd_keyset_eddsa_2p::dkg(c.job, (curve_id)curve, b);
  return rv ? rv : out(b, ks, ksl);
  } catch (const std::bad_alloc&) { return E_INSUFFICIENT;
  } catch (...) { return E_GENERAL; }  // cb_assert throws: never let it cross cgo
}

int qv_hd_refresh(int ecdsa, int role, uintptr_t h, const uint8_t* ks, size_t ksl, uint8_t** nks, size_t* nksl) {
  try {
  ctx_t c(role, h);
  buf_t b;
  error_t rv = ecdsa ? api::hd_keyset_ecdsa_2p::refresh(c.job, M(ks, ksl), b)
                     : api::hd_keyset_eddsa_2p::refresh(c.job, M(ks, ksl), b);
  return rv ? rv : out(b, nks, nksl);
  } catch (const std::bad_alloc&) { return E_INSUFFICIENT;
  } catch (...) { return E_GENERAL; }  // cb_assert throws: never let it cross cgo
}

int qv_hd_derive(int ecdsa, int role, uintptr_t h, const uint8_t* ks, size_t ksl, const uint32_t* hp, size_t hpn,
                 const uint32_t* nhp, size_t nhpn, uint8_t** sid, size_t* sidl, uint8_t** key, size_t* keyl) {
  try {
  ctx_t c(role, h);
  buf_t s(M(*sid, *sidl));
  std::vector<api::bip32_path_t> nh{P(nhp, nhpn)};
  std::vector<buf_t> keys;
  error_t rv = ecdsa ? api::hd_keyset_ecdsa_2p::derive_ecdsa_2p_keys(c.job, M(ks, ksl), P(hp, hpn), nh, s, keys)
                     : api::hd_keyset_eddsa_2p::derive_eddsa_2p_keys(c.job, M(ks, ksl), P(hp, hpn), nh, s, keys);
  if (rv) return rv;
  out(s, sid, sidl);
  return out(keys[0], key, keyl);
  } catch (const std::bad_alloc&) { return E_INSUFFICIENT;
  } catch (...) { return E_GENERAL; }  // cb_assert throws: never let it cross cgo
}

int qv_hd_node_ecdsa(int role, uintptr_t h, const uint8_t* ks, size_t ksl, const uint32_t* hp, size_t hpn,
                     uint8_t** sid, size_t* sidl, uint8_t Q33[33], uint8_t cc32[32]) {
  try {
  // Copy of the VRF part of key_share_ecdsa_hdmpc_2p_t::derive_keys (src/cbmpc/protocol/hd_keyset_ecdsa_2p.cpp),
  // exporting the account node (Q_derived, chain_code), which the public API discards.
  ctx_t c(role, h);
  ks_blob_t blob;
  if (error_t rv = convert(blob, M(ks, ksl))) return rv;
  ecurve_t curve = crypto::curve_secp256k1;  // spike: secp256k1 only
  const mod_t& q = curve.order();
  const auto& G = curve.generator();
  mpc::job_2p_t job = api::detail::to_internal_job(c.job);
  mpc::bip32_path_t hpath(hp, (int)hpn);

  ecc_point_t Q, K;
  if (Q.from_bin(curve, blob.root_Q) || K.from_bin(curve, blob.root_K)) return E_FORMAT;
  ecc_point_t K_share = curve.mul_to_generator(blob.k_share);
  ecc_point_t other_K_share = K - K_share;

  buf_t sidb(M(*sid, *sidl));
  error_t rv;
  if (sidb.empty())
    if (rv = mpc::generate_sid_fixed_mp(job, sidb)) return rv;
  const buf256_t derive_sid = crypto::sha256_t::hash(std::string("ecdsa-hd-keyset-2p-derive-node"), uint64_t(sidb.size()), sidb, hpath);

  ecc_point_t P_ = crypto::ro::hash_curve(hpath.get()).curve(curve);
  ecc_point_t Z1, Z2, Z_share = blob.k_share * P_;
  zk::dh_t zk_dh1, zk_dh2;
  if (job.is_p1()) { Z1 = Z_share; zk_dh1.prove(P_, K_share, Z1, blob.k_share, derive_sid, 1); }
  else Z2 = Z_share;
  if (rv = job.p1_to_p2(Z1, zk_dh1)) return rv;
  if (job.is_p2()) {
    if (rv = zk_dh1.verify(P_, other_K_share, Z1, derive_sid, 1)) return rv;
    zk_dh2.prove(P_, K_share, Z2, blob.k_share, derive_sid, 2);
  }
  if (rv = job.p2_to_p1(Z2, zk_dh2)) return rv;
  if (job.is_p1()) if (rv = zk_dh2.verify(P_, other_K_share, Z2, derive_sid, 2)) return rv;
  ecc_point_t Z = Z1 + Z2;
  const int delta_size = curve.size() + 16;
  buf_t y = crypto::ro::hash_string(Z).bitlen(bytes_to_bits(delta_size) + 256);
  bn_t delta = bn_t::from_bin(y.take(delta_size)) % q;
  buf_t cc = y.skip(delta_size);
  ecc_point_t Qd = Q + delta * G;
  Qd.to_compressed_bin(Q33);
  memcpy(cc32, cc.data(), 32);
  out(sidb, sid, sidl);
  return 0;
  } catch (const std::bad_alloc&) { return E_INSUFFICIENT;
  } catch (...) { return E_GENERAL; }  // cb_assert throws: never let it cross cgo
}

int qv_hd_root_pub(int ecdsa, const uint8_t* ks, size_t ksl, uint8_t** q, size_t* ql) {
  try {
  buf_t b;
  error_t rv = ecdsa ? api::hd_keyset_ecdsa_2p::extract_root_public_key_compressed(M(ks, ksl), b)
                     : api::hd_keyset_eddsa_2p::extract_root_public_key_compressed(M(ks, ksl), b);
  return rv ? rv : out(b, q, ql);
  } catch (const std::bad_alloc&) { return E_INSUFFICIENT;
  } catch (...) { return E_GENERAL; }  // cb_assert throws: never let it cross cgo
}

int qv_2p_dkg(int alg, int role, uintptr_t h, int curve, uint8_t** key, size_t* keyl) {
  try {
  ctx_t c(role, h);
  buf_t b;
  error_t rv = alg == 0   ? api::ecdsa_2p::dkg(c.job, (curve_id)curve, b)
               : alg == 1 ? api::eddsa_2p::dkg(c.job, (curve_id)curve, b)
                          : api::schnorr_2p::dkg(c.job, (curve_id)curve, b);
  return rv ? rv : out(b, key, keyl);
  } catch (const std::bad_alloc&) { return E_INSUFFICIENT;
  } catch (...) { return E_GENERAL; }  // cb_assert throws: never let it cross cgo
}

int qv_2p_sign(int alg, int role, uintptr_t h, const uint8_t* key, size_t keyl, const uint8_t* msg, size_t msgl,
               uint8_t** sig, size_t* sigl) {
  try {
  ctx_t c(role, h);
  buf_t s, sid;
  error_t rv = alg == 0   ? api::ecdsa_2p::sign(c.job, M(key, keyl), M(msg, msgl), sid, s)
               : alg == 1 ? api::eddsa_2p::sign(c.job, M(key, keyl), M(msg, msgl), s)
                          : api::schnorr_2p::sign(c.job, M(key, keyl), M(msg, msgl), s);
  return rv ? rv : out(s, sig, sigl);
  } catch (const std::bad_alloc&) { return E_INSUFFICIENT;
  } catch (...) { return E_GENERAL; }  // cb_assert throws: never let it cross cgo
}

int qv_2p_pub(int alg, const uint8_t* key, size_t keyl, uint8_t** pub, size_t* publ) {
  try {
  buf_t b;
  error_t rv = alg == 0   ? api::ecdsa_2p::get_public_key_compressed(M(key, keyl), b)
               : alg == 1 ? api::eddsa_2p::get_public_key_compressed(M(key, keyl), b)
                          : api::schnorr_2p::get_public_key_compressed(M(key, keyl), b);
  return rv ? rv : out(b, pub, publ);
  } catch (const std::bad_alloc&) { return E_INSUFFICIENT;
  } catch (...) { return E_GENERAL; }  // cb_assert throws: never let it cross cgo
}

int qv_schnorr_xonly(const uint8_t* key, size_t keyl, uint8_t** pub, size_t* publ) {
  try {
  buf_t b;
  error_t rv = api::schnorr_2p::extract_public_key_xonly(M(key, keyl), b);
  return rv ? rv : out(b, pub, publ);
  } catch (const std::bad_alloc&) { return E_INSUFFICIENT;
  } catch (...) { return E_GENERAL; }  // cb_assert throws: never let it cross cgo
}

int qv_ks_split(int ecdsa, const uint8_t* ks, size_t ksl, uint8_t** stripped, size_t* sl, uint8_t** x, size_t* xl,
                uint8_t** k, size_t* kl, uint8_t** Qx33, uint8_t** Qk33) {
  try {
  if (!ecdsa) return E_NOT_SUPPORTED;
  ks_blob_t blob;
  if (error_t rv = convert(blob, M(ks, ksl))) return rv;
  ecurve_t curve = crypto::curve_secp256k1;
  const mod_t& q = curve.order();
  out(blob.x_share.to_bin(), x, xl);
  out(blob.k_share.to_bin(), k, kl);
  *Qx33 = (uint8_t*)malloc(33);
  *Qk33 = (uint8_t*)malloc(33);
  curve.mul_to_generator(blob.x_share % q).to_compressed_bin(*Qx33);
  curve.mul_to_generator(blob.k_share % q).to_compressed_bin(*Qk33);
  blob.x_share = 0;
  blob.k_share = 0;
  return out(convert(blob), stripped, sl);
  } catch (const std::bad_alloc&) { return E_INSUFFICIENT;
  } catch (...) { return E_GENERAL; }  // cb_assert throws: never let it cross cgo
}

int qv_ks_join(int ecdsa, const uint8_t* stripped, size_t sl, const uint8_t* x, size_t xl, const uint8_t* k,
               size_t kl, uint8_t** ks, size_t* ksl) {
  try {
  if (!ecdsa) return E_NOT_SUPPORTED;
  ks_blob_t blob;
  if (error_t rv = convert(blob, M(stripped, sl))) return rv;
  blob.x_share = bn_t::from_bin(M(x, xl));
  blob.k_share = bn_t::from_bin(M(k, kl));
  return out(convert(blob), ks, ksl);
  } catch (const std::bad_alloc&) { return E_INSUFFICIENT;
  } catch (...) { return E_GENERAL; }  // cb_assert throws: never let it cross cgo
}

int qv_pve_keygen(int curve, uint8_t** ek, size_t* ekl, uint8_t** dk, size_t* dkl) {
  try {
  (void)curve;
  buf_t e, d;
  if (error_t rv = api::pve::generate_base_pke_rsa_keypair(e, d)) return rv;
  out(e, ek, ekl);
  return out(d, dk, dkl);
  } catch (const std::bad_alloc&) { return E_INSUFFICIENT;
  } catch (...) { return E_GENERAL; }  // cb_assert throws: never let it cross cgo
}

int qv_pve_encrypt(int curve, const uint8_t* ek, size_t ekl, const uint8_t* label, size_t labell, const uint8_t* xs[],
                   const size_t xsl[], size_t n, uint8_t** ct, size_t* ctl) {
  try {
  std::vector<mem_t> v;
  for (size_t i = 0; i < n; i++) v.push_back(M(xs[i], xsl[i]));
  buf_t b;
  error_t rv = api::pve::encrypt_batch((curve_id)curve, M(ek, ekl), M(label, labell), v, b);
  return rv ? rv : out(b, ct, ctl);
  } catch (const std::bad_alloc&) { return E_INSUFFICIENT;
  } catch (...) { return E_GENERAL; }  // cb_assert throws: never let it cross cgo
}

int qv_pve_verify(int curve, const uint8_t* ek, size_t ekl, const uint8_t* ct, size_t ctl, const uint8_t* Qs[],
                  const size_t Qsl[], size_t n, const uint8_t* label, size_t labell) {
  try {
  std::vector<mem_t> v;
  for (size_t i = 0; i < n; i++) v.push_back(M(Qs[i], Qsl[i]));
  return api::pve::verify_batch((curve_id)curve, M(ek, ekl), M(ct, ctl), v, M(label, labell));
  } catch (const std::bad_alloc&) { return E_INSUFFICIENT;
  } catch (...) { return E_GENERAL; }  // cb_assert throws: never let it cross cgo
}

int qv_pve_decrypt(int curve, const uint8_t* dk, size_t dkl, const uint8_t* ek, size_t ekl, const uint8_t* ct,
                   size_t ctl, const uint8_t* label, size_t labell, uint8_t** xs, size_t* xsl, size_t* n) {
  try {
  std::vector<buf_t> v;
  error_t rv = api::pve::decrypt_batch((curve_id)curve, M(dk, dkl), M(ek, ekl), M(ct, ctl),
                                                              M(label, labell), v);
  if (rv) return rv;
  std::vector<uint8_t> flat;
  for (auto& b : v) flat.insert(flat.end(), b.data(), b.data() + b.size());
  *n = v.size();
  return out(flat, xs, xsl);
  } catch (const std::bad_alloc&) { return E_INSUFFICIENT;
  } catch (...) { return E_GENERAL; }  // cb_assert throws: never let it cross cgo
}

}  // extern "C"
