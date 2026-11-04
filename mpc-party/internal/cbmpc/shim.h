// C ABI over Coinbase cb-mpc (pinned in ../../cbmpc.pin). Only 2-party protocols.
//
// Conventions
//  - Every function returns 0 on success, else a non-zero code. Codes in the 0xff0n.... range come from cb-mpc
//    (category in bits 16..23: 1 generic, 3 network, 4 crypto, 6 openssl, 10 control flow), 0xff0b.... are shim codes.
//  - EVERY entry point catches every C++ exception (cb_assert throws) and returns an error code. Nothing may unwind
//    through cgo: that is std::terminate.
//  - Output buffers are malloc'ed by the shim; the caller frees them with qv_free (secrets: qv_wipe first).
//  - On failure no output pointer is set.
#pragma once
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

// shim-specific codes (cb-mpc ERRCODE(category, code) = 0xff000000 | category << 16 | code)
#define QV_E_TRANSPORT 0xff030001u  /* == cb-mpc E_NET_GENERAL */
#define QV_E_EXCEPTION 0xff0b0001u  /* a C++ exception other than the ones below was caught */
#define QV_E_ASSERT    0xff0b0002u  /* cb_assert failed inside cb-mpc (assertion_failed_t) */
#define QV_E_BADALLOC  0xff0b0003u  /* std::bad_alloc */
#define QV_E_LAYOUT    0xff0b0004u  /* blob did not match the layout this shim was written for */
#define QV_E_UNSUPPORTED 0xff0b0005u

enum { QV_ALG_ECDSA = 0, QV_ALG_EDDSA = 1, QV_ALG_SCHNORR = 2 };
enum { QV_CURVE_P256 = 1, QV_CURVE_SECP256K1 = 2, QV_CURVE_ED25519 = 3 };

void qv_free(void* p);
void qv_wipe(void* p, size_t n);   // OPENSSL_cleanse
int qv_mlock(void* p, size_t n);   // best effort, returns 0 on success

// The pinned source commit the library was built from is checked by the build script and pin_test.go.
// A compile-time identifier of the cb-mpc API generation we mirror:
const char* qv_layout_id(void);

// Test-only: throws on purpose. kind: 0 std::runtime_error, 1 cb_assert failure, 2 std::bad_alloc, 3 int, 4 nothing.
int qv_test_throw(int kind);

// ---- HD keysets. alg is QV_ALG_ECDSA (secp256k1 only) or QV_ALG_EDDSA (ed25519). role: 0 = p1, 1 = p2. h: transport handle.
int qv_hd_dkg(int alg, int role, uintptr_t h, uint8_t** ks, size_t* ksl);
int qv_hd_refresh(int alg, int role, uintptr_t h, const uint8_t* ks, size_t ksl, uint8_t** nks, size_t* nksl);
// Derive the key blob for (hardened_path, non_hardened_path). Needs both parties online.
int qv_hd_derive(int alg, int role, uintptr_t h, const uint8_t* ks, size_t ksl,
                 const uint32_t* hp, size_t hpn, const uint32_t* nhp, size_t nhpn, uint8_t** key, size_t* keyl);
// Hardened (VRF) step only: returns the node's compressed public key (33 bytes) and its chain code (32 bytes).
// *ql is 33 (secp256k1) or 32 (ed25519); Q has room for 33 bytes.
int qv_hd_node(int alg, int role, uintptr_t h, const uint8_t* ks, size_t ksl, const uint32_t* hp, size_t hpn,
               uint8_t Q[33], size_t* ql, uint8_t cc32[32]);
int qv_hd_root_pub(int alg, const uint8_t* ks, size_t ksl, uint8_t** q, size_t* ql);
// Parse a keyset blob: checks version/role/curve and ranges, returns role and curve id.
int qv_hd_info(int alg, const uint8_t* ks, size_t ksl, int* role, int* curve);

// ---- Plain 2PC keys (derived keys, BIP340 keys). alg: ECDSA, EDDSA or SCHNORR.
int qv_2p_dkg(int alg, int role, uintptr_t h, int curve, uint8_t** key, size_t* keyl);
int qv_2p_refresh(int alg, int role, uintptr_t h, const uint8_t* key, size_t keyl, uint8_t** nkey, size_t* nkeyl);
// Only role 0 (p1) receives the signature; for role 1 *sig is NULL and *sigl 0.
int qv_2p_sign(int alg, int role, uintptr_t h, const uint8_t* key, size_t keyl,
               const uint8_t* msg, size_t msgl, uint8_t** sig, size_t* sigl);
int qv_2p_pub(int alg, const uint8_t* key, size_t keyl, uint8_t** pub, size_t* publ);
int qv_schnorr_xonly(const uint8_t* key, size_t keyl, uint8_t** pub, size_t* publ);

// ---- Backup: split a keyset into (stripped blob, x mod q, k) and back.
// For p1 the stripped blob still holds the Paillier private key and c_key: it is as sensitive as the whole keyset.
// xq and k are 32-byte big-endian (malloc'ed, 32 bytes). Qx/Qk are the compressed public points of xq and k
// (*ql bytes each: 33 secp256k1, 32 ed25519; buffers have room for 33). *x_reduced is 1 if x was >= q (p1 after a
// refresh), i.e. the exact x is only recoverable from the stripped blob.
int qv_ks_split(int alg, const uint8_t* ks, size_t ksl, uint8_t** stripped, size_t* sl,
                uint8_t** xq, uint8_t** k, uint8_t Qx[33], uint8_t Qk[33], size_t* ql, int* x_reduced);
// p1: the exact x is recomputed by decrypting c_key (it may exceed q after a refresh) and must match xq mod q.
int qv_ks_join(int alg, const uint8_t* stripped, size_t sl, const uint8_t* xq, const uint8_t* k,
               const uint8_t* Qx, const uint8_t* Qk, size_t ql, uint8_t** ks, size_t* ksl);

// ---- PVE (publicly verifiable encryption) of 32-byte scalars to an RSA-OAEP backup key.
int qv_pve_keygen(uint8_t** ek, size_t* ekl, uint8_t** dk, size_t* dkl);
int qv_pve_encrypt(int curve, const uint8_t* ek, size_t ekl, const uint8_t* label, size_t labell,
                   const uint8_t* xs32, size_t n, uint8_t** ct, size_t* ctl);
int qv_pve_verify(int curve, const uint8_t* ek, size_t ekl, const uint8_t* ct, size_t ctl,
                  const uint8_t* Qs, size_t ql, size_t n, const uint8_t* label, size_t labell);
// Output: n scalars, each exactly 32 bytes, concatenated.
int qv_pve_decrypt(int curve, const uint8_t* dk, size_t dkl, const uint8_t* ek, size_t ekl,
                   const uint8_t* ct, size_t ctl, const uint8_t* label, size_t labell, uint8_t** xs32, size_t* n);

// Implemented in Go (cgo //export): one blocking transport per protocol session. Return 0 or non-zero.
int qv_go_send(uintptr_t h, void* msg, size_t len);
int qv_go_recv(uintptr_t h, void** out, size_t* outlen);  // *out is malloc'ed, freed by the shim

#ifdef __cplusplus
}
#endif
