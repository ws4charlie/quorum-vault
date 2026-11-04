// Thin C shim over cb-mpc's C++ API (HD keysets, ECDSA/EdDSA/Schnorr 2PC, PVE).
// All functions return 0 on success, else a cb-mpc error code. Output buffers are
// malloc'ed by the shim and must be released with qv_free.
#pragma once
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif


void qv_free(void* p);
void qv_wipe(void* p, size_t n);

// role: 0 = p1, 1 = p2. curve: 1 p256, 2 secp256k1, 3 ed25519.
int qv_hd_dkg(int ecdsa, int role, uintptr_t h, int curve, uint8_t** ks, size_t* ksl);
int qv_hd_refresh(int ecdsa, int role, uintptr_t h, const uint8_t* ks, size_t ksl, uint8_t** nks, size_t* nksl);
// Derive one key blob for (hardened_path, one non-hardened path). sid in/out (may be empty on input).
int qv_hd_derive(int ecdsa, int role, uintptr_t h, const uint8_t* ks, size_t ksl,
                 const uint32_t* hp, size_t hpn, const uint32_t* nhp, size_t nhpn,
                 uint8_t** sid, size_t* sidl, uint8_t** key, size_t* keyl);
// ECDSA only: run the hardened (VRF) step and also return the account node's public key
// (33 bytes) and chain code (32 bytes), i.e. the material of an xpub. Both parties learn it.
int qv_hd_node_ecdsa(int role, uintptr_t h, const uint8_t* ks, size_t ksl,
                     const uint32_t* hp, size_t hpn, uint8_t** sid, size_t* sidl,
                     uint8_t Q33[33], uint8_t cc32[32]);
int qv_hd_root_pub(int ecdsa, const uint8_t* ks, size_t ksl, uint8_t** q, size_t* ql);

// Plain (non-HD) 2PC keys.
int qv_2p_dkg(int alg /*0 ecdsa,1 eddsa,2 schnorr*/, int role, uintptr_t h, int curve, uint8_t** key, size_t* keyl);
int qv_2p_sign(int alg, int role, uintptr_t h, const uint8_t* key, size_t keyl,
               const uint8_t* msg, size_t msgl, uint8_t** sig, size_t* sigl);
int qv_2p_pub(int alg, const uint8_t* key, size_t keyl, uint8_t** pub, size_t* publ);
int qv_schnorr_xonly(const uint8_t* key, size_t keyl, uint8_t** pub, size_t* publ);

// Backup: split a keyset blob into (blob without scalars) + big-endian x, k; and the reverse.
int qv_ks_split(int ecdsa, const uint8_t* ks, size_t ksl, uint8_t** stripped, size_t* sl,
                uint8_t** x, size_t* xl, uint8_t** k, size_t* kl, uint8_t** Qx33, uint8_t** Qk33);
int qv_ks_join(int ecdsa, const uint8_t* stripped, size_t sl, const uint8_t* x, size_t xl,
               const uint8_t* k, size_t kl, uint8_t** ks, size_t* ksl);

// PVE (publicly verifiable encryption) of a batch of scalars to an RSA-OAEP backup key.
int qv_pve_keygen(int curve, uint8_t** ek, size_t* ekl, uint8_t** dk, size_t* dkl);
int qv_pve_encrypt(int curve, const uint8_t* ek, size_t ekl, const uint8_t* label, size_t labell,
                   const uint8_t* xs[], const size_t xsl[], size_t n, uint8_t** ct, size_t* ctl);
int qv_pve_verify(int curve, const uint8_t* ek, size_t ekl, const uint8_t* ct, size_t ctl,
                  const uint8_t* Qs[], const size_t Qsl[], size_t n, const uint8_t* label, size_t labell);
int qv_pve_decrypt(int curve, const uint8_t* dk, size_t dkl, const uint8_t* ek, size_t ekl,
                   const uint8_t* ct, size_t ctl, const uint8_t* label, size_t labell,
                   uint8_t** xs, size_t* xsl, size_t* n);
#ifdef __cplusplus
}
#endif
