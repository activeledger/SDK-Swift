#ifndef ACTIVELEDGER_MLDSA_H
#define ACTIVELEDGER_MLDSA_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define AL_MLDSA65_PUBLICKEYBYTES 1952
#define AL_MLDSA65_SECRETKEYBYTES 4032
#define AL_MLDSA65_SIGNATUREBYTES 3309
#define AL_MLDSA65_SEEDBYTES 32

/*
 * Key pair from a 32-byte seed. Deterministic: the seed is the FIPS 204
 * key-generation seed (xi), so the same seed gives the same key in every
 * Activeledger SDK. Returns 0 on success, -1 if seedlen is not 32, if key
 * generation drew a number of random bytes other than the seed length, or on
 * an internal error.
 */
int al_mldsa65_keypair_from_seed(uint8_t *pk, uint8_t *sk,
                                 const uint8_t *seed, size_t seedlen);

/* Key pair from the OS CSPRNG. Returns 0 on success, -1 on error. */
int al_mldsa65_keypair(uint8_t *pk, uint8_t *sk);

/*
 * Detached signature over (m, mlen). Hedged (randomised) as in the reference
 * SDK: two signatures over one message differ, and both verify. *siglen is
 * set to the signature length (always AL_MLDSA65_SIGNATUREBYTES for ML-DSA).
 * Returns 0 on success, -1 on error.
 */
int al_mldsa65_sign(uint8_t *sig, size_t *siglen,
                    const uint8_t *m, size_t mlen, const uint8_t *sk);

/* Verify a detached signature. Returns 0 if valid, -1 otherwise. */
int al_mldsa65_verify(const uint8_t *sig, size_t siglen,
                      const uint8_t *m, size_t mlen, const uint8_t *pk);

#ifdef __cplusplus
}
#endif

#endif /* ACTIVELEDGER_MLDSA_H */
