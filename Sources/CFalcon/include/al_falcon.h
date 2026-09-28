#ifndef ACTIVELEDGER_FALCON_H
#define ACTIVELEDGER_FALCON_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Keys carry PQClean/liboqs's 1-byte header (0x09 public, 0x59 private), so
 * they are 897 and 1281 bytes - the byte forms the ledger uses. */
#define AL_FALCON512_PUBLICKEYBYTES 897
#define AL_FALCON512_SECRETKEYBYTES 1281
/* Maximum compressed signature length; the actual length varies. */
#define AL_FALCON512_SIGNATUREBYTES 752
#define AL_FALCON512_SEEDBYTES 48

/*
 * Key pair from a 48-byte seed. Deterministic: Falcon key generation reads
 * exactly 48 bytes of randomness and expands them with SHAKE-256, so feeding
 * it the seed gives the key every Activeledger SDK derives from that seed.
 * Returns 0 on success, -1 if seedlen is not 48, if key generation drew a
 * number of random bytes other than the seed length, or on an internal error.
 */
int al_falcon512_keypair_from_seed(uint8_t *pk, uint8_t *sk,
                                   const uint8_t *seed, size_t seedlen);

/* Key pair from the OS CSPRNG. Returns 0 on success, -1 on error. */
int al_falcon512_keypair(uint8_t *pk, uint8_t *sk);

/*
 * Detached, compressed signature (header 0x39) over (m, mlen). Randomised, as
 * in the reference SDK. *siglen is set to the actual length, which varies and
 * is at most AL_FALCON512_SIGNATUREBYTES, so sig must have that much room.
 * Returns 0 on success, -1 on error.
 */
int al_falcon512_sign(uint8_t *sig, size_t *siglen,
                      const uint8_t *m, size_t mlen, const uint8_t *sk);

/* Verify a detached signature. Returns 0 if valid, -1 otherwise. */
int al_falcon512_verify(const uint8_t *sig, size_t siglen,
                        const uint8_t *m, size_t mlen, const uint8_t *pk);

#ifdef __cplusplus
}
#endif

#endif /* ACTIVELEDGER_FALCON_H */
