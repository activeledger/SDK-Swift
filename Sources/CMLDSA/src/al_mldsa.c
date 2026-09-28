#include "al_mldsa.h"

#include "api.h"        /* PQClean ML-DSA-65 clean, in ../pqclean */
#include "randombytes.h" /* CPQCommon: randombytes + al_pq_seed_begin/end */

int al_mldsa65_keypair_from_seed(uint8_t *pk, uint8_t *sk,
                                 const uint8_t *seed, size_t seedlen) {
    if (seedlen != AL_MLDSA65_SEEDBYTES) {
        return -1;
    }
    al_pq_seed_begin(seed, seedlen);
    int rc = PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair(pk, sk);
    size_t consumed = al_pq_seed_end();
    if (rc != 0) {
        return -1;
    }
    /* Key generation must consume exactly the seed; anything else means the
     * key is not the portable one other SDKs derive from this seed. */
    if (consumed != seedlen) {
        return -1;
    }
    return 0;
}

int al_mldsa65_keypair(uint8_t *pk, uint8_t *sk) {
    return PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair(pk, sk) == 0 ? 0 : -1;
}

int al_mldsa65_sign(uint8_t *sig, size_t *siglen,
                    const uint8_t *m, size_t mlen, const uint8_t *sk) {
    return PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk)
                   == 0
               ? 0
               : -1;
}

int al_mldsa65_verify(const uint8_t *sig, size_t siglen,
                      const uint8_t *m, size_t mlen, const uint8_t *pk) {
    return PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk)
                   == 0
               ? 0
               : -1;
}
