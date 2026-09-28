#include "al_falcon.h"

#include "api.h"        /* PQClean Falcon-512 clean, in ../pqclean */
#include "randombytes.h" /* CPQCommon: randombytes + al_pq_seed_begin/end */

int al_falcon512_keypair_from_seed(uint8_t *pk, uint8_t *sk,
                                   const uint8_t *seed, size_t seedlen) {
    if (seedlen != AL_FALCON512_SEEDBYTES) {
        return -1;
    }
    al_pq_seed_begin(seed, seedlen);
    int rc = PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair(pk, sk);
    size_t consumed = al_pq_seed_end();
    if (rc != 0) {
        return -1;
    }
    /* Falcon key generation reads exactly 48 bytes once. A different count
     * means this build does not derive the portable, seed-determined key. */
    if (consumed != seedlen) {
        return -1;
    }
    return 0;
}

int al_falcon512_keypair(uint8_t *pk, uint8_t *sk) {
    return PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair(pk, sk) == 0 ? 0 : -1;
}

int al_falcon512_sign(uint8_t *sig, size_t *siglen,
                      const uint8_t *m, size_t mlen, const uint8_t *sk) {
    return PQCLEAN_FALCON512_CLEAN_crypto_sign_signature(sig, siglen, m, mlen,
                                                         sk) == 0
               ? 0
               : -1;
}

int al_falcon512_verify(const uint8_t *sig, size_t siglen,
                        const uint8_t *m, size_t mlen, const uint8_t *pk) {
    return PQCLEAN_FALCON512_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk)
                   == 0
               ? 0
               : -1;
}
