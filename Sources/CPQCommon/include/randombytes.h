#ifndef ACTIVELEDGER_PQ_RANDOMBYTES_H
#define ACTIVELEDGER_PQ_RANDOMBYTES_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The randombytes() the PQClean sources call. Returns 0 on success.
 *
 * By default it draws from the operating system CSPRNG. While a seed is
 * armed (see al_pq_seed_begin) it instead returns bytes from that seed, which
 * is how deterministic, seed-derived key generation is done: PQClean's
 * crypto_sign_keypair reads its entire randomness through this one call, so
 * feeding it the seed makes the key a pure function of the seed - the same
 * identity every Activeledger SDK derives from that seed.
 */
int randombytes(uint8_t *output, size_t n);

/*
 * Arm the seeded source for the current thread. Subsequent randombytes()
 * calls on this thread return bytes drawn from seed[0..len), cycling if more
 * are requested than the seed holds. The armed state is thread-local, so it
 * never affects randombytes() on other threads (signing on another thread
 * keeps drawing from the OS CSPRNG).
 */
void al_pq_seed_begin(const uint8_t *seed, size_t len);

/*
 * Disarm the seeded source for the current thread and return how many bytes
 * randombytes() drew from the seed since al_pq_seed_begin. A value other than
 * the seed length means key generation did not consume exactly the seed, so
 * the key is not the portable one other SDKs derive and must be rejected.
 */
size_t al_pq_seed_end(void);

#ifdef __cplusplus
}
#endif

#endif /* ACTIVELEDGER_PQ_RANDOMBYTES_H */
