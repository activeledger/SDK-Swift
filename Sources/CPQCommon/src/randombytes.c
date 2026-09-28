#include "randombytes.h"

#include <stddef.h>
#include <stdint.h>

#if defined(__APPLE__)
#include <sys/random.h>   /* getentropy */
#elif defined(__linux__)
#include <sys/random.h>   /* getentropy (glibc 2.25+) */
#include <errno.h>
#endif

#include <stdio.h>

/* Thread-local seeded state. __thread is understood by clang and gcc, the
 * only compilers SwiftPM drives here. */
static __thread const uint8_t *al_seed = NULL;
static __thread size_t al_seed_len = 0;
static __thread size_t al_seed_pos = 0;

void al_pq_seed_begin(const uint8_t *seed, size_t len) {
    al_seed = seed;
    al_seed_len = len;
    al_seed_pos = 0;
}

size_t al_pq_seed_end(void) {
    size_t consumed = al_seed_pos;
    al_seed = NULL;
    al_seed_len = 0;
    al_seed_pos = 0;
    return consumed;
}

/* Draw from the OS CSPRNG. Returns 0 on success, -1 on failure. */
static int os_random(uint8_t *output, size_t n) {
#if defined(__APPLE__) || defined(__linux__)
    size_t off = 0;
    while (off < n) {
        size_t chunk = n - off;
        if (chunk > 256) {
            chunk = 256;   /* getentropy refuses more than 256 bytes */
        }
        if (getentropy(output + off, chunk) != 0) {
            goto urandom;   /* fall back to /dev/urandom */
        }
        off += chunk;
    }
    return 0;
urandom:
#endif
    {
        FILE *f = fopen("/dev/urandom", "rb");
        if (f == NULL) {
            return -1;
        }
        size_t got = fread(output, 1, n, f);
        fclose(f);
        return got == n ? 0 : -1;
    }
}

int randombytes(uint8_t *output, size_t n) {
    if (al_seed != NULL && al_seed_len > 0) {
        for (size_t i = 0; i < n; i++) {
            /* Cycling past the end keeps every byte defined; al_pq_seed_end
             * then reports the overrun so the caller can reject the key. */
            output[i] = al_seed[al_seed_pos++ % al_seed_len];
        }
        return 0;
    }
    return os_random(output, n);
}
