// C harness: OpenSSL 3.5+ native ML-DSA-65 / ML-KEM-768 under ThreadSanitizer.
//   shared-key   ONE EVP_PKEY shared by all threads, each thread uses its own EVP_PKEY_CTX
//                (the documented-safe pattern). Invariants must hold and TSan must stay silent.
//   shared-ctx   ONE signing EVP_PKEY_CTX shared by all threads with no lock (misuse; contexts are
//                not documented as thread-safe). Each call re-initialises the shared context and
//                signs, exactly like the Java JCA initSign/sign pattern. Outcomes are classified:
//                ok / loud (error returned) / invalid / crossValid (another thread's message).
//   locked-ctx   same as shared-ctx under a mutex: the control, must be all ok.
// Author: Ayman Alsadig Mohamed Suliman
// BUILD: cc -fsanitize=thread -O1 -g openssl_shared.c -lcrypto -lpthread -ldl
// THREADS / OPS env vars (defaults 16 / 500); MISUSE_THREADS / MISUSE_OPS for the ctx modes.
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <openssl/rand.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MSG_LEN 64

static EVP_PKEY *sig_key, *kem_key;          // shared keys
static EVP_SIGNATURE *sig_alg;               // fetched once, read-only
static EVP_PKEY_CTX *shared_ctx;             // shared signing context (ctx modes only)
static pthread_mutex_t ctx_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_barrier_t start_b, done_b;
static int G, N, mode_locked;
static size_t sig_max;
static uint8_t *msgs;                        // [G][N][MSG_LEN]
static atomic_long ok_n, loud_n, invalid_n, cross_n, kem_ok_n, kem_bad_n, kem_err_n;

static int env_int(const char *name, int def) {
  const char *v = getenv(name);
  int x = v ? atoi(v) : 0;
  return x > 0 ? x : def;
}

static uint8_t *msg_at(int t, int i) { return msgs + ((size_t)t * N + i) * MSG_LEN; }

static int verify(const uint8_t *m, const uint8_t *sig, size_t siglen) {
  EVP_PKEY_CTX *v = EVP_PKEY_CTX_new_from_pkey(NULL, sig_key, NULL);
  int r = v && EVP_PKEY_verify_message_init(v, sig_alg, NULL) == 1 &&
          EVP_PKEY_verify(v, sig, siglen, m, MSG_LEN) == 1;
  EVP_PKEY_CTX_free(v);
  ERR_clear_error();
  return r;
}

static int sign_with(EVP_PKEY_CTX *c, const uint8_t *m, uint8_t *sig, size_t *siglen) {
  *siglen = sig_max;
  return EVP_PKEY_sign_message_init(c, sig_alg, NULL) == 1 &&
         EVP_PKEY_sign(c, sig, siglen, m, MSG_LEN) == 1;
}

// ---- documented-safe pattern: shared key, private contexts ---------------------------------
static void *key_worker(void *arg) {
  (void)arg;
  uint8_t m[MSG_LEN], *sig = malloc(sig_max);
  for (int i = 0; i < N; i++) {
    size_t siglen;
    RAND_bytes(m, sizeof m);
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_pkey(NULL, sig_key, NULL);
    if (!c || !sign_with(c, m, sig, &siglen)) atomic_fetch_add(&loud_n, 1);
    else if (verify(m, sig, siglen)) atomic_fetch_add(&ok_n, 1);
    else atomic_fetch_add(&invalid_n, 1);
    EVP_PKEY_CTX_free(c);

    uint8_t ct[2048], ss1[64], ss2[64];
    size_t ctlen = sizeof ct, s1 = sizeof ss1, s2 = sizeof ss2;
    EVP_PKEY_CTX *e = EVP_PKEY_CTX_new_from_pkey(NULL, kem_key, NULL);
    EVP_PKEY_CTX *d = EVP_PKEY_CTX_new_from_pkey(NULL, kem_key, NULL);
    if (!e || !d || EVP_PKEY_encapsulate_init(e, NULL) != 1 ||
        EVP_PKEY_encapsulate(e, ct, &ctlen, ss1, &s1) != 1 ||
        EVP_PKEY_decapsulate_init(d, NULL) != 1 ||
        EVP_PKEY_decapsulate(d, ss2, &s2, ct, ctlen) != 1) atomic_fetch_add(&kem_err_n, 1);
    else if (s1 == s2 && memcmp(ss1, ss2, s1) == 0) atomic_fetch_add(&kem_ok_n, 1);
    else atomic_fetch_add(&kem_bad_n, 1);
    EVP_PKEY_CTX_free(e); EVP_PKEY_CTX_free(d);
    ERR_clear_error();
  }
  free(sig);
  return NULL;
}

// ---- misuse pattern: one shared signing context --------------------------------------------
static void *ctx_worker(void *arg) {
  int t = (int)(intptr_t)arg;
  uint8_t *sig = malloc(sig_max);
  for (int i = 0; i < N; i++) {
    size_t siglen = 0;
    int good;
    pthread_barrier_wait(&start_b);
    if (mode_locked) pthread_mutex_lock(&ctx_lock);
    good = sign_with(shared_ctx, msg_at(t, i), sig, &siglen);
    if (mode_locked) pthread_mutex_unlock(&ctx_lock);
    ERR_clear_error();
    pthread_barrier_wait(&done_b);
    if (!good) { atomic_fetch_add(&loud_n, 1); continue; }
    if (verify(msg_at(t, i), sig, siglen)) { atomic_fetch_add(&ok_n, 1); continue; }
    int cross = 0;
    for (int j = 0; j < G && !cross; j++) if (j != t && verify(msg_at(j, i), sig, siglen)) cross = 1;
    atomic_fetch_add(cross ? &cross_n : &invalid_n, 1);
  }
  free(sig);
  return NULL;
}

int main(int argc, char **argv) {
  const char *mode = argc > 1 ? argv[1] : "shared-key";
  int ctx_mode = strcmp(mode, "shared-key") != 0;
  mode_locked = strcmp(mode, "locked-ctx") == 0;
  G = ctx_mode ? env_int("MISUSE_THREADS", 8) : env_int("THREADS", 16);
  N = ctx_mode ? env_int("MISUSE_OPS", 300) : env_int("OPS", 500);

  sig_key = EVP_PKEY_Q_keygen(NULL, NULL, "ML-DSA-65");
  kem_key = EVP_PKEY_Q_keygen(NULL, NULL, "ML-KEM-768");
  sig_alg = EVP_SIGNATURE_fetch(NULL, "ML-DSA-65", NULL);
  if (!sig_key || !kem_key || !sig_alg) { ERR_print_errors_fp(stderr); fprintf(stderr, "setup failed\n"); return 2; }
  sig_max = (size_t)EVP_PKEY_get_size(sig_key);

  pthread_t *th = calloc((size_t)G, sizeof *th);
  if (ctx_mode) {
    shared_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, sig_key, NULL);
    msgs = malloc((size_t)G * N * MSG_LEN);
    RAND_bytes(msgs, G * N * MSG_LEN);
    pthread_barrier_init(&start_b, NULL, (unsigned)G);
    pthread_barrier_init(&done_b, NULL, (unsigned)G);
    for (int g = 0; g < G; g++) pthread_create(&th[g], NULL, ctx_worker, (void *)(intptr_t)g);
  } else {
    for (int g = 0; g < G; g++) pthread_create(&th[g], NULL, key_worker, NULL);
  }
  for (int g = 0; g < G; g++) pthread_join(th[g], NULL);

  long total = (long)G * N;
  printf("RESULT provider=OpenSSL/%s alg=ML-DSA-65 mode=%s threads=%d ops=%d msgBytes=%d total=%ld ok=%ld loud=%ld invalid=%ld crossValid=%ld mixedValid=0 emptyMessage=0\n",
         OPENSSL_VERSION_STR, mode, G, N, MSG_LEN, total, atomic_load(&ok_n), atomic_load(&loud_n),
         atomic_load(&invalid_n), atomic_load(&cross_n));
  if (!ctx_mode)
    printf("OpenSSL %s shared-key ML-KEM-768: %d threads x %d ops, ok=%ld mismatch=%ld err=%ld\n",
           OPENSSL_VERSION_STR, G, N, atomic_load(&kem_ok_n), atomic_load(&kem_bad_n), atomic_load(&kem_err_n));
  long classified = atomic_load(&ok_n) + atomic_load(&loud_n) + atomic_load(&invalid_n) + atomic_load(&cross_n);
  if (classified != total) { printf("HARNESS ERROR: classified %ld of %ld\n", classified, total); return 1; }
  if (!ctx_mode && (atomic_load(&ok_n) != total || atomic_load(&kem_ok_n) != total)) { printf("INVARIANT VIOLATION\n"); return 1; }
  if (mode_locked && atomic_load(&ok_n) != total) { printf("CONTROL FAILED: locked-ctx must be all ok\n"); return 1; }
  return 0;
}
