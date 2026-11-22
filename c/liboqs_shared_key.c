// C harness: liboqs ML-DSA-65 and ML-KEM-768 — ONE OQS_SIG / OQS_KEM object and ONE key pair
// shared by all threads, built and run under ThreadSanitizer.
// Invariants: every signature verifies for its own message; every decapsulation returns the
// encapsulated secret. Author: Ayman Alsadig Mohamed Suliman
// BUILD (see Dockerfile): cc -fsanitize=thread -O1 -g liboqs_shared_key.c -loqs -lpthread
// THREADS / OPS env vars override the defaults 16 / 500.
#include <oqs/oqs.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static OQS_SIG *sig_obj;   // shared
static OQS_KEM *kem_obj;   // shared
static uint8_t *sig_pk, *sig_sk, *kem_pk, *kem_sk;   // shared keys
static int OPS;
static atomic_long sig_ok, sig_bad, sig_err, kem_ok, kem_bad, kem_err;

static int env_int(const char *name, int def) {
  const char *v = getenv(name);
  int x = v ? atoi(v) : 0;
  return x > 0 ? x : def;
}

static void *worker(void *arg) {
  (void)arg;
  uint8_t msg[64];
  uint8_t *signature = malloc(sig_obj->length_signature);
  uint8_t *ct = malloc(kem_obj->length_ciphertext);
  uint8_t *ss1 = malloc(kem_obj->length_shared_secret), *ss2 = malloc(kem_obj->length_shared_secret);
  for (int i = 0; i < OPS; i++) {
    size_t siglen = 0;
    OQS_randombytes(msg, sizeof msg);
    if (OQS_SIG_sign(sig_obj, signature, &siglen, msg, sizeof msg, sig_sk) != OQS_SUCCESS) atomic_fetch_add(&sig_err, 1);
    else if (OQS_SIG_verify(sig_obj, msg, sizeof msg, signature, siglen, sig_pk) == OQS_SUCCESS) atomic_fetch_add(&sig_ok, 1);
    else atomic_fetch_add(&sig_bad, 1);

    if (OQS_KEM_encaps(kem_obj, ct, ss1, kem_pk) != OQS_SUCCESS ||
        OQS_KEM_decaps(kem_obj, ss2, ct, kem_sk) != OQS_SUCCESS) atomic_fetch_add(&kem_err, 1);
    else if (memcmp(ss1, ss2, kem_obj->length_shared_secret) == 0) atomic_fetch_add(&kem_ok, 1);
    else atomic_fetch_add(&kem_bad, 1);
  }
  free(signature); free(ct); free(ss1); free(ss2);
  return NULL;
}

int main(void) {
  OQS_init();
  const int G = env_int("THREADS", 16);
  OPS = env_int("OPS", 500);
  sig_obj = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
  kem_obj = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
  if (!sig_obj || !kem_obj) { fprintf(stderr, "ML-DSA-65 or ML-KEM-768 not enabled in liboqs\n"); return 2; }
  sig_pk = malloc(sig_obj->length_public_key); sig_sk = malloc(sig_obj->length_secret_key);
  kem_pk = malloc(kem_obj->length_public_key); kem_sk = malloc(kem_obj->length_secret_key);
  if (OQS_SIG_keypair(sig_obj, sig_pk, sig_sk) != OQS_SUCCESS ||
      OQS_KEM_keypair(kem_obj, kem_pk, kem_sk) != OQS_SUCCESS) { fprintf(stderr, "keygen failed\n"); return 2; }

  pthread_t *th = calloc((size_t)G, sizeof *th);
  for (int g = 0; g < G; g++) pthread_create(&th[g], NULL, worker, NULL);
  for (int g = 0; g < G; g++) pthread_join(th[g], NULL);

  long want = (long)G * OPS;
  printf("liboqs %s shared-key ML-DSA-65: %d threads x %d ops, ok=%ld bad=%ld err=%ld\n",
         OQS_version(), G, OPS, atomic_load(&sig_ok), atomic_load(&sig_bad), atomic_load(&sig_err));
  printf("liboqs %s shared-key ML-KEM-768: %d threads x %d ops, ok=%ld mismatch=%ld err=%ld\n",
         OQS_version(), G, OPS, atomic_load(&kem_ok), atomic_load(&kem_bad), atomic_load(&kem_err));
  int pass = atomic_load(&sig_ok) == want && atomic_load(&kem_ok) == want;
  OQS_SIG_free(sig_obj); OQS_KEM_free(kem_obj);
  OQS_destroy();
  if (!pass) { printf("INVARIANT VIOLATION\n"); return 1; }
  return 0;
}
