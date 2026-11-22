// Positive control for ThreadSanitizer in C: a deliberate data race.
// Built with -fsanitize=thread it MUST print "WARNING: ThreadSanitizer: data race".
#include <pthread.h>
#include <stdio.h>

static long shared;   // deliberately unsynchronised

static void *bump(void *arg) {
  (void)arg;
  for (int i = 0; i < 1000; i++) shared++;
  return NULL;
}

int main(void) {
  pthread_t a, b;
  pthread_create(&a, NULL, bump, NULL);
  pthread_create(&b, NULL, bump, NULL);
  pthread_join(a, NULL);
  pthread_join(b, NULL);
  printf("canary done: %ld\n", shared);
  return 0;
}
