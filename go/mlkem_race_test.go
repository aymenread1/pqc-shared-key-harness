// Go portable harness: shared ML-KEM key across goroutines, run with the race detector.
// Requires Go 1.24+ (crypto/mlkem). Author: Ayman Alsadig Mohamed Suliman
// RUN:  go test -race -run TestSharedKey -v ./...
//       (THREADS / OPS env vars override the defaults 16 / 500)
// Invariant: every encapsulation decapsulates to the same shared secret.
package pqcts

import (
	"bytes"
	"crypto/mlkem"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
)

func envInt(name string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(name)); err == nil && v > 0 {
		return v
	}
	return def
}

// Name starts with TestSharedKey so the documented `-run TestSharedKey` matches it.
func TestSharedKeyMLKEM768(t *testing.T) {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	ek := dk.EncapsulationKey() // shared across goroutines
	G, N := envInt("THREADS", 16), envInt("OPS", 500)
	var wg sync.WaitGroup
	var mismatch, fail, done atomic.Int64
	for g := 0; g < G; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < N; i++ {
				ss1, ct := ek.Encapsulate()    // shared encapsulation key
				ss2, err := dk.Decapsulate(ct) // shared decapsulation key
				if err != nil {
					fail.Add(1)
					continue
				}
				if !bytes.Equal(ss1, ss2) {
					mismatch.Add(1)
				}
				done.Add(1)
			}
		}()
	}
	wg.Wait()
	if want := int64(G * N); done.Load()+fail.Load() != want {
		t.Fatalf("only %d of %d operations ran", done.Load()+fail.Load(), want)
	}
	if mismatch.Load() != 0 || fail.Load() != 0 {
		t.Fatalf("INVARIANT VIOLATION: mismatch=%d fail=%d (and check -race output)", mismatch.Load(), fail.Load())
	}
	t.Logf("shared-key ML-KEM-768: %d goroutines x %d ops, 0 mismatch, 0 fail", G, N)
}
