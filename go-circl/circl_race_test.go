// Go harness #2: Cloudflare CIRCL — ML-DSA-65 and ML-KEM-768 keys shared across goroutines,
// run with the race detector. Author: Ayman Alsadig Mohamed Suliman
// RUN:  go mod tidy && go test -race -run TestSharedKey -v ./...
//
//	(THREADS / OPS env vars override the defaults 16 / 500)
//
// Schemes are looked up by name so a renamed scheme fails loudly with the list of names.
package circl

import (
	"bytes"
	"crypto/rand"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"

	kemschemes "github.com/cloudflare/circl/kem/schemes"
	signschemes "github.com/cloudflare/circl/sign/schemes"
)

func envInt(name string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(name)); err == nil && v > 0 {
		return v
	}
	return def
}

func TestSharedKeyCirclMLDSA65(t *testing.T) {
	s := signschemes.ByName("ML-DSA-65")
	if s == nil {
		var names []string
		for _, x := range signschemes.All() {
			names = append(names, x.Name())
		}
		t.Fatalf("ML-DSA-65 not found; available: %v", names)
	}
	pk, sk, err := s.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	G, N := envInt("THREADS", 16), envInt("OPS", 500)
	var wg sync.WaitGroup
	var bad, done atomic.Int64
	for g := 0; g < G; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			msg := make([]byte, 64)
			for i := 0; i < N; i++ {
				_, _ = rand.Read(msg)
				sig := s.Sign(sk, msg, nil) // shared private key
				if !s.Verify(pk, msg, sig, nil) {
					bad.Add(1)
				}
				done.Add(1)
			}
		}()
	}
	wg.Wait()
	if done.Load() != int64(G*N) || bad.Load() != 0 {
		t.Fatalf("INVARIANT VIOLATION: ran=%d of %d, bad=%d", done.Load(), G*N, bad.Load())
	}
	t.Logf("CIRCL shared-key ML-DSA-65: %d goroutines x %d ops, 0 bad", G, N)
}

func TestSharedKeyCirclMLKEM768(t *testing.T) {
	s := kemschemes.ByName("ML-KEM-768")
	if s == nil {
		var names []string
		for _, x := range kemschemes.All() {
			names = append(names, x.Name())
		}
		t.Fatalf("ML-KEM-768 not found; available: %v", names)
	}
	pk, sk, err := s.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	G, N := envInt("THREADS", 16), envInt("OPS", 500)
	var wg sync.WaitGroup
	var bad, fail, done atomic.Int64
	for g := 0; g < G; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < N; i++ {
				ct, ss1, err := s.Encapsulate(pk) // shared public key
				if err == nil {
					var ss2 []byte
					ss2, err = s.Decapsulate(sk, ct) // shared private key
					if err == nil && !bytes.Equal(ss1, ss2) {
						bad.Add(1)
					}
				}
				if err != nil {
					fail.Add(1)
				}
				done.Add(1)
			}
		}()
	}
	wg.Wait()
	if done.Load() != int64(G*N) || bad.Load() != 0 || fail.Load() != 0 {
		t.Fatalf("INVARIANT VIOLATION: ran=%d of %d, mismatch=%d fail=%d", done.Load(), G*N, bad.Load(), fail.Load())
	}
	t.Logf("CIRCL shared-key ML-KEM-768: %d goroutines x %d ops, 0 mismatch, 0 fail", G, N)
}
