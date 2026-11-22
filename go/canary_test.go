//go:build canary

// Positive control: proves the race detector is active in this environment.
// RUN: go test -race -tags canary -run TestCanary ./...   -> MUST FAIL with "DATA RACE".
package pqcts

import (
	"sync"
	"testing"
)

func TestCanaryDataRace(t *testing.T) {
	var shared int // deliberately unsynchronised
	var wg sync.WaitGroup
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				shared++
			}
		}()
	}
	wg.Wait()
	t.Logf("shared=%d", shared)
}
