package main

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestStreamSunnyWorkerPoolLimitsConcurrencyAndStreamsResults(t *testing.T) {
	candidates := []int{0, 1, 2, 3, 4, 5, 6, 7}
	release := make(chan struct{})
	var active int32
	var maximum int32
	results := streamSunnyWorkerPool(candidates, 3, func(candidate int) int {
		current := atomic.AddInt32(&active, 1)
		for {
			observed := atomic.LoadInt32(&maximum)
			if current <= observed || atomic.CompareAndSwapInt32(&maximum, observed, current) {
				break
			}
		}
		if candidate != 0 {
			<-release
		}
		atomic.AddInt32(&active, -1)
		return candidate
	})

	select {
	case first := <-results:
		if first != 0 {
			t.Fatalf("first streamed result = %d, want 0", first)
		}
	case <-time.After(time.Second):
		t.Fatal("first result was not streamed while the rest of the batch was running")
	}

	close(release)
	seen := map[int]bool{0: true}
	for result := range results {
		seen[result] = true
	}
	if len(seen) != len(candidates) {
		t.Fatalf("received %d results, want %d", len(seen), len(candidates))
	}
	if got := atomic.LoadInt32(&maximum); got > 3 {
		t.Fatalf("maximum concurrency = %d, want at most 3", got)
	}
}

func TestStreamSunnyWorkerPoolRefillsFreedWorkerImmediately(t *testing.T) {
	started := make(chan int, 3)
	releaseFirst := make(chan struct{})
	releaseOthers := make(chan struct{})
	results := streamSunnyWorkerPool([]int{0, 1, 2}, 2, func(candidate int) int {
		started <- candidate
		if candidate == 0 {
			<-releaseFirst
		} else {
			<-releaseOthers
		}
		return candidate
	})

	initial := map[int]bool{}
	for len(initial) < 2 {
		select {
		case candidate := <-started:
			initial[candidate] = true
		case <-time.After(time.Second):
			t.Fatal("initial workers did not start")
		}
	}
	if !initial[0] || !initial[1] {
		t.Fatalf("initial workers started %v, want candidates 0 and 1", initial)
	}

	close(releaseFirst)
	select {
	case result := <-results:
		if result != 0 {
			t.Fatalf("first completed result = %d, want 0", result)
		}
	case <-time.After(time.Second):
		t.Fatal("first worker did not complete")
	}
	select {
	case candidate := <-started:
		if candidate != 2 {
			t.Fatalf("replacement worker started candidate %d, want 2", candidate)
		}
	case <-time.After(time.Second):
		t.Fatal("next candidate did not start while another worker was still running")
	}

	close(releaseOthers)
	for range results {
	}
}
