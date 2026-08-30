package main

import (
	"sync"
)

func streamSunnyWorkerPool[Candidate any, Result any](candidates []Candidate, concurrency int, run func(Candidate) Result) <-chan Result {
	results := make(chan Result)
	if len(candidates) == 0 {
		close(results)
		return results
	}
	if concurrency < 1 {
		concurrency = 1
	}
	if concurrency > len(candidates) {
		concurrency = len(candidates)
	}
	jobs := make(chan Candidate)
	var workers sync.WaitGroup
	for index := 0; index < concurrency; index++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for candidate := range jobs {
				results <- run(candidate)
			}
		}()
	}
	go func() {
		for _, candidate := range candidates {
			jobs <- candidate
		}
		close(jobs)
		workers.Wait()
		close(results)
	}()
	return results
}
