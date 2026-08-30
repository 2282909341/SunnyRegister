package main

import (
	"context"
	"sync"
)

func streamSunnyWorkerPool[Candidate any, Result any](candidates []Candidate, concurrency int, run func(Candidate) Result) <-chan Result {
	return streamSunnyWorkerPoolContext(context.Background(), candidates, concurrency, run)
}

func streamSunnyWorkerPoolContext[Candidate any, Result any](ctx context.Context, candidates []Candidate, concurrency int, run func(Candidate) Result) <-chan Result {
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
			for {
				select {
				case <-ctx.Done():
					return
				case candidate, ok := <-jobs:
					if !ok {
						return
					}
					if ctx.Err() != nil {
						return
					}
					result := run(candidate)
					select {
					case results <- result:
					case <-ctx.Done():
						return
					}
				}
			}
		}()
	}
	go func() {
		for _, candidate := range candidates {
			select {
			case jobs <- candidate:
			case <-ctx.Done():
				close(jobs)
				workers.Wait()
				close(results)
				return
			}
		}
		close(jobs)
		workers.Wait()
		close(results)
	}()
	return results
}
