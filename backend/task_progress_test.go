package main

import (
	"testing"
	"time"
)

func TestPersistTaskProgressUpdatesLiveCounters(t *testing.T) {
	s := newSunnySessionTestServer(t)
	task := s.createTask(sunnyTrialTaskType, "sunny", map[string]any{"session_ids": []uint{1}}, 3)
	task.Status = TaskRunning
	task.ProgressCurrent = 1
	updatedAt := time.Now().Add(time.Second)
	s.persistTaskProgress(&task, 1, 0, updatedAt)

	var stored Task
	if err := s.db.Where("id = ?", task.ID).First(&stored).Error; err != nil {
		t.Fatalf("reload task: %v", err)
	}
	if stored.ProgressCurrent != 1 || stored.SuccessCount != 1 || stored.ErrorCount != 0 {
		t.Fatalf("live progress=%d success=%d failed=%d", stored.ProgressCurrent, stored.SuccessCount, stored.ErrorCount)
	}
	if !stored.UpdatedAt.Equal(updatedAt) {
		t.Fatalf("updated_at=%v, want %v", stored.UpdatedAt, updatedAt)
	}
}
