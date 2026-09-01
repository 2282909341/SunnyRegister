package main

import (
	"net/http"
	"net/http/httptest"
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

func TestPersistTaskProgressDoesNotOverwriteCancellationStatus(t *testing.T) {
	s := newSunnySessionTestServer(t)
	task := s.createTask(sunnyCheckoutTaskType, "chatgpt", map[string]any{}, 1)
	if err := s.db.Model(&Task{}).Where("id = ?", task.ID).Update("status", TaskCancelRequested).Error; err != nil {
		t.Fatal(err)
	}
	task.ProgressCurrent = 1
	s.persistTaskProgress(&task, 1, 0, time.Now())
	var stored Task
	if err := s.db.Where("id = ?", task.ID).First(&stored).Error; err != nil {
		t.Fatal(err)
	}
	if stored.Status != TaskCancelRequested {
		t.Fatalf("status=%q, want %q", stored.Status, TaskCancelRequested)
	}
	s.finishSunnyCheckoutTask(&task, map[string]any{"requested": 1, "success": 1, "failed": 0, "items": []any{}})
	if err := s.db.Where("id = ?", task.ID).First(&stored).Error; err != nil {
		t.Fatal(err)
	}
	if stored.Status != TaskCancelled {
		t.Fatalf("finish status=%q, want %q", stored.Status, TaskCancelled)
	}
}

func TestSunnyCheckoutStartDoesNotResurrectCancelRequestedTask(t *testing.T) {
	s := newSunnySessionTestServer(t)
	task := s.createTask(sunnyCheckoutTaskType, "chatgpt", map[string]any{}, 1)
	task.Status = TaskClaimed
	if err := s.db.Model(&Task{}).Where("id = ?", task.ID).Update("status", TaskClaimed).Error; err != nil {
		t.Fatal(err)
	}
	// Simulate the cancellation request arriving after dispatch claimed the
	// task but before its executor performed the running transition.
	if err := s.db.Model(&Task{}).Where("id = ?", task.ID).Update("status", TaskCancelRequested).Error; err != nil {
		t.Fatal(err)
	}

	s.executeSunnyCheckoutTask(&task, map[string]any{})

	var stored Task
	if err := s.db.Where("id = ?", task.ID).First(&stored).Error; err != nil {
		t.Fatal(err)
	}
	if stored.Status != TaskCancelled {
		t.Fatalf("status=%q, want %q", stored.Status, TaskCancelled)
	}
	if stored.Status == TaskRunning {
		t.Fatal("cancelled checkout task must not be resurrected as running")
	}
}

func TestClaimPendingTaskDoesNotOverwriteCancellation(t *testing.T) {
	s := newSunnySessionTestServer(t)
	task := s.createTask(sunnyCheckoutTaskType, "chatgpt", map[string]any{}, 1)
	// Keep a stale pending object like the one returned by dispatchPending, then
	// simulate the cancel request winning the race before the conditional claim.
	if err := s.db.Model(&Task{}).Where("id = ?", task.ID).Update("status", TaskCancelled).Error; err != nil {
		t.Fatal(err)
	}
	if s.claimPendingTask(&task) {
		t.Fatal("cancelled task must not be claimed")
	}

	var stored Task
	if err := s.db.Where("id = ?", task.ID).First(&stored).Error; err != nil {
		t.Fatal(err)
	}
	if stored.Status != TaskCancelled {
		t.Fatalf("status=%q, want %q", stored.Status, TaskCancelled)
	}
}

func TestCancelPendingSunnyCheckoutReleasesTemporaryCredentials(t *testing.T) {
	s := newSunnySessionTestServer(t)
	s.checkoutCreds = map[string]checkoutSecret{
		"credential-test": {Tokens: map[string]string{"0": "secret-at"}},
	}
	task := s.createTask(sunnyCheckoutTaskType, "chatgpt", map[string]any{"credential_id": "credential-test"}, 1)
	recorder := httptest.NewRecorder()
	s.handleTasks(recorder, httptest.NewRequest(http.MethodPost, "/tasks/"+task.ID+"/cancel", nil), "/"+task.ID+"/cancel")
	if recorder.Code != http.StatusOK {
		t.Fatalf("cancel status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	s.checkoutMu.Lock()
	_, retained := s.checkoutCreds["credential-test"]
	s.checkoutMu.Unlock()
	if retained {
		t.Fatal("cancelled pending checkout retained temporary credentials")
	}
}

func TestTransitionTaskCancellationDoesNotOverwriteCompletedTaskFromStaleSnapshot(t *testing.T) {
	s := newSunnySessionTestServer(t)
	task := s.createTask(sunnyCheckoutTaskType, "chatgpt", map[string]any{"credential_id": "credential-race"}, 1)
	s.checkoutCreds = map[string]checkoutSecret{
		"credential-race": {Tokens: map[string]string{"0": "secret-at"}},
	}
	// Keep a running object as the cancellation handler's stale snapshot,
	// then let the executor complete before the handler writes anything.
	stale := task
	stale.Status = TaskRunning
	completedAt := time.Now()
	if err := s.db.Model(&Task{}).Where("id = ?", task.ID).Updates(map[string]any{
		"status":      TaskSucceeded,
		"result_json": `{"completed":true}`,
		"finished_at": completedAt,
		"updated_at":  completedAt,
	}).Error; err != nil {
		t.Fatalf("complete task: %v", err)
	}
	transitioned, err := s.transitionTaskCancellation(&stale, "用户已停止任务")
	if err != nil {
		t.Fatalf("cancel transition: %v", err)
	}
	if transitioned {
		t.Fatal("cancellation must not transition an already completed task")
	}
	if stale.Status != TaskSucceeded || stale.ResultJSON != `{"completed":true}` {
		t.Fatalf("stale task was overwritten: status=%q result=%q", stale.Status, stale.ResultJSON)
	}
	s.checkoutMu.Lock()
	_, retained := s.checkoutCreds["credential-race"]
	s.checkoutMu.Unlock()
	if !retained {
		t.Fatal("terminal-race cancellation must not release a credential still owned by the executor")
	}
}

func TestTransitionTaskCancellationClaimsStalePendingSnapshotWithoutReleasingCredential(t *testing.T) {
	s := newSunnySessionTestServer(t)
	s.checkoutCreds = map[string]checkoutSecret{
		"credential-claimed-race": {Tokens: map[string]string{"0": "secret-at"}},
	}
	task := s.createTask(sunnyCheckoutTaskType, "chatgpt", map[string]any{"credential_id": "credential-claimed-race"}, 1)
	stale := task
	if err := s.db.Model(&Task{}).Where("id = ?", task.ID).Update("status", TaskClaimed).Error; err != nil {
		t.Fatalf("claim task: %v", err)
	}
	transitioned, err := s.transitionTaskCancellation(&stale, "用户已停止任务")
	if err != nil {
		t.Fatalf("cancel transition: %v", err)
	}
	if !transitioned || stale.Status != TaskCancelRequested {
		t.Fatalf("claimed task cancellation status=%q transitioned=%v", stale.Status, transitioned)
	}
	s.checkoutMu.Lock()
	_, retained := s.checkoutCreds["credential-claimed-race"]
	s.checkoutMu.Unlock()
	if !retained {
		t.Fatal("claimed checkout credential was released before its executor finished")
	}
}
