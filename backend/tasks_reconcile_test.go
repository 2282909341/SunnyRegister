package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestReconcilePythonTaskKeepsRunningWhenWorkerHealthIsUnavailable(t *testing.T) {
	s := newTaskEventTestServer(t)
	t.Setenv("PYTHON_WORKER_URL", "http://127.0.0.1:1")
	task := Task{
		ID: "network-blip-task", Type: "sunny_rebind", Status: TaskRunning,
		PayloadJSON: "{}", UpdatedAt: time.Now().Add(-10 * time.Minute),
	}
	if err := s.db.Create(&task).Error; err != nil {
		t.Fatalf("create task: %v", err)
	}

	s.reconcilePythonTaskStatus(&task)
	var got Task
	if err := s.db.First(&got, "id = ?", task.ID).Error; err != nil {
		t.Fatalf("load task: %v", err)
	}
	if got.Status != TaskRunning {
		t.Fatalf("temporary Worker health failure changed task status to %q", got.Status)
	}
}

func TestReconcilePythonTaskAllowsWorkerTaskListingGracePeriod(t *testing.T) {
	worker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"running": []string{}})
	}))
	defer worker.Close()

	s := newTaskEventTestServer(t)
	t.Setenv("PYTHON_WORKER_URL", worker.URL)
	task := Task{
		ID: "worker-start-grace-task", Type: "sunny_add_ls", Status: TaskRunning,
		PayloadJSON: "{}", UpdatedAt: time.Now().Add(-2 * time.Minute),
	}
	if err := s.db.Create(&task).Error; err != nil {
		t.Fatalf("create task: %v", err)
	}

	s.reconcilePythonTaskStatus(&task)
	var got Task
	if err := s.db.First(&got, "id = ?", task.ID).Error; err != nil {
		t.Fatalf("load task: %v", err)
	}
	if got.Status != TaskRunning {
		t.Fatalf("Worker task listing gap changed task status to %q", got.Status)
	}
}
