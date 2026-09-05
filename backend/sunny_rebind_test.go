package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSunnyRebindTaskRequiresEnabledDomainMailbox(t *testing.T) {
	s := newSunnySessionTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/sunny/sessions/rebind", strings.NewReader(`{"session_ids":[1]}`))
	rec := httptest.NewRecorder()
	s.handleSunny(rec, req, "sessions/rebind")
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "未启用") {
		t.Fatalf("expected disabled domain mailbox rejection, got %d %s", rec.Code, rec.Body.String())
	}
}

func TestSunnyRebindTaskCreatesWorkerTask(t *testing.T) {
	s := newSunnySessionTestServer(t)
	s.maintenance = map[string]any{"rebind_concurrency": 3}
	s.sunnySaveConfig(sunnyCfgDomainMailbox, mergeConfig(defaultDomainMailboxConfig(), map[string]any{
		"enabled_for_rebinding": true,
		"base_url":              "https://mail.example",
		"auth_token":            "token-1",
		"site_password":         "site-password",
		"pickup_base_url":       "https://sunny.example",
		"domain":                "example.com",
	}))
	req := httptest.NewRequest(http.MethodPost, "/api/sunny/sessions/rebind", strings.NewReader(`{"session_ids":[1],"channel":"domain"}`))
	rec := httptest.NewRecorder()
	s.handleSunny(rec, req, "sessions/rebind")
	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected accepted task, got %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"type":"sunny_rebind"`) {
		t.Fatalf("worker task type missing: %s", rec.Body.String())
	}
	var task Task
	if err := s.db.Where("type = ?", "sunny_rebind").First(&task).Error; err != nil {
		t.Fatalf("load rebind task: %v", err)
	}
	if got := intValue(jsonMap(task.PayloadJSON)["concurrency"], 0); got != 3 {
		t.Fatalf("rebind concurrency = %d, want 3", got)
	}
}

func TestSunnyRebindTaskMailComChannel(t *testing.T) {
	s := newSunnySessionTestServer(t)
	s.sunnySaveConfig(sunnyCfgMailCom, mergeConfig(defaultMailComConfig(), map[string]any{
		"enabled_for_rebinding": true,
		"base_url":              "http://185.114.48.56:8788",
		"accounts": []map[string]any{
			{"email": "master@mail.com", "password": "secret"},
		},
	}))
	req := httptest.NewRequest(http.MethodPost, "/api/sunny/sessions/rebind", strings.NewReader(`{"session_ids":[1],"channel":"mailcom"}`))
	rec := httptest.NewRecorder()
	s.handleSunny(rec, req, "sessions/rebind")
	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected accepted task, got %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"type":"sunny_rebind"`) {
		t.Fatalf("worker task type missing: %s", rec.Body.String())
	}
	var task Task
	if err := s.db.Where("type = ?", "sunny_rebind").First(&task).Error; err != nil {
		t.Fatalf("load rebind task: %v", err)
	}
	if got := text(jsonMap(task.PayloadJSON)["channel"]); got != "mailcom" {
		t.Fatalf("rebind channel = %q, want mailcom", got)
	}
}
