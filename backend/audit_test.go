package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func TestReadAuditRequestBodyPreservesOversizedPayload(t *testing.T) {
	s := newAuditTestServer(t)
	payload := `{"lines":"` + strings.Repeat("x", 4*1024*1024) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/sunny/mailboxes/import", strings.NewReader(payload))
	req.ContentLength = -1
	if body := s.readAuditRequestBody(req); len(body) != 0 {
		t.Fatalf("oversized body should not be audited: %#v", body)
	}
	restored, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("read restored request body: %v", err)
	}
	if string(restored) != payload {
		t.Fatalf("request body changed: got %d bytes, want %d", len(restored), len(payload))
	}
}

func newAuditTestServer(t *testing.T) *Server {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:"+filepath.ToSlash(filepath.Join(t.TempDir(), "audit.db"))+"?cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open audit database: %v", err)
	}
	if err := db.AutoMigrate(&AuditLog{}, &AuditSetting{}, &AuditExportJob{}, &Task{}, &SunnyAccount{}, &SunnySession{}, &SunnyMailbox{}); err != nil {
		t.Fatalf("migrate audit database: %v", err)
	}
	if sqlDB, err := db.DB(); err == nil {
		t.Cleanup(func() { _ = sqlDB.Close() })
	}
	return &Server{db: db, adminUser: "admin", sessions: map[string]time.Time{}, loginFailures: map[string]*loginFailure{}, stop: make(chan struct{})}
}

func TestAuditMiddlewareRecordsMutationsAndRedactsSecrets(t *testing.T) {
	s := newAuditTestServer(t)
	handler := s.auditMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, http.StatusOK, map[string]any{"ok": true}) }))
	body := `{"lines":"first@example.com----secret----client----refresh\nsecond@outlook.com----secret----client----refresh","access_token":"eyJsecret.payload.signature"}`
	req := httptest.NewRequest(http.MethodPost, "/api/sunny/mailboxes/import", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("mutation status = %d", rec.Code)
	}
	var item AuditLog
	if err := s.db.First(&item).Error; err != nil {
		t.Fatalf("audit log missing: %v", err)
	}
	if item.Category != "mailbox" || item.Action != "import" || item.Count != 2 {
		t.Fatalf("unexpected audit classification: %#v", item)
	}
	if item.Email != "first@example.com, second@outlook.com" {
		t.Fatalf("mailbox import emails missing from audit record: %q", item.Email)
	}
	if strings.Contains(item.DetailsJSON, "secret") || strings.Contains(item.DetailsJSON, "eyJsecret") {
		t.Fatalf("audit details leaked secrets: %s", item.DetailsJSON)
	}
	var details map[string]any
	if json.Unmarshal([]byte(item.DetailsJSON), &details) != nil || intValue(details["lines_count"], 0) != 2 {
		t.Fatalf("audit import summary missing: %s", item.DetailsJSON)
	}

	getReq := httptest.NewRequest(http.MethodGet, "/api/sunny/mailboxes", nil)
	handler.ServeHTTP(httptest.NewRecorder(), getReq)
	var count int64
	s.db.Model(&AuditLog{}).Count(&count)
	if count != 1 {
		t.Fatalf("read-only request was audited, count=%d", count)
	}
}

func TestAuditMiddlewareClassifiesNewAccountTasksAndLinksTaskID(t *testing.T) {
	s := newAuditTestServer(t)
	accounts := []SunnyAccount{{Email: "First@Example.com"}, {Email: "second@example.com"}}
	if err := s.db.Create(&accounts).Error; err != nil {
		t.Fatalf("create accounts: %v", err)
	}
	handler := s.auditMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusAccepted, map[string]any{
			"id": "task_acquire_rt", "task_id": "task_acquire_rt", "type": "sunny_acquire_rt", "status": TaskPending,
			"progress_detail": map[string]any{"current": 0, "total": 2},
		})
	}))
	req := httptest.NewRequest(http.MethodPost, "/api/sunny/tasks/acquire-rt", strings.NewReader(fmt.Sprintf(`{"account_ids":[%d,%d]}`, accounts[0].ID, accounts[1].ID)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("task submission status = %d", rec.Code)
	}
	var item AuditLog
	if err := s.db.First(&item).Error; err != nil {
		t.Fatalf("audit log missing: %v", err)
	}
	if item.LogType != "task" || item.Category != "account" || item.Action != "acquire_refresh_token" {
		t.Fatalf("unexpected account task classification: %#v", item)
	}
	if item.TaskID != "task_acquire_rt" || item.Count != 2 {
		t.Fatalf("task response metadata missing: %#v", item)
	}
	if item.Email != "First@Example.com, second@example.com" || item.SubjectKey != "first@example.com, second@example.com" {
		t.Fatalf("account emails missing from audit record: %#v", item)
	}
	var matched int64
	applyAuditFilters(s.db.Model(&AuditLog{}), map[string]string{"email": "SECOND@EXAMPLE.COM"}, nil).Count(&matched)
	if matched != 1 {
		t.Fatalf("email filter matched %d rows, want 1", matched)
	}
	if !strings.Contains(item.DetailsJSON, `"response_task_id":"task_acquire_rt"`) {
		t.Fatalf("task id missing from details: %s", item.DetailsJSON)
	}
}

func TestAuditNewFeatureRouteClassification(t *testing.T) {
	tests := []struct {
		path, category, action, entityType string
		logType                            string
	}{
		{"/api/sunny/sessions/health-check", "account", "health_check", "account_health", "task"},
		{"/api/sunny/sessions/subscription-check", "account", "subscription_check", "account_subscription", "task"},
		{"/api/sunny/sessions/trial-check", "account", "trial_check", "account_trial", "task"},
		{"/api/sunny/sessions/checkout-probe", "account", "checkout_probe", "account_checkout", "task"},
		{"/api/sunny/tasks/refresh-session", "account", "refresh_access_token", "account_token", "task"},
		{"/api/sunny/tasks/acquire-rt", "account", "acquire_refresh_token", "account_token", "task"},
		{"/api/sunny/sessions/export", "account", "export", "account", "operation"},
		{"/api/sunny/phones/provider-options", "sms", "refresh", "sms_provider_options", "operation"},
	}
	for _, test := range tests {
		t.Run(test.action, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, test.path, nil)
			meta := auditMetaForRequest(req, map[string]any{"session_ids": []any{1, 2}}, map[string]any{"task_id": "task_new_feature"}, http.StatusAccepted)
			if meta.LogType != test.logType || meta.Category != test.category || meta.Action != test.action || meta.EntityType != test.entityType {
				t.Fatalf("unexpected classification for %s: %#v", test.path, meta)
			}
			if test.logType == "task" && meta.TaskID != "task_new_feature" {
				t.Fatalf("task id not linked for %s: %#v", test.path, meta)
			}
		})
	}
}

func TestAuditResponseCaptureDoesNotTruncateClientResponse(t *testing.T) {
	s := newAuditTestServer(t)
	largeValue := strings.Repeat("x", auditResponseCaptureLimit+1024)
	handler := s.auditMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"value": largeValue})
	}))
	req := httptest.NewRequest(http.MethodPost, "/api/sunny/sessions/export", strings.NewReader(`{"format":"all","session_ids":[1]}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	var response map[string]any
	if json.Unmarshal(rec.Body.Bytes(), &response) != nil || text(response["value"]) != largeValue {
		t.Fatalf("client response was truncated: got %d bytes", rec.Body.Len())
	}
}

func TestAuditMiddlewareRecordsReadOnlyPanicsWithoutAuditingNormalReads(t *testing.T) {
	s := newAuditTestServer(t)
	handler := s.auditMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("read failed") }))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/sunny/sessions", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("panic response status = %d", rec.Code)
	}
	var item AuditLog
	if err := s.db.First(&item).Error; err != nil {
		t.Fatalf("panic audit log missing: %v", err)
	}
	if item.LogType != "system" || item.Action != "panic" || item.Status != "failed" || item.Method != http.MethodGet {
		t.Fatalf("unexpected panic audit log: %#v", item)
	}
}

func TestAuditCompletedScheduledHealthTaskRecordsFullLifecycle(t *testing.T) {
	s := newAuditTestServer(t)
	task := Task{
		ID: "task_health_scheduled", Type: sunnyHealthTaskType, Platform: "sunny", Status: TaskSucceeded,
		PayloadJSON:   dumpJSON(map[string]any{"scheduled": true}),
		ResultJSON:    dumpJSON(map[string]any{"requested": 3, "checked": 2, "alive": 1, "banned": 1, "failed": 1, "skipped": 4, "items": []any{map[string]any{"email": "hidden@example.com"}}}),
		ProgressTotal: 3, SuccessCount: 2, ErrorCount: 1,
	}
	if err := s.db.Create(&task).Error; err != nil {
		t.Fatalf("create scheduled task: %v", err)
	}
	s.auditCompletedTasks()
	var rows []AuditLog
	if err := s.db.Where("task_id = ?", task.ID).Order("id asc").Find(&rows).Error; err != nil {
		t.Fatalf("load task audit logs: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("scheduled terminal task should have start and completion logs, got %d", len(rows))
	}
	if rows[0].LogType != "scheduler" || rows[0].Category != "account" || rows[0].Action != "health_check_started" || rows[0].Status != "running" {
		t.Fatalf("unexpected scheduled start log: %#v", rows[0])
	}
	if rows[1].Action != "health_check_completed" || rows[1].Status != "warning" || rows[1].Count != 3 {
		t.Fatalf("unexpected scheduled completion log: %#v", rows[1])
	}
	if !strings.Contains(rows[1].DetailsJSON, `"banned":1`) || !strings.Contains(rows[1].DetailsJSON, `"skipped":4`) || strings.Contains(rows[1].DetailsJSON, "hidden@example.com") {
		t.Fatalf("health result summary is incomplete or leaked item details: %s", rows[1].DetailsJSON)
	}
}

func TestAuditRetentionCleanup(t *testing.T) {
	s := newAuditTestServer(t)
	now := time.Now()
	if err := s.db.Create(&AuditSetting{ID: 1, RetentionDays: 7, CleanupHour: now.Hour(), Enabled: true}).Error; err != nil {
		t.Fatalf("create audit setting: %v", err)
	}
	s.db.Create(&AuditLog{OccurredAt: now.AddDate(0, 0, -8), Summary: "old"})
	s.db.Create(&AuditLog{OccurredAt: now.AddDate(0, 0, -1), Summary: "recent"})
	// CleanupHour 带 gorm:"default:3" 标签，Create 会丢弃零值字段：用例在
	// 00:00~00:59 运行时 now.Hour()==0，落库值被默认值 3 覆盖，
	// auditRetentionCleanup 因整点不匹配直接返回，断言必然失败。这里用 map
	// 更新显式写回，并在调用前重新取整点，避免零值覆盖与跨整点漂移。
	if err := s.db.Model(&AuditSetting{}).Where("id = ?", 1).Updates(map[string]any{"cleanup_hour": time.Now().Hour()}).Error; err != nil {
		t.Fatalf("pin audit cleanup hour: %v", err)
	}
	s.auditRetentionCleanup()
	var oldCount, recentCount int64
	s.db.Model(&AuditLog{}).Where("summary = ?", "old").Count(&oldCount)
	s.db.Model(&AuditLog{}).Where("summary = ?", "recent").Count(&recentCount)
	if oldCount != 0 || recentCount != 1 {
		t.Fatalf("unexpected retention result old=%d recent=%d", oldCount, recentCount)
	}
}

func TestAuditExportJobCreatesDownload(t *testing.T) {
	s := newAuditTestServer(t)
	t.Setenv("ACCOUNT_MANAGER_DATABASE_URL", filepath.Join(t.TempDir(), "sunnyregister.db"))
	s.db.Create(&AuditLog{OccurredAt: time.Now(), Actor: "admin", LogType: "operation", Category: "mailbox", Action: "update", Status: "success", Summary: "updated mailbox"})
	job := AuditExportJob{ID: "audit_export_test", Status: "queued", Format: "csv", FiltersJSON: "{}", SelectedJSON: "[]", Actor: "admin"}
	s.db.Create(&job)
	s.runAuditExport(job.ID)
	if err := s.db.First(&job, "id = ?", job.ID).Error; err != nil {
		t.Fatalf("reload export job: %v", err)
	}
	if job.Status != "completed" || job.RecordCount != 1 || job.FilePath == "" {
		t.Fatalf("unexpected export result: %#v", job)
	}
	if _, err := os.Stat(job.FilePath); err != nil {
		t.Fatalf("export file missing: %v", err)
	}
}
