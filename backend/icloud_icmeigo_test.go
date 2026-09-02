package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestIcMeiGoParseAndFetchMail(t *testing.T) {
	t.Run("parse credentials", func(t *testing.T) {
		parsed, err := parseSunnyMailboxLineForProvider("alias@icloud.com----alias_key", "apple", "icmeigo")
		if err != nil {
			t.Fatalf("parse icmeigo mailbox: %v", err)
		}
		if parsed["email"] != "alias@icloud.com" || parsed["access_key"] != "alias_key" {
			t.Fatalf("unexpected icmeigo parse: %#v", parsed)
		}
	})

	t.Run("invalid line missing key", func(t *testing.T) {
		if _, err := parseSunnyMailboxLineForProvider("alias@icloud.com----", "apple", "icmeigo"); err == nil {
			t.Fatal("expected missing icmeigo key to fail")
		}
	})

	t.Run("fetch with data payload", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost || r.URL.Path != "/api/hme/mail" {
				t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
			}
			if got := r.Header.Get("Authorization"); got != "Bearer alias_key" {
				t.Fatalf("missing Bearer auth header: %q", got)
			}
			body, _ := io.ReadAll(r.Body)
			if !strings.Contains(string(body), "alias@icloud.com") {
				t.Fatalf("request body missing email: %s", body)
			}
			_, _ = w.Write([]byte(`{"data":{"id":101,"subject":"Your code","from":"OpenAI <noreply@example.com>","received_at":"2026-08-01T10:00:00Z","content":"Your verification code is 654321","html_content":""}}`))
		}))
		defer server.Close()
		oldBase := icmeigoAPIBaseURL
		icmeigoAPIBaseURL = server.URL
		defer func() { icmeigoAPIBaseURL = oldBase }()

		payload, err := fetchIcMeiGoLatestMail("alias@icloud.com", "alias_key", 5, "")
		if err != nil {
			t.Fatalf("fetch icmeigo mail: %v", err)
		}
		if payload["mail_protocol"] != "icmeigo_api" {
			t.Fatalf("unexpected protocol: %v", payload["mail_protocol"])
		}
		items, _ := payload["items"].([]map[string]any)
		if len(items) != 1 || items[0]["otp"] != "654321" || items[0]["source"] != "icmeigo" {
			t.Fatalf("unexpected icmeigo latest item: %#v", items)
		}
	})

	t.Run("404 treated as empty", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.NotFound(w, r)
		}))
		defer server.Close()
		oldBase := icmeigoAPIBaseURL
		icmeigoAPIBaseURL = server.URL
		defer func() { icmeigoAPIBaseURL = oldBase }()

		payload, err := fetchIcMeiGoLatestMail("alias@icloud.com", "alias_key", 5, "")
		if err != nil {
			t.Fatalf("404 should be treated as empty: %v", err)
		}
		items, _ := payload["items"].([]map[string]any)
		if len(items) != 0 {
			t.Fatalf("expected zero items for empty mailbox, got %d", len(items))
		}
	})

	t.Run("401 classified as credential invalid", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"API_KEY_INVALID"}`))
		}))
		defer server.Close()
		oldBase := icmeigoAPIBaseURL
		icmeigoAPIBaseURL = server.URL
		defer func() { icmeigoAPIBaseURL = oldBase }()

		_, err := fetchIcMeiGoLatestMail("alias@icloud.com", "bad_key", 5, "")
		if err == nil {
			t.Fatal("expected 401 to fail")
		}
		if mailErr, ok := err.(*outlookMailError); ok {
			if mailErr.Code != "mailbox_credential_invalid" || !mailErr.Terminal {
				t.Fatalf("unexpected error classification: %#v", mailErr)
			}
		}
	})
}

func TestIcMeiGoGenerateAndReleaseFlow(t *testing.T) {
	successes := 0
	generateAllowed := 1
	released := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer api_key" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"API_KEY_INVALID"}`))
			return
		}
		switch r.URL.Path {
		case "/api/hme/quota":
			_, _ = w.Write([]byte(`{"data":{"remaining_quota":2,"total_quota":2,"occupied_concurrency":1,"total_concurrency":1}}`))
		case "/api/hme/generate":
			if successes >= generateAllowed+released {
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte(`{"code":"API_CONCURRENCY_LIMIT","message":"当前并发已满，请释放邮箱或等待释放完成后再试","details":{}}`))
				return
			}
			successes++
			_, _ = w.Write([]byte(fmt.Sprintf(`{"data":{"email":"box%d@icloud.com"}}`, successes)))
		case "/api/hme/release-all":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			email, _ := body["email"].(string)
			if email == "" {
				t.Errorf("release-all must target one mailbox, got body=%v", body)
			}
			released++
			_, _ = w.Write([]byte(`{"data":{"success":1,"failed":0,"pending":0}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	oldBase := icmeigoAPIBaseURL
	icmeigoAPIBaseURL = server.URL
	defer func() { icmeigoAPIBaseURL = oldBase }()

	t.Run("stops gracefully when concurrency is full and no completed mailbox", func(t *testing.T) {
		successes, released = 0, 0
		s := newSunnySessionTestServer(t)
		imported, bad, notes := s.importIcMeiGoCards("api_key", 0)
		if imported != 1 || len(bad) != 0 {
			t.Fatalf("concurrency-full stop should import 1 without errors: imported=%d bad=%v", imported, bad)
		}
		if len(notes) != 1 || !strings.Contains(notes[0], "并发已满") {
			t.Fatalf("expected a concurrency note, got %v", notes)
		}
	})

	t.Run("releases a password+2fa mailbox to free the slot and continues", func(t *testing.T) {
		successes, released = 0, 0
		s := newSunnySessionTestServer(t)
		if err := s.db.Create(&SunnyMailbox{Email: "done@icloud.com", MailboxType: "apple", MailboxChannel: "icmeigo", AccessKey: "api_key", ChatGPTPassword: "pw", TOTPSecret: "totp", Status: "已注册", Enabled: true}).Error; err != nil {
			t.Fatal(err)
		}
		imported, bad, notes := s.importIcMeiGoCards("api_key", 0)
		if imported != 2 || len(bad) != 0 || len(notes) != 0 {
			t.Fatalf("completed mailbox release should let import continue: imported=%d bad=%v notes=%v", imported, bad, notes)
		}
		if released != 1 {
			t.Fatalf("release calls=%d, want 1", released)
		}
		var done SunnyMailbox
		if err := s.db.Where("email = ?", "done@icloud.com").First(&done).Error; err != nil {
			t.Fatal(err)
		}
		if done.Enabled || done.Status != "已释放" {
			t.Fatalf("released mailbox was not marked: enabled=%v status=%q", done.Enabled, done.Status)
		}
	})

	t.Run("skips a released row and releases the next completed mailbox", func(t *testing.T) {
		successes, released = 0, 0
		s := newSunnySessionTestServer(t)
		rows := []SunnyMailbox{
			{Email: "old-released@icloud.com", MailboxType: "apple", MailboxChannel: "icmeigo", AccessKey: "api_key", ChatGPTPassword: "pw", TOTPSecret: "totp", Status: "已释放", Enabled: false},
			{Email: "next-done@icloud.com", MailboxType: "apple", MailboxChannel: "icmeigo", AccessKey: "api_key", ChatGPTPassword: "pw", TOTPSecret: "totp", Status: "已注册", Enabled: true},
		}
		if err := s.db.Create(&rows).Error; err != nil {
			t.Fatal(err)
		}
		if err := s.db.Model(&rows[0]).UpdateColumn("enabled", false).Error; err != nil {
			t.Fatal(err)
		}
		imported, bad, notes := s.importIcMeiGoCards("api_key", 0)
		if imported != 2 || len(bad) != 0 || len(notes) != 0 || released != 1 {
			t.Fatalf("released row shadowed next candidate: imported=%d bad=%v notes=%v released=%d", imported, bad, notes, released)
		}
		var old SunnyMailbox
		if err := s.db.Where("email = ?", "old-released@icloud.com").First(&old).Error; err != nil || old.Enabled || old.Status != "已释放" {
			t.Fatalf("old released row changed: row=%#v err=%v", old, err)
		}
	})

	t.Run("releases a failed mailbox without credentials and continues", func(t *testing.T) {
		successes, released = 0, 0
		s := newSunnySessionTestServer(t)
		failed := SunnyMailbox{Email: "failed@icloud.com", MailboxType: "apple", MailboxChannel: "icmeigo", AccessKey: "api_key", Status: "失败", Enabled: true, LastError: "registration failed"}
		if err := s.db.Create(&failed).Error; err != nil {
			t.Fatal(err)
		}
		if err := s.db.Model(&failed).UpdateColumn("enabled", false).Error; err != nil {
			t.Fatal(err)
		}
		imported, bad, notes := s.importIcMeiGoCards("api_key", 0)
		if imported != 2 || len(bad) != 0 || len(notes) != 0 || released != 1 {
			t.Fatalf("failed mailbox did not free slot: imported=%d bad=%v notes=%v released=%d", imported, bad, notes, released)
		}
		if err := s.db.First(&failed, failed.ID).Error; err != nil || failed.Enabled || failed.Status != "已释放" {
			t.Fatalf("failed mailbox was not marked released: row=%#v err=%v", failed, err)
		}
	})
}

func TestIcMeiGoGenerateErrorClassificationAndUpsertReset(t *testing.T) {
	t.Run("pending release is accepted", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"data":{"success":0,"failed":0,"pending":1}}`))
		}))
		defer server.Close()
		oldBase := icmeigoAPIBaseURL
		icmeigoAPIBaseURL = server.URL
		defer func() { icmeigoAPIBaseURL = oldBase }()

		if err := icmeigoReleaseMailbox(server.Client(), "api_key", "pending@icloud.com"); err != nil {
			t.Fatalf("pending release should be accepted: %v", err)
		}
	})

	t.Run("provider code is not mislabeled as quota exhausted", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"code":"SERVICE_TEMPORARILY_UNAVAILABLE","message":"please retry"}`))
		}))
		defer server.Close()
		oldBase := icmeigoAPIBaseURL
		icmeigoAPIBaseURL = server.URL
		defer func() { icmeigoAPIBaseURL = oldBase }()

		_, err := icmeigoGenerate(server.Client(), "api_key")
		mailErr, ok := err.(*outlookMailError)
		if !ok || mailErr.Code != "mailbox_provider_failed" || strings.Contains(mailErr.UserMessage, "额度") {
			t.Fatalf("unexpected transient error classification: %#v", err)
		}
	})

	t.Run("repeat import clears dirty status", func(t *testing.T) {
		s := newSunnySessionTestServer(t)
		row := SunnyMailbox{Email: "dirty@icloud.com", MailboxType: "apple", MailboxChannel: "icmeigo", AccessKey: "old", Status: "失败", Enabled: false, LastError: "old failure"}
		if err := s.db.Create(&row).Error; err != nil {
			t.Fatal(err)
		}
		if err := s.upsertIcMeiGoMailbox(0, row.Email, "new"); err != nil {
			t.Fatal(err)
		}
		if err := s.db.First(&row, row.ID).Error; err != nil || !row.Enabled || row.Status != "未注册" || row.LastError != "" || row.AccessKey != "new" {
			t.Fatalf("dirty mailbox was not reset: row=%#v err=%v", row, err)
		}
	})
}
