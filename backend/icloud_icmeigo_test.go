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
	remainingQuota := 2
	totalConcurrency := 1
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer api_key" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"API_KEY_INVALID"}`))
			return
		}
		switch r.URL.Path {
		case "/api/hme/quota":
			_, _ = w.Write([]byte(fmt.Sprintf(`{"data":{"remaining_quota":%d,"total_quota":%d,"occupied_concurrency":1,"total_concurrency":%d}}`, remainingQuota, remainingQuota, totalConcurrency)))
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
		remainingQuota, totalConcurrency = 2, 1
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
		remainingQuota, totalConcurrency = 2, 1
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

	t.Run("uses the card concurrency as the release limit", func(t *testing.T) {
		successes, released = 0, 0
		remainingQuota, totalConcurrency = 5, 5
		s := newSunnySessionTestServer(t)
		for i := 1; i <= 4; i++ {
			mailbox := SunnyMailbox{Email: fmt.Sprintf("done%d@icloud.com", i), MailboxType: "apple", MailboxChannel: "icmeigo", AccessKey: "api_key", ChatGPTPassword: "pw", TOTPSecret: "totp", Status: "已注册", Enabled: true}
			if err := s.db.Create(&mailbox).Error; err != nil {
				t.Fatal(err)
			}
		}
		imported, bad, notes := s.importIcMeiGoCards("api_key", 0)
		if imported != 5 || released != 4 || len(bad) != 0 || len(notes) != 0 {
			t.Fatalf("concurrency-aware release failed: imported=%d released=%d bad=%v notes=%v", imported, released, bad, notes)
		}
	})
}

func TestIcMeiGoRegistrationRequiresLoginSecret(t *testing.T) {
	s := newSunnySessionTestServer(t)
	mailbox := SunnyMailbox{Email: "icmeigo-register@icloud.com", MailboxType: "apple", MailboxChannel: "icmeigo", AccessKey: "api_key", Status: "未注册", Enabled: true}
	if err := s.db.Create(&mailbox).Error; err != nil {
		t.Fatal(err)
	}
	body := map[string]any{"mailbox_ids": []any{float64(mailbox.ID)}, "setup_login_secret": false}
	s.sunnyRequireIcMeigoLoginSecret(body)
	if body["setup_login_secret"] != true {
		t.Fatal("ic.meigo registration must force password and 2FA setup")
	}
}

func TestIcMeiGoTaskAutomaticallyRecognizesAllCardsAndQuota(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/hme/quota" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"data":{"remaining_quota":9,"total_quota":10,"total_concurrency":1}}`))
	}))
	defer server.Close()
	oldBase := icmeigoAPIBaseURL
	icmeigoAPIBaseURL = server.URL
	defer func() { icmeigoAPIBaseURL = oldBase }()

	s := newSunnySessionTestServer(t)
	for i, key := range []string{"api_card_a", "api_card_b"} {
		mailbox := SunnyMailbox{Email: fmt.Sprintf("card%d@icloud.com", i+1), GroupID: 1, MailboxType: "apple", MailboxChannel: "icmeigo", AccessKey: key, Status: "未注册", Enabled: true}
		if err := s.db.Create(&mailbox).Error; err != nil {
			t.Fatal(err)
		}
	}
	body := map[string]any{"identity": "icmeigo", "setup_login_secret": false}
	if err := s.sunnyPrepareIcMeigoTask(body); err != nil {
		t.Fatal(err)
	}
	if got := intValue(body["count"], 0); got != 20 {
		t.Fatalf("auto-recognized account count=%d, want 20", got)
	}
	if len(uintSlice(body["mailbox_ids"])) != 2 || !boolValue(body["icmeigo_auto"], false) || !boolValue(body["setup_login_secret"], false) {
		t.Fatalf("unexpected prepared task: %#v", body)
	}

	recorder := httptest.NewRecorder()
	s.sunnyIcMeigoSummary(recorder)
	var summary map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &summary); err != nil {
		t.Fatal(err)
	}
	if intValue(summary["cards"], 0) != 2 || intValue(summary["total_accounts"], 0) != 20 {
		t.Fatalf("unexpected summary: %#v", summary)
	}
	if strings.Contains(recorder.Body.String(), "api_card_") {
		t.Fatal("summary must not expose card secrets")
	}
}

func TestIcMeiGoCardCanBeRemovedWithoutDeletingHistory(t *testing.T) {
	releases := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/hme/quota":
			_, _ = w.Write([]byte(`{"data":{"remaining_quota":8,"total_quota":10,"total_concurrency":2}}`))
		case "/api/hme/release-all":
			releases++
			_, _ = w.Write([]byte(`{"data":{"success":1,"failed":0,"pending":0}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	oldBase := icmeigoAPIBaseURL
	icmeigoAPIBaseURL = server.URL
	defer func() { icmeigoAPIBaseURL = oldBase }()

	s := newSunnySessionTestServer(t)
	for i := 1; i <= 2; i++ {
		mailbox := SunnyMailbox{Email: fmt.Sprintf("failed%d@icloud.com", i), MailboxType: "apple", MailboxChannel: "icmeigo", AccessKey: "api_card_remove", Status: "失败", Enabled: true}
		if err := s.db.Create(&mailbox).Error; err != nil {
			t.Fatal(err)
		}
	}

	summaryRecorder := httptest.NewRecorder()
	s.sunnyIcMeigoSummary(summaryRecorder)
	var summary map[string]any
	if err := json.Unmarshal(summaryRecorder.Body.Bytes(), &summary); err != nil {
		t.Fatal(err)
	}
	items, _ := summary["card_items"].([]any)
	if len(items) != 1 || strings.Contains(summaryRecorder.Body.String(), "api_card_remove") {
		t.Fatalf("card manager summary is invalid or leaked the key: %s", summaryRecorder.Body.String())
	}

	recorder := httptest.NewRecorder()
	s.handleSunny(recorder, httptest.NewRequest(http.MethodDelete, "/api/sunny/icmeigo/cards/"+sunnyIcMeigoCardID("api_card_remove"), nil), "icmeigo/cards/"+sunnyIcMeigoCardID("api_card_remove"))
	if recorder.Code != http.StatusOK || releases != 2 {
		t.Fatalf("remove card failed: status=%d releases=%d body=%s", recorder.Code, releases, recorder.Body.String())
	}
	var rows []SunnyMailbox
	if err := s.db.Where("mailbox_channel = ?", "icmeigo").Order("id asc").Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("history rows=%d, want 2", len(rows))
	}
	for _, row := range rows {
		if row.Enabled || row.Status != "已释放" {
			t.Fatalf("card row not removed from scheduling: enabled=%v status=%q", row.Enabled, row.Status)
		}
	}
}

func TestIcMeiGoProviderResponses(t *testing.T) {
	t.Run("pending release is accepted", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"data":{"success":0,"failed":0,"pending":1}}`))
		}))
		defer server.Close()
		oldBase := icmeigoAPIBaseURL
		icmeigoAPIBaseURL = server.URL
		defer func() { icmeigoAPIBaseURL = oldBase }()
		if err := icmeigoReleaseMailbox(server.Client(), "api_key", "pending@icloud.com"); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("temporary provider error is not quota exhaustion", func(t *testing.T) {
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
		if !ok || mailErr.Code != "mailbox_provider_failed" {
			t.Fatalf("unexpected error: %#v", err)
		}
	})
}
