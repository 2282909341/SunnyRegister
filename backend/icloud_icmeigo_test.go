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
	generated := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer api_key" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"API_KEY_INVALID"}`))
			return
		}
		switch r.URL.Path {
		case "/api/hme/quota":
			_, _ = w.Write([]byte(`{"data":{"remaining_quota":2,"total_quota":2,"occupied_concurrency":0,"total_concurrency":1}}`))
		case "/api/hme/generate":
			generated++
			_, _ = w.Write([]byte(fmt.Sprintf(`{"data":{"email":"box%d@icloud.com"}}`, generated)))
		case "/api/hme/release-all":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			email, _ := body["email"].(string)
			if email == "" {
				t.Errorf("release-all must target one mailbox, got body=%v", body)
			}
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
	client := icmeigoHTTPClient("")

	email, err := icmeigoGenerate(client, "api_key")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if err := icmeigoReleaseMailbox(client, "api_key", email); err != nil {
		t.Fatalf("release after generate: %v", err)
	}

	// The manual generate above consumed 1 call but not the mock quota, so
	// importIcMeiGoCards still sees remaining_quota=2 and generates twice.
	imported, bad := s.importIcMeiGoCards("api_key", 0)
	if imported != 2 || len(bad) != 0 {
		t.Fatalf("card expansion should import per quota: imported=%d bad=%v", imported, bad)
	}
	if generated != 3 { // 1 manual + 2 from the import loop
		t.Fatalf("generate calls=%d, want 3 (1 manual + 2 per quota)", generated)
	}
	var rows []SunnyMailbox
	if err := s.db.Where("mailbox_channel = ?", "icmeigo").Order("id asc").Find(&rows).Error; err != nil || len(rows) < 2 {
		t.Fatalf("icmeigo mailbox rows=%v err=%v", rows, err)
	}
	if rows[0].AccessKey != "api_key" || !strings.Contains(rows[0].Raw, "----api_key") {
		t.Fatalf("row not sharing the card key: %#v", rows[0])
	}
}