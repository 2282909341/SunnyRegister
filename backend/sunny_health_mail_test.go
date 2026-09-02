package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestFetchOutlookMailSubjectsUsesGraphSubjectAndPreview(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"access_token":"graph-token"}`)
		case "/messages":
			if got := r.Header.Get("Authorization"); got != "Bearer graph-token" {
				t.Fatalf("unexpected authorization header: %s", got)
			}
			if got := r.URL.Query().Get("$select"); got != "subject,bodyPreview" {
				t.Fatalf("health query must request subject and body preview, got %q", got)
			}
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"value":[{"subject":"Welcome","bodyPreview":"Weekly update"},{"subject":"Account notice [C-ABC123]","bodyPreview":"Access deactivated"}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	originalGraphEndpoints := hotmailGraphTokenEndpoints
	originalIMAPEndpoints := hotmailTokenEndpoints
	originalMessagesURL := outlookGraphMessagesURL
	hotmailGraphTokenEndpoints = []hotmailTokenEndpoint{{Name: "GRAPH-TEST", URL: server.URL + "/token"}}
	hotmailTokenEndpoints = nil
	outlookGraphMessagesURL = server.URL + "/messages"
	t.Cleanup(func() {
		hotmailGraphTokenEndpoints = originalGraphEndpoints
		hotmailTokenEndpoints = originalIMAPEndpoints
		outlookGraphMessagesURL = originalMessagesURL
	})

	subjects, err := fetchOutlookMailSubjects("user@outlook.com", "client-id", "refresh-token", 5, "")
	if err != nil {
		t.Fatalf("Graph subject query failed: %v", err)
	}
	if got := strings.Join(subjects, "|"); got != "Welcome\nWeekly update|Account notice [C-ABC123]\nAccess deactivated" {
		t.Fatalf("unexpected subjects: %s", got)
	}
}

func TestFetchMailSubjectsViaGraphRespectsProxyValidation(t *testing.T) {
	_, err := fetchMailSubjectsViaGraph("token", 5, "://bad-proxy")
	if err == nil || !strings.Contains(err.Error(), "invalid Graph proxy URL") {
		t.Fatalf("expected proxy validation error, got %v", err)
	}
	if _, parseErr := url.Parse("://bad-proxy"); parseErr == nil {
		t.Fatal("test proxy must remain invalid")
	}
}

func TestFetchOutlookMailSubjectsFallsBackToIMAP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"access_token":"mail-token"}`)
	}))
	defer server.Close()

	originalGraphEndpoints := hotmailGraphTokenEndpoints
	originalIMAPEndpoints := hotmailTokenEndpoints
	originalGraphFetch := sunnyFetchMailSubjectsViaGraph
	originalIMAPFetch := sunnyFetchMailHeadersViaIMAP
	hotmailGraphTokenEndpoints = []hotmailTokenEndpoint{{Name: "GRAPH-TEST", URL: server.URL}}
	hotmailTokenEndpoints = []hotmailTokenEndpoint{{Name: "IMAP-TEST", URL: server.URL}}
	sunnyFetchMailSubjectsViaGraph = func(string, int, string) ([]string, error) {
		return nil, fmt.Errorf("Graph permission unavailable")
	}
	sunnyFetchMailHeadersViaIMAP = func(email, token string, limit int, proxy string) ([]string, error) {
		if email != "user@outlook.com" || token != "mail-token" || limit != 5 {
			t.Fatalf("unexpected IMAP fallback arguments: %s %s %d", email, token, limit)
		}
		return []string{"IMAP subject"}, nil
	}
	t.Cleanup(func() {
		hotmailGraphTokenEndpoints = originalGraphEndpoints
		hotmailTokenEndpoints = originalIMAPEndpoints
		sunnyFetchMailSubjectsViaGraph = originalGraphFetch
		sunnyFetchMailHeadersViaIMAP = originalIMAPFetch
	})

	subjects, err := fetchOutlookMailSubjects("user@outlook.com", "client-id", "refresh-token", 5, "")
	if err != nil {
		t.Fatalf("IMAP fallback failed: %v", err)
	}
	if len(subjects) != 1 || subjects[0] != "IMAP subject" {
		t.Fatalf("unexpected IMAP subjects: %#v", subjects)
	}
}

func TestSunnyHealthCheckConcurrencyDefaultsAndBounds(t *testing.T) {
	server := &Server{maintenance: map[string]any{"health_concurrency": 4}}
	if got := server.sunnyHealthCheckConcurrency(); got != 4 {
		t.Fatalf("configured concurrency = %d, want 4", got)
	}
	server.maintenance["health_concurrency"] = 99
	if got := server.sunnyHealthCheckConcurrency(); got != 16 {
		t.Fatalf("max concurrency = %d, want 16", got)
	}
}
