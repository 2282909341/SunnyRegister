package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSunnySubscriptionPlanTypeFromAccessToken(t *testing.T) {
	encode := func(value string) string { return base64.RawURLEncoding.EncodeToString([]byte(value)) }
	for _, plan := range []string{"free", "plus"} {
		t.Run(plan, func(t *testing.T) {
			token := encode(`{"alg":"none"}`) + "." + encode(fmt.Sprintf(`{"https://api.openai.com/auth":{"chatgpt_plan_type":%q}}`, plan)) + ".signature"
			if got := sunnySubscriptionPlanTypeFromAccessToken(token); got != plan {
				t.Fatalf("plan type=%q, want %s", got, plan)
			}
		})
	}
}

func TestSunnySubscriptionMailMarkers(t *testing.T) {
	tests := []struct {
		name    string
		subject string
		body    string
		want    bool
	}{
		{name: "Japanese", subject: "ChatGPT - 新しいプラン", body: "サブスクリプションの管理\nChatGPT Plus Subscription", want: true},
		{name: "Chinese", subject: "ChatGPT - 你的新套餐", body: "管理订阅", want: true},
		{name: "English", subject: "ChatGPT - Your new plan", body: "Manage your subscription", want: true},
		{name: "Korean", subject: "ChatGPT - 새로운 요금제", body: "구독 관리", want: true},
		{name: "Portuguese", subject: "ChatGPT - Seu novo plano", body: "Gerenciar assinatura", want: true},
		{name: "Candidate without confirmation", subject: "ChatGPT - Your new plan", body: "A generic product announcement", want: false},
		{name: "Unrelated mail", subject: "Weekly account update", body: "ChatGPT Plus Subscription", want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			payload := map[string]any{"items": []map[string]any{{"subject": test.subject, "body": test.body}}}
			got, _ := sunnySubscriptionPayloadConfirmed(payload)
			if got != test.want {
				t.Fatalf("confirmed=%v, want %v", got, test.want)
			}
		})
	}
}

func TestSunnySubscriptionTaskUpdatesMailboxAndAccountPlan(t *testing.T) {
	s := newSunnySessionTestServer(t)
	s.db.Model(&SunnyMailbox{}).Where("email = ?", "session@example.com").Update("account_type", "free")
	s.db.Model(&SunnyAccount{}).Where("email = ?", "session@example.com").Update("account_type", "free")
	var session SunnySession
	if err := s.db.Where("email = ?", "session@example.com").First(&session).Error; err != nil {
		t.Fatalf("load session: %v", err)
	}
	previousDetect := sunnyDetectSubscriptionMail
	sunnyDetectSubscriptionMail = func(candidate sunnySubscriptionCandidate, _ string) (bool, string, error) {
		if candidate.Email != session.Email || candidate.ClientID != "client-id" || candidate.RefreshToken != "mailbox-refresh-token" {
			t.Fatalf("unexpected candidate: %#v", candidate)
		}
		return true, "ChatGPT - 新しいプラン", nil
	}
	t.Cleanup(func() { sunnyDetectSubscriptionMail = previousDetect })

	task := s.createTask(sunnySubscriptionTaskType, "sunny", map[string]any{"session_ids": []uint{session.ID}}, 1)
	s.executeSunnySubscriptionTask(&task, map[string]any{"session_ids": []uint{session.ID}})

	var mailbox SunnyMailbox
	var account SunnyAccount
	s.db.Where("email = ?", session.Email).First(&mailbox)
	s.db.Where("email = ?", session.Email).First(&account)
	if mailbox.AccountType != "plus" || account.AccountType != "plus" {
		t.Fatalf("plan was not synchronized: mailbox=%q account=%q", mailbox.AccountType, account.AccountType)
	}
	if err := s.db.First(&task, "id = ?", task.ID).Error; err != nil {
		t.Fatalf("reload task: %v", err)
	}
	result := jsonMap(task.ResultJSON)
	if task.Status != TaskSucceeded || intValue(result["subscribed"], 0) != 1 || intValue(result["failed"], 0) != 0 {
		t.Fatalf("unexpected task result: status=%s result=%#v", task.Status, result)
	}
}

func TestUpdateSunnySubscriptionPlanUsesStableRecordIDs(t *testing.T) {
	s := newSunnySessionTestServer(t)
	var session SunnySession
	if err := s.db.Where("email = ?", "session@example.com").First(&session).Error; err != nil {
		t.Fatalf("load session: %v", err)
	}
	var account SunnyAccount
	if err := s.db.First(&account, session.AccountID).Error; err != nil {
		t.Fatalf("load account: %v", err)
	}
	duplicate := SunnyAccount{MailboxID: account.MailboxID, Email: "rebound@example.com", AccountType: "free", Status: "registered"}
	if err := s.db.Create(&duplicate).Error; err != nil {
		t.Fatalf("create duplicate-shaped account: %v", err)
	}
	candidate := sunnySubscriptionCandidate{
		SessionID: session.ID, AccountID: account.ID, MailboxID: account.MailboxID, Email: "rebound@example.com",
	}
	if err := s.updateSunnySubscriptionPlan(candidate, "plus"); err != nil {
		t.Fatalf("update subscription plan: %v", err)
	}
	var updated, untouched SunnyAccount
	s.db.First(&updated, account.ID)
	s.db.First(&untouched, duplicate.ID)
	if updated.AccountType != "plus" || untouched.AccountType != "free" {
		t.Fatalf("stable account mapping not respected: updated=%q duplicate=%q", updated.AccountType, untouched.AccountType)
	}
	var mailbox SunnyMailbox
	s.db.First(&mailbox, account.MailboxID)
	if mailbox.AccountType != "plus" {
		t.Fatalf("stable mailbox plan=%q, want plus", mailbox.AccountType)
	}
}

func TestReconcileSunnyRebindIdentityDuplicatesKeepsOriginalAndFreshToken(t *testing.T) {
	s := newSunnySessionTestServer(t)
	encode := func(value string) string { return base64.RawURLEncoding.EncodeToString([]byte(value)) }
	oldToken := encode(`{"alg":"none"}`) + "." + encode(`{"exp":100,"https://api.openai.com/auth":{"chatgpt_plan_type":"free"}}`) + ".signature"
	freshToken := encode(`{"alg":"none"}`) + "." + encode(`{"exp":4102444800,"https://api.openai.com/auth":{"chatgpt_plan_type":"plus"}}`) + ".signature"
	var mailbox SunnyMailbox
	if err := s.db.Where("email = ?", "session@example.com").First(&mailbox).Error; err != nil {
		t.Fatalf("load mailbox: %v", err)
	}
	if err := s.db.Model(&mailbox).Updates(map[string]any{"rebind_email": "rebound@example.com", "account_type": "free"}).Error; err != nil {
		t.Fatalf("prepare mailbox: %v", err)
	}
	var original SunnyAccount
	if err := s.db.Where("email = ?", mailbox.Email).First(&original).Error; err != nil {
		t.Fatalf("load original account: %v", err)
	}
	if err := s.db.Model(&original).Updates(map[string]any{"access_token": oldToken, "account_type": "free"}).Error; err != nil {
		t.Fatalf("prepare original account: %v", err)
	}
	if err := s.db.Model(&SunnySession{}).Where("account_id = ?", original.ID).Updates(map[string]any{"access_token": oldToken, "session_json": dumpJSON(map[string]any{"accessToken": oldToken})}).Error; err != nil {
		t.Fatalf("prepare original session: %v", err)
	}
	duplicate := SunnyAccount{MailboxID: mailbox.ID, Email: mailbox.RebindEmail, AccountType: "free", AccessToken: freshToken, Status: "registered"}
	if err := s.db.Create(&duplicate).Error; err != nil {
		t.Fatalf("create duplicate account: %v", err)
	}
	duplicateSession := SunnySession{AccountID: duplicate.ID, Email: mailbox.RebindEmail, AccessToken: freshToken, SessionJSON: dumpJSON(map[string]any{"accessToken": freshToken})}
	if err := s.db.Create(&duplicateSession).Error; err != nil {
		t.Fatalf("create duplicate session: %v", err)
	}

	reconcileSunnyRebindIdentityDuplicates(s.db)

	var accounts []SunnyAccount
	var sessions []SunnySession
	s.db.Order("id asc").Find(&accounts)
	s.db.Order("id asc").Find(&sessions)
	if len(accounts) != 1 || accounts[0].ID != original.ID || accounts[0].AccessToken != freshToken || accounts[0].AccountType != "plus" {
		t.Fatalf("unexpected reconciled accounts: %#v", accounts)
	}
	if len(sessions) != 1 || sessions[0].AccountID != original.ID || sessions[0].Email != mailbox.Email || sessions[0].AccessToken != freshToken {
		t.Fatalf("unexpected reconciled sessions: %#v", sessions)
	}
	var updatedMailbox SunnyMailbox
	s.db.First(&updatedMailbox, mailbox.ID)
	if updatedMailbox.AccountType != "plus" {
		t.Fatalf("mailbox plan=%q, want plus", updatedMailbox.AccountType)
	}
}

func TestSunnySubscriptionTaskPersistsCompletedAccountBeforeBatchFinishes(t *testing.T) {
	s := newSunnySessionTestServer(t)
	if err := s.db.Model(&SunnyMailbox{}).Where("email = ?", "session@example.com").Update("account_type", "free").Error; err != nil {
		t.Fatalf("prepare first mailbox: %v", err)
	}
	if err := s.db.Model(&SunnyAccount{}).Where("email = ?", "session@example.com").Update("account_type", "free").Error; err != nil {
		t.Fatalf("prepare first account: %v", err)
	}
	var first SunnySession
	if err := s.db.Where("email = ?", "session@example.com").First(&first).Error; err != nil {
		t.Fatalf("load first session: %v", err)
	}

	mailbox := SunnyMailbox{Email: "second@example.com", ClientID: "second-client", RefreshToken: "second-refresh", Status: "已注册", AccountType: "free", Enabled: true}
	if err := s.db.Create(&mailbox).Error; err != nil {
		t.Fatalf("create second mailbox: %v", err)
	}
	account := SunnyAccount{MailboxID: mailbox.ID, Email: mailbox.Email, Status: "registered", AccountType: "free"}
	if err := s.db.Create(&account).Error; err != nil {
		t.Fatalf("create second account: %v", err)
	}
	second := SunnySession{AccountID: account.ID, Email: mailbox.Email}
	if err := s.db.Create(&second).Error; err != nil {
		t.Fatalf("create second session: %v", err)
	}

	firstDetected := make(chan struct{})
	releaseSecond := make(chan struct{})
	releasedSecond := false
	defer func() {
		if !releasedSecond {
			close(releaseSecond)
		}
	}()
	previousDetect := sunnyDetectSubscriptionMail
	sunnyDetectSubscriptionMail = func(candidate sunnySubscriptionCandidate, _ string) (bool, string, error) {
		if candidate.SessionID == first.ID {
			close(firstDetected)
			return true, "ChatGPT - Your new plan", nil
		}
		<-releaseSecond
		return false, "", nil
	}
	t.Cleanup(func() { sunnyDetectSubscriptionMail = previousDetect })
	previousProbe := sunnyProbeSubscriptionAT
	sunnyProbeSubscriptionAT = func(_ context.Context, _ *Server, candidate sunnySubscriptionCandidate, _ string) sunnySubscriptionATResult {
		return sunnySubscriptionATResult{SessionID: candidate.SessionID, AccountID: candidate.AccountID, Email: candidate.Email, Status: "valid", PlanType: "free"}
	}
	t.Cleanup(func() { sunnyProbeSubscriptionAT = previousProbe })

	task := s.createTask(sunnySubscriptionTaskType, "sunny", map[string]any{"session_ids": []uint{first.ID, second.ID}}, 2)
	done := make(chan struct{})
	go func() {
		s.executeSunnySubscriptionTask(&task, map[string]any{"session_ids": []uint{first.ID, second.ID}})
		close(done)
	}()

	select {
	case <-firstDetected:
	case <-time.After(time.Second):
		t.Fatal("first subscription detection did not finish")
	}
	deadline := time.Now().Add(time.Second)
	for {
		var updated SunnyAccount
		if err := s.db.Where("email = ?", first.Email).First(&updated).Error; err != nil {
			t.Fatalf("reload first account: %v", err)
		}
		if updated.AccountType == "plus" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("first completed subscription result was not persisted while the batch was running")
		}
		time.Sleep(10 * time.Millisecond)
	}
	var running Task
	if err := s.db.First(&running, "id = ?", task.ID).Error; err != nil {
		t.Fatalf("reload running task: %v", err)
	}
	if terminalTaskStatuses[running.Status] {
		t.Fatalf("task reached terminal state before second account completed: %q", running.Status)
	}

	close(releaseSecond)
	releasedSecond = true
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("subscription batch did not finish after releasing second account")
	}
}

func TestSunnySubscriptionTaskKeepsPlanWhenNoMailMatches(t *testing.T) {
	s := newSunnySessionTestServer(t)
	s.db.Model(&SunnyMailbox{}).Where("email = ?", "session@example.com").Update("account_type", "team")
	s.db.Model(&SunnyAccount{}).Where("email = ?", "session@example.com").Update("account_type", "team")
	var session SunnySession
	s.db.Where("email = ?", "session@example.com").First(&session)
	previousDetect := sunnyDetectSubscriptionMail
	sunnyDetectSubscriptionMail = func(sunnySubscriptionCandidate, string) (bool, string, error) { return false, "", nil }
	t.Cleanup(func() { sunnyDetectSubscriptionMail = previousDetect })
	previousProbe := sunnyProbeSubscriptionAT
	sunnyProbeSubscriptionAT = func(_ context.Context, _ *Server, candidate sunnySubscriptionCandidate, _ string) sunnySubscriptionATResult {
		return sunnySubscriptionATResult{SessionID: candidate.SessionID, AccountID: candidate.AccountID, Email: candidate.Email, Status: "valid", PlanType: "team"}
	}
	t.Cleanup(func() { sunnyProbeSubscriptionAT = previousProbe })

	task := s.createTask(sunnySubscriptionTaskType, "sunny", map[string]any{"session_ids": []uint{session.ID}}, 1)
	s.executeSunnySubscriptionTask(&task, map[string]any{"session_ids": []uint{session.ID}})
	var mailbox SunnyMailbox
	var account SunnyAccount
	s.db.Where("email = ?", session.Email).First(&mailbox)
	s.db.Where("email = ?", session.Email).First(&account)
	if mailbox.AccountType != "team" || account.AccountType != "team" {
		t.Fatalf("unmatched check changed plan: mailbox=%q account=%q", mailbox.AccountType, account.AccountType)
	}
}

func TestSunnySubscriptionTaskUsesAccessTokenFallbackWhenMailDoesNotMatch(t *testing.T) {
	s := newSunnySessionTestServer(t)
	s.db.Model(&SunnyMailbox{}).Where("email = ?", "session@example.com").Update("account_type", "free")
	s.db.Model(&SunnyAccount{}).Where("email = ?", "session@example.com").Update("account_type", "free")
	var session SunnySession
	s.db.Where("email = ?", "session@example.com").First(&session)
	previousDetect := sunnyDetectSubscriptionMail
	sunnyDetectSubscriptionMail = func(sunnySubscriptionCandidate, string) (bool, string, error) { return false, "", nil }
	t.Cleanup(func() { sunnyDetectSubscriptionMail = previousDetect })
	previousProbe := sunnyProbeSubscriptionAT
	sunnyProbeSubscriptionAT = func(_ context.Context, _ *Server, candidate sunnySubscriptionCandidate, _ string) sunnySubscriptionATResult {
		return sunnySubscriptionATResult{SessionID: candidate.SessionID, AccountID: candidate.AccountID, Email: candidate.Email, Status: "valid", PlanType: "plus"}
	}
	t.Cleanup(func() { sunnyProbeSubscriptionAT = previousProbe })

	task := s.createTask(sunnySubscriptionTaskType, "sunny", map[string]any{"session_ids": []uint{session.ID}}, 1)
	s.executeSunnySubscriptionTask(&task, map[string]any{"session_ids": []uint{session.ID}})
	var mailbox SunnyMailbox
	var account SunnyAccount
	s.db.Where("email = ?", session.Email).First(&mailbox)
	s.db.Where("email = ?", session.Email).First(&account)
	if mailbox.AccountType != "plus" || account.AccountType != "plus" {
		t.Fatalf("AT fallback did not synchronize plus plan: mailbox=%q account=%q", mailbox.AccountType, account.AccountType)
	}
	var saved Task
	s.db.First(&saved, "id = ?", task.ID)
	result := jsonMap(saved.ResultJSON)
	if intValue(result["subscribed"], 0) != 1 || intValue(result["not_subscribed"], 0) != 0 || intValue(result["failed"], 0) != 0 {
		t.Fatalf("unexpected AT fallback result: %#v", result)
	}
}

func TestSunnySubscriptionBatchUsesSameMailThenAccessTokenFallback(t *testing.T) {
	s := newSunnySessionTestServer(t)
	var first SunnySession
	if err := s.db.Where("email = ?", "session@example.com").First(&first).Error; err != nil {
		t.Fatalf("load first session: %v", err)
	}
	if err := s.db.Model(&SunnyMailbox{}).Where("email = ?", first.Email).Update("account_type", "free").Error; err != nil {
		t.Fatalf("prepare first mailbox: %v", err)
	}
	if err := s.db.Model(&SunnyAccount{}).Where("email = ?", first.Email).Update("account_type", "free").Error; err != nil {
		t.Fatalf("prepare first account: %v", err)
	}
	mailbox := SunnyMailbox{Email: "second@example.com", ClientID: "second-client", RefreshToken: "second-refresh", Status: "已注册", AccountType: "plus", Enabled: true}
	if err := s.db.Create(&mailbox).Error; err != nil {
		t.Fatalf("create second mailbox: %v", err)
	}
	account := SunnyAccount{MailboxID: mailbox.ID, Email: mailbox.Email, Status: "registered", AccountType: "plus", AccessToken: "second-access-token"}
	if err := s.db.Create(&account).Error; err != nil {
		t.Fatalf("create second account: %v", err)
	}
	second := SunnySession{AccountID: account.ID, Email: mailbox.Email, AccessToken: account.AccessToken}
	if err := s.db.Create(&second).Error; err != nil {
		t.Fatalf("create second session: %v", err)
	}

	previousDetect := sunnyDetectSubscriptionMail
	sunnyDetectSubscriptionMail = func(sunnySubscriptionCandidate, string) (bool, string, error) { return false, "", nil }
	t.Cleanup(func() { sunnyDetectSubscriptionMail = previousDetect })
	previousProbe := sunnyProbeSubscriptionAT
	sunnyProbeSubscriptionAT = func(_ context.Context, _ *Server, candidate sunnySubscriptionCandidate, _ string) sunnySubscriptionATResult {
		plan := "free"
		if candidate.SessionID == first.ID {
			plan = "plus"
		}
		return sunnySubscriptionATResult{SessionID: candidate.SessionID, AccountID: candidate.AccountID, Email: candidate.Email, Status: "valid", PlanType: plan}
	}
	t.Cleanup(func() { sunnyProbeSubscriptionAT = previousProbe })

	task := s.createTask(sunnySubscriptionTaskType, "sunny", map[string]any{"session_ids": []uint{first.ID, second.ID}}, 2)
	s.executeSunnySubscriptionTask(&task, map[string]any{"session_ids": []uint{first.ID, second.ID}})
	var firstAccount, secondAccount SunnyAccount
	s.db.Where("email = ?", first.Email).First(&firstAccount)
	s.db.Where("email = ?", second.Email).First(&secondAccount)
	if firstAccount.AccountType != "plus" || secondAccount.AccountType != "free" {
		t.Fatalf("batch AT plans were not synchronized: first=%q second=%q", firstAccount.AccountType, secondAccount.AccountType)
	}
	var saved Task
	s.db.First(&saved, "id = ?", task.ID)
	result := jsonMap(saved.ResultJSON)
	if intValue(result["requested"], 0) != 2 || intValue(result["subscribed"], 0) != 1 || intValue(result["not_subscribed"], 0) != 1 || intValue(result["failed"], 0) != 0 {
		t.Fatalf("unexpected batch subscription result: %#v", result)
	}
}

func TestSunnySubscriptionCandidatesPreferReboundDomainMailbox(t *testing.T) {
	s := newSunnySessionTestServer(t)
	pickup, _ := domainMailboxPickupCredential("https://mail-api.example", "rebound@example.com", "dmsk_subscription")
	if err := s.db.Model(&SunnyMailbox{}).Where("email = ?", "session@example.com").Updates(map[string]any{
		"rebind_email":       "rebound@example.com",
		"rebind_mailbox_api": pickup,
		"mailbox_type":       "domain",
		"mailbox_channel":    "domain_api",
		"access_key":         pickup,
		"pickup_token_hash":  domainMailboxPickupTokenHash("dmsk_subscription"),
	}).Error; err != nil {
		t.Fatalf("save rebound mailbox: %v", err)
	}
	var session SunnySession
	if err := s.db.Where("email = ?", "session@example.com").First(&session).Error; err != nil {
		t.Fatalf("load session: %v", err)
	}
	candidates, err := s.sunnySubscriptionCandidates([]uint{session.ID})
	if err != nil || len(candidates) != 1 {
		t.Fatalf("subscription candidates: err=%v candidates=%#v", err, candidates)
	}
	candidate := candidates[0]
	if candidate.Email != "session@example.com" || candidate.MailEmail != "rebound@example.com" || candidate.MailboxType != "domain" || candidate.Channel != "domain_api" || candidate.AccessKey != pickup {
		t.Fatalf("rebound mailbox was not selected: %#v", candidate)
	}
}

func TestSunnySubscriptionUsesReboundDomainMailAPI(t *testing.T) {
	requestedEmail := ""
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		requestedEmail = text(body["toEmail"])
		writeJSON(w, http.StatusOK, map[string]any{"items": []any{
			map[string]any{"id": 1, "receivedAt": time.Now().Format(time.RFC3339), "subject": "ChatGPT - Your new plan", "body": "Manage your subscription"},
		}})
	}))
	defer upstream.Close()
	s := newSunnySessionTestServer(t)
	s.sunnySaveConfig(sunnyCfgDomainMailbox, map[string]any{
		"enabled": true, "base_url": upstream.URL, "auth_token": "cloudmail-token", "site_password": "site-password", "domains": []string{"example.com"},
	})
	pickup, _ := domainMailboxPickupCredential("https://mail-api.example", "rebound@example.com", "dmsk_subscription")
	if err := s.db.Model(&SunnyMailbox{}).Where("email = ?", "session@example.com").Updates(map[string]any{
		"rebind_email":       "rebound@example.com",
		"rebind_mailbox_api": pickup,
		"mailbox_type":       "domain",
		"mailbox_channel":    "domain_api",
		"access_key":         pickup,
		"pickup_token_hash":  domainMailboxPickupTokenHash("dmsk_subscription"),
	}).Error; err != nil {
		t.Fatalf("save rebound mailbox: %v", err)
	}
	var session SunnySession
	s.db.Where("email = ?", "session@example.com").First(&session)
	candidates, err := s.sunnySubscriptionCandidates([]uint{session.ID})
	if err != nil || len(candidates) != 1 {
		t.Fatalf("subscription candidates: err=%v candidates=%#v", err, candidates)
	}
	matched, subject, err := s.detectSunnySubscriptionMail(candidates[0], "")
	if err != nil || !matched || subject == "" || requestedEmail != "rebound@example.com" {
		t.Fatalf("rebound subscription lookup failed: matched=%v subject=%q requested=%q err=%v", matched, subject, requestedEmail, err)
	}
}

func TestSunnySubscriptionRouteCreatesLocalTask(t *testing.T) {
	s := newSunnySessionTestServer(t)
	var session SunnySession
	s.db.Where("email = ?", "session@example.com").First(&session)
	req := httptest.NewRequest(http.MethodPost, "/api/sunny/sessions/subscription-check", strings.NewReader(fmt.Sprintf(`{"session_ids":[%d]}`, session.ID)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.sunnySessions(rec, req, []string{"subscription-check"})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("subscription route status=%d body=%s", rec.Code, rec.Body.String())
	}
	var task Task
	if err := s.db.Order("created_at desc").First(&task).Error; err != nil {
		t.Fatalf("load task: %v", err)
	}
	if task.Type != sunnySubscriptionTaskType || !sunnyGoTaskType(task.Type) {
		t.Fatalf("subscription task was not local: type=%q local=%v", task.Type, sunnyGoTaskType(task.Type))
	}
}

func TestFetchXbovoMailSubjectsDoesNotFetchBodies(t *testing.T) {
	rawRequests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/messages":
			fmt.Fprint(w, `{"ok":true,"messages":[{"id":12,"subject":"ChatGPT - Your new plan","preview":"Access has been deactivated"}]}`)
		case "/api/v1/message/raw":
			rawRequests++
			fmt.Fprint(w, `{"ok":true,"text":"Manage subscription"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	previousURL := xbovoAPIBaseURL
	xbovoAPIBaseURL = server.URL
	t.Cleanup(func() { xbovoAPIBaseURL = previousURL })

	subjects, err := fetchXbovoMailSubjects("user@icloud.com", "key", 5, "")
	if err != nil || strings.Join(subjects, "|") != "ChatGPT - Your new plan" {
		t.Fatalf("subjects=%#v err=%v", subjects, err)
	}
	if rawRequests != 0 {
		t.Fatalf("subject-only query fetched %d message bodies", rawRequests)
	}
	evidence, err := fetchXbovoHealthMailEvidence("user@icloud.com", "key", 5, "")
	if err != nil || strings.Join(evidence, "|") != "ChatGPT - Your new plan\nAccess has been deactivated" {
		t.Fatalf("health evidence=%#v err=%v", evidence, err)
	}
}
