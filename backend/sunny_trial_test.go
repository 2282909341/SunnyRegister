package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSunnyTrialCheckAPIResponses(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s", r.Method)
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		switch body["access_token"] {
		case "eligible-token":
			writeJSON(w, http.StatusOK, map[string]any{"eligible": true, "message": "有试用资格", "query_count": 1})
		case "ineligible-token":
			writeJSON(w, http.StatusOK, map[string]any{"eligible": false, "message": "无试用资格", "query_count": 2})
		default:
			writeJSON(w, http.StatusUnauthorized, map[string]any{"detail": "accessToken 无效或已过期"})
		}
	}))
	defer server.Close()
	previousEndpoint := sunnyTrialCheckEndpoint
	sunnyTrialCheckEndpoint = server.URL
	t.Cleanup(func() { sunnyTrialCheckEndpoint = previousEndpoint })

	tests := []struct {
		name, token       string
		eligible, invalid bool
		wantError         bool
	}{
		{name: "eligible", token: "eligible-token", eligible: true},
		{name: "ineligible", token: "ineligible-token"},
		{name: "invalid", token: "invalid-token", invalid: true, wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			eligible, _, invalid, err := checkSunnyTrialEligibility(context.Background(), test.token)
			if eligible != test.eligible || invalid != test.invalid || (err != nil) != test.wantError {
				t.Fatalf("eligible=%v invalid=%v err=%v", eligible, invalid, err)
			}
		})
	}
}

func TestSunnyTrialConcurrencyDefaultsAndLimits(t *testing.T) {
	s := &Server{maintenance: map[string]any{"trial_concurrency": 4}}
	if got := s.sunnyTrialConcurrency(); got != 4 {
		t.Fatalf("configured trial concurrency = %d, want 4", got)
	}
	s.maintenance["trial_concurrency"] = 99
	if got := s.sunnyTrialConcurrency(); got != 16 {
		t.Fatalf("maximum trial concurrency = %d, want 16", got)
	}
	s.maintenance["trial_concurrency"] = 1
	if got := s.sunnyTrialConcurrency(); got != 1 {
		t.Fatalf("configured trial concurrency = %d, want 1", got)
	}
}

func TestSunnyCommerceCheckRetriesOnceAndMergesPartialResults(t *testing.T) {
	previousCheck := sunnyCheckCommerce
	callCount := 0
	sunnyCheckCommerce = func(context.Context, string) sunnyCommerceProbeResult {
		callCount++
		if callCount == 1 {
			return sunnyCommerceProbeResult{
				Eligibility:    sunnyTrialEligible,
				TrialState:     sunnyTrialEligible,
				TrialMessage:   "eligible",
				CheckoutKind:   sunnyCheckoutUnknown,
				CheckoutError:  "temporary checkout error",
				PaymentMethods: nil,
			}
		}
		return sunnyCommerceProbeResult{
			Eligibility:    sunnyTrialUnknown,
			TrialError:     "temporary trial error",
			CheckoutKind:   "oaics",
			PaymentMethods: []string{"card"},
		}
	}
	t.Cleanup(func() { sunnyCheckCommerce = previousCheck })

	result, retried := checkSunnyCommerceWithRetry(context.Background(), "access-token")
	if !retried || callCount != 2 {
		t.Fatalf("retried=%v calls=%d, want retried once", retried, callCount)
	}
	if result.Eligibility != sunnyTrialEligible || result.CheckoutKind != "oaics" || len(result.PaymentMethods) != 1 {
		t.Fatalf("partial results were not merged: %#v", result)
	}
}

func TestSunnyCommerceCheckDoesNotRetryInvalidToken(t *testing.T) {
	previousCheck := sunnyCheckCommerce
	callCount := 0
	sunnyCheckCommerce = func(context.Context, string) sunnyCommerceProbeResult {
		callCount++
		return sunnyCommerceProbeResult{Eligibility: sunnyTrialUnknown, CheckoutKind: sunnyCheckoutUnknown, InvalidToken: true, TrialError: "expired"}
	}
	t.Cleanup(func() { sunnyCheckCommerce = previousCheck })

	_, retried := checkSunnyCommerceWithRetry(context.Background(), "expired-token")
	if retried || callCount != 1 {
		t.Fatalf("invalid token retried=%v calls=%d, want no retry", retried, callCount)
	}
}

func prepareSunnyTrialAccount(t *testing.T, s *Server) SunnySession {
	t.Helper()
	if err := s.db.Create(&SunnyProxy{Address: "http://jp-trial.example:8080", Country: "JP", PurposeTags: sunnyProxyPurposeCommerce, Status: "enabled", Enabled: true}).Error; err != nil {
		t.Fatalf("prepare trial proxy: %v", err)
	}
	if err := s.db.Model(&SunnyAccount{}).Where("email = ?", "session@example.com").Updates(map[string]any{
		"status": "registered", "account_type": "free", "trial_eligibility": sunnyTrialUnknown,
	}).Error; err != nil {
		t.Fatalf("prepare account: %v", err)
	}
	if err := s.db.Model(&SunnyMailbox{}).Where("email = ?", "session@example.com").Updates(map[string]any{
		"status": "已注册", "account_type": "free", "trial_eligibility": sunnyTrialUnknown,
	}).Error; err != nil {
		t.Fatalf("prepare mailbox: %v", err)
	}
	var session SunnySession
	if err := s.db.Where("email = ?", "session@example.com").First(&session).Error; err != nil {
		t.Fatalf("load session: %v", err)
	}
	return session
}

func TestSunnyTrialTaskPersistsAndFiltersEligibility(t *testing.T) {
	s := newSunnySessionTestServer(t)
	session := prepareSunnyTrialAccount(t, s)
	if filter := normalizeSunnyTrialFilter("unsupported"); filter != "" {
		t.Fatalf("unsupported trial filter = %q", filter)
	}
	unknownRecorder := httptest.NewRecorder()
	unknownRequest := httptest.NewRequest(http.MethodGet, "/api/sunny/sessions?trial_eligibility=unknown", nil)
	s.sunnySessions(unknownRecorder, unknownRequest, nil)
	if unknownRecorder.Code != http.StatusOK || !strings.Contains(unknownRecorder.Body.String(), `"trial_eligibility":"unknown"`) {
		t.Fatalf("unknown filter status=%d body=%s", unknownRecorder.Code, unknownRecorder.Body.String())
	}

	previousCheck := sunnyCheckTrialOnly
	sunnyCheckTrialOnly = func(context.Context, string) sunnyCommerceProbeResult {
		return sunnyCommerceProbeResult{Eligibility: sunnyTrialEligible, TrialState: sunnyTrialEligible, TrialMessage: "该账号有 ChatGPT Plus 0 元试用资格"}
	}
	t.Cleanup(func() { sunnyCheckTrialOnly = previousCheck })

	payload := map[string]any{"session_ids": []uint{session.ID}, "countries": []string{"JP"}}
	task := s.createTask(sunnyTrialTaskType, "sunny", payload, 1)
	s.executeSunnyTrialTask(&task, payload)
	var account SunnyAccount
	var mailbox SunnyMailbox
	s.db.Where("email = ?", session.Email).First(&account)
	s.db.Where("email = ?", session.Email).First(&mailbox)
	if account.TrialEligibility != sunnyTrialEligible || mailbox.TrialEligibility != sunnyTrialEligible || account.TrialCheckedAt == nil || mailbox.TrialCheckedAt == nil {
		t.Fatalf("trial state not synchronized: account=%#v mailbox=%#v", account, mailbox)
	}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/sunny/sessions?trial_eligibility=eligible", nil)
	s.sunnySessions(recorder, request, nil)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"trial_eligibility":"eligible"`) {
		t.Fatalf("eligible filter status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestSunnyTrialTaskDoesNotOverwriteCheckoutOrPaymentData(t *testing.T) {
	s := newSunnySessionTestServer(t)
	session := prepareSunnyTrialAccount(t, s)
	if err := s.db.Model(&SunnyAccount{}).Where("email = ?", session.Email).Updates(map[string]any{
		"checkout_kind": "oaics", "payment_methods_json": `["card","paypal"]`,
	}).Error; err != nil {
		t.Fatal(err)
	}
	previousCheck := sunnyCheckTrialOnly
	sunnyCheckTrialOnly = func(context.Context, string) sunnyCommerceProbeResult {
		return sunnyCommerceProbeResult{Eligibility: sunnyTrialIneligible, TrialState: sunnyTrialIneligible}
	}
	t.Cleanup(func() { sunnyCheckTrialOnly = previousCheck })

	payload := map[string]any{"session_ids": []uint{session.ID}, "countries": []string{"JP"}}
	task := s.createTask(sunnyTrialTaskType, "sunny", payload, 1)
	s.executeSunnyTrialTask(&task, payload)
	var account SunnyAccount
	s.db.Where("email = ?", session.Email).First(&account)
	if account.TrialEligibility != sunnyTrialIneligible || account.CheckoutKind != "oaics" || account.PaymentMethodsJSON != `["card","paypal"]` {
		t.Fatalf("unexpected account state after trial-only check: %#v", account)
	}
}

func TestSunnyTrialInvalidTokenClearsEligibilityAndMarksATInvalid(t *testing.T) {
	s := newSunnySessionTestServer(t)
	session := prepareSunnyTrialAccount(t, s)
	if err := s.db.Model(&SunnyAccount{}).Where("email = ?", session.Email).Update("trial_eligibility", sunnyTrialEligible).Error; err != nil {
		t.Fatal(err)
	}
	previousCheck := sunnyCheckTrialOnly
	sunnyCheckTrialOnly = func(context.Context, string) sunnyCommerceProbeResult {
		return sunnyCommerceProbeResult{Eligibility: sunnyTrialUnknown, TrialError: "accessToken 无效或已过期", InvalidToken: true}
	}
	t.Cleanup(func() { sunnyCheckTrialOnly = previousCheck })

	payload := map[string]any{"session_ids": []uint{session.ID}, "countries": []string{"JP"}}
	task := s.createTask(sunnyTrialTaskType, "sunny", payload, 1)
	s.executeSunnyTrialTask(&task, payload)
	var account SunnyAccount
	s.db.Where("email = ?", session.Email).First(&account)
	s.db.First(&session, session.ID)
	if account.TrialEligibility != sunnyTrialUnknown || session.AccessTokenStatus != "invalid" || !strings.Contains(session.AccessTokenError, "无效或已过期") {
		t.Fatalf("invalid token state account=%#v session=%#v", account, session)
	}
	var renewal Task
	if err := s.db.Where("type = ?", "sunny_refresh_session").First(&renewal).Error; err != nil {
		t.Fatalf("renewal task was not queued: %v", err)
	}
	renewalPayload := jsonMap(renewal.PayloadJSON)
	if ids := uintSlice(renewalPayload["account_ids"]); len(ids) != 1 || ids[0] != session.AccountID {
		t.Fatalf("unexpected renewal payload: %#v", renewalPayload)
	}
	if text(renewalPayload["source"]) != "trial_check" || text(renewalPayload["source_task_id"]) != task.ID {
		t.Fatalf("unexpected renewal source: %#v", renewalPayload)
	}
	result := jsonMap(task.ResultJSON)
	if text(result["renewal_task_id"]) != renewal.ID || intValue(result["renewal_queued"], 0) != 1 {
		t.Fatalf("renewal result missing: %#v", result)
	}
}

func TestSunnyTrialDoesNotQueueDuplicateRenewalForActiveAccount(t *testing.T) {
	s := newSunnySessionTestServer(t)
	session := prepareSunnyTrialAccount(t, s)
	activeRenewal := s.createTask("sunny_refresh_session", "sunny", map[string]any{"account_ids": []uint{session.AccountID}}, 1)
	previousCheck := sunnyCheckTrialOnly
	sunnyCheckTrialOnly = func(context.Context, string) sunnyCommerceProbeResult {
		return sunnyCommerceProbeResult{Eligibility: sunnyTrialUnknown, TrialError: "accessToken 无效或已过期", InvalidToken: true}
	}
	t.Cleanup(func() { sunnyCheckTrialOnly = previousCheck })

	payload := map[string]any{"session_ids": []uint{session.ID}, "countries": []string{"JP"}}
	task := s.createTask(sunnyTrialTaskType, "sunny", payload, 1)
	s.executeSunnyTrialTask(&task, payload)
	result := jsonMap(task.ResultJSON)
	if text(result["renewal_task_id"]) != "" || intValue(result["renewal_queued"], 0) != 0 {
		t.Fatalf("duplicate renewal task was queued: %#v", result)
	}
	var renewals []Task
	if err := s.db.Where("type = ?", "sunny_refresh_session").Find(&renewals).Error; err != nil {
		t.Fatalf("load renewal tasks: %v", err)
	}
	if len(renewals) != 1 || renewals[0].ID != activeRenewal.ID {
		t.Fatalf("unexpected renewal tasks: %#v", renewals)
	}
}

func TestSunnyTrialEligibilityCanBeEditedFromSessionAndMailbox(t *testing.T) {
	s := newSunnySessionTestServer(t)
	session := prepareSunnyTrialAccount(t, s)
	put := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/sunny/sessions/%d", session.ID), strings.NewReader(`{"trial_eligibility":"ineligible"}`))
	put.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	s.sunnySessions(recorder, put, []string{fmt.Sprint(session.ID)})
	if recorder.Code != http.StatusOK {
		t.Fatalf("session update status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var mailbox SunnyMailbox
	s.db.Where("email = ?", session.Email).First(&mailbox)
	if mailbox.TrialEligibility != sunnyTrialIneligible {
		t.Fatalf("mailbox eligibility = %q", mailbox.TrialEligibility)
	}

	mailboxPut := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/sunny/mailboxes/%d", mailbox.ID), strings.NewReader(`{"trial_eligibility":"eligible"}`))
	mailboxPut.Header.Set("Content-Type", "application/json")
	mailboxRecorder := httptest.NewRecorder()
	s.sunnyMailboxes(mailboxRecorder, mailboxPut, []string{fmt.Sprint(mailbox.ID)})
	if mailboxRecorder.Code != http.StatusOK {
		t.Fatalf("mailbox update status=%d body=%s", mailboxRecorder.Code, mailboxRecorder.Body.String())
	}
	var account SunnyAccount
	s.db.Where("email = ?", session.Email).First(&account)
	if account.TrialEligibility != sunnyTrialEligible {
		t.Fatalf("account eligibility = %q", account.TrialEligibility)
	}
}

func TestSunnyMailboxTrialEligibilityFilterUsesLinkedDataAndPaginates(t *testing.T) {
	s := newSunnySessionTestServer(t)
	prepareSunnyTrialAccount(t, s)
	if err := s.db.Model(&SunnyAccount{}).Where("email = ?", "session@example.com").Update("trial_eligibility", sunnyTrialEligible).Error; err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/sunny/mailboxes?summary=true&trial_eligibility=eligible&page=1&page_size=1", nil)
	s.sunnyMailboxes(recorder, request, nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("mailbox filter status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		Items []map[string]any `json:"items"`
		Total int              `json:"total"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode mailbox response: %v", err)
	}
	if response.Total != 1 || len(response.Items) != 1 || text(response.Items[0]["trial_eligibility"]) != sunnyTrialEligible {
		t.Fatalf("unexpected mailbox filter response: %#v", response)
	}
}

func TestSunnyTrialRouteCreatesLocalTask(t *testing.T) {
	s := newSunnySessionTestServer(t)
	session := prepareSunnyTrialAccount(t, s)
	req := httptest.NewRequest(http.MethodPost, "/api/sunny/sessions/trial-check", strings.NewReader(fmt.Sprintf(`{"session_ids":[%d],"countries":["JP"]}`, session.ID)))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	s.sunnySessions(recorder, req, []string{"trial-check"})
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("route status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var task Task
	if err := s.db.Order("created_at desc").First(&task).Error; err != nil || task.Type != sunnyTrialTaskType {
		t.Fatalf("trial task missing: task=%#v err=%v", task, err)
	}
}

func TestSunnyTrialCountryRouteUsesEnabledCommerceCountries(t *testing.T) {
	s := newSunnySessionTestServer(t)
	proxies := []SunnyProxy{
		{Address: "http://commerce-us.example:8080", Country: "US", PurposeTags: "commerce,payment_probe", Status: "enabled", Enabled: true},
		{Address: "http://commerce-jp.example:8080", Country: "JP", PurposeTags: "commerce,payment_probe", Status: "enabled", Enabled: true},
		{Address: "http://register-br.example:8080", Country: "BR", PurposeTags: "register", Status: "enabled", Enabled: true},
	}
	if err := s.db.Create(&proxies).Error; err != nil {
		t.Fatalf("create proxies: %v", err)
	}
	recorder := httptest.NewRecorder()
	s.sunnySessions(recorder, httptest.NewRequest(http.MethodGet, "/api/sunny/sessions/trial-check/countries", nil), []string{"trial-check", "countries"})
	if recorder.Code != http.StatusOK {
		t.Fatalf("country route status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		Countries []string `json:"countries"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode countries: %v", err)
	}
	if strings.Join(response.Countries, ",") != "JP,US" {
		t.Fatalf("unexpected trial countries: %#v", response.Countries)
	}
}

func TestSunnyTrialTaskUsesOnlySelectedCountriesAndMergesHistory(t *testing.T) {
	s := newSunnySessionTestServer(t)
	session := prepareSunnyTrialAccount(t, s)
	if err := s.db.Create(&SunnyProxy{Address: "http://vn-trial.example:8080", Country: "VN", PurposeTags: sunnyProxyPurposeCommerce, Status: "enabled", Enabled: true}).Error; err != nil {
		t.Fatal(err)
	}
	history := `{"JP":"eligible","VN":"eligible"}`
	if err := s.db.Model(&SunnyAccount{}).Where("email = ?", session.Email).Update("trial_country_results_json", history).Error; err != nil {
		t.Fatal(err)
	}
	if err := s.db.Model(&SunnyMailbox{}).Where("email = ?", session.Email).Update("trial_country_results_json", history).Error; err != nil {
		t.Fatal(err)
	}

	previousCheck := sunnyCheckTrialOnly
	calledProxies := []string{}
	sunnyCheckTrialOnly = func(ctx context.Context, _ string) sunnyCommerceProbeResult {
		calledProxies = append(calledProxies, text(ctx.Value(sunnyTrialProxyContextKey{})))
		return sunnyCommerceProbeResult{Eligibility: sunnyTrialIneligible, TrialState: sunnyTrialIneligible, TrialMessage: "ineligible"}
	}
	t.Cleanup(func() { sunnyCheckTrialOnly = previousCheck })

	if _, err := s.createSunnyTrialTask(map[string]any{"session_ids": []uint{session.ID}}); err == nil || !strings.Contains(err.Error(), "至少选择") {
		t.Fatalf("missing countries should be rejected, got %v", err)
	}
	if _, err := s.createSunnyTrialTask(map[string]any{"session_ids": []uint{session.ID}, "countries": []string{"US"}}); err == nil || !strings.Contains(err.Error(), "US") {
		t.Fatalf("unavailable trial country should be rejected, got %v", err)
	}
	missingCountryPayload := map[string]any{"session_ids": []uint{session.ID}}
	missingCountryTask := s.createTask(sunnyTrialTaskType, "sunny", missingCountryPayload, 1)
	s.executeSunnyTrialTask(&missingCountryTask, missingCountryPayload)
	if missingCountryTask.Status != TaskFailed || len(calledProxies) != 0 {
		t.Fatalf("trial executor accepted a task without selected countries: status=%q proxies=%v", missingCountryTask.Status, calledProxies)
	}
	task, err := s.createSunnyTrialTask(map[string]any{"session_ids": []uint{session.ID}, "countries": []any{"VN", "VN"}})
	if err != nil {
		t.Fatal(err)
	}
	payload := jsonMap(task.PayloadJSON)
	if got := strings.Join(stringSlice(payload["countries"]), ","); got != "VN" {
		t.Fatalf("countries payload=%q", got)
	}
	s.executeSunnyTrialTask(&task, payload)
	if got := strings.Join(calledProxies, ","); got != "http://vn-trial.example:8080" {
		t.Fatalf("trial used proxies outside the selected VN group: %q", got)
	}

	var account SunnyAccount
	var mailbox SunnyMailbox
	if err := s.db.Where("email = ?", session.Email).First(&account).Error; err != nil {
		t.Fatal(err)
	}
	if err := s.db.Where("email = ?", session.Email).First(&mailbox).Error; err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string]string{"account": account.TrialCountryResultsJSON, "mailbox": mailbox.TrialCountryResultsJSON} {
		results := sunnyTrialCountryResults(raw, "{}")
		if results["JP"] != sunnyTrialEligible || results["VN"] != sunnyTrialIneligible {
			t.Fatalf("%s country history was not merged selectively: %#v", name, results)
		}
	}
	if account.TrialEligibility != sunnyTrialEligible || mailbox.TrialEligibility != sunnyTrialEligible {
		t.Fatalf("overall eligibility should remain eligible because historical JP is eligible: account=%q mailbox=%q", account.TrialEligibility, mailbox.TrialEligibility)
	}
	result := jsonMap(task.ResultJSON)
	if intValue(result["eligible"], 0) != 1 || intValue(result["ineligible"], 0) != 0 {
		t.Fatalf("task summary did not use merged country eligibility: %#v", result)
	}
}

func TestSunnyTrialTasksSkipSessionsAlreadyBeingChecked(t *testing.T) {
	s := newSunnySessionTestServer(t)
	first := prepareSunnyTrialAccount(t, s)

	mailbox := SunnyMailbox{Email: "second@example.com", Status: "已注册", AccountType: "free", Enabled: true}
	if err := s.db.Create(&mailbox).Error; err != nil {
		t.Fatalf("create second mailbox: %v", err)
	}
	account := SunnyAccount{MailboxID: mailbox.ID, Email: mailbox.Email, Status: "registered", AccountType: "free", AccessToken: "second-token"}
	if err := s.db.Create(&account).Error; err != nil {
		t.Fatalf("create second account: %v", err)
	}
	second := SunnySession{AccountID: account.ID, Email: mailbox.Email, AccessToken: account.AccessToken}
	if err := s.db.Create(&second).Error; err != nil {
		t.Fatalf("create second session: %v", err)
	}

	firstTask, err := s.createSunnyTrialTask(map[string]any{"session_ids": []uint{first.ID}, "countries": []string{"JP"}})
	if err != nil {
		t.Fatalf("create first trial task: %v", err)
	}
	secondTask, err := s.createSunnyTrialTask(map[string]any{"session_ids": []uint{first.ID, second.ID}, "countries": []string{"JP"}})
	if err != nil {
		t.Fatalf("create overlapping trial task: %v", err)
	}
	secondPayload := jsonMap(secondTask.PayloadJSON)
	if ids := uintSlice(secondPayload["skip_session_ids"]); len(ids) != 1 || ids[0] != first.ID {
		t.Fatalf("unexpected skipped session IDs: %#v", secondPayload)
	}

	previousCheck := sunnyCheckTrialOnly
	sunnyCheckTrialOnly = func(context.Context, string) sunnyCommerceProbeResult {
		return sunnyCommerceProbeResult{Eligibility: sunnyTrialEligible, TrialState: sunnyTrialEligible, TrialMessage: "eligible"}
	}
	t.Cleanup(func() { sunnyCheckTrialOnly = previousCheck })
	s.executeSunnyTrialTask(&secondTask, secondPayload)
	result := jsonMap(secondTask.ResultJSON)
	if intValue(result["skipped"], 0) != 1 || intValue(result["eligible"], 0) != 1 {
		t.Fatalf("overlapping trial task did not continue with remaining session: %#v", result)
	}
	if secondTask.Status != TaskSucceeded || firstTask.Status != TaskPending {
		t.Fatalf("unexpected task statuses: first=%q second=%q", firstTask.Status, secondTask.Status)
	}
}

func TestSunnyCommerceWorkerResponse(t *testing.T) {
	worker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/probe-commerce" || r.Method != http.MethodPost {
			t.Fatalf("unexpected worker request: %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer worker-secret" {
			t.Fatalf("authorization = %q", got)
		}
		var requestBody struct {
			PromotionProxyURL string `json:"promotion_proxy_url"`
			CheckoutProxyURL  string `json:"checkout_proxy_url"`
		}
		if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
			t.Fatalf("decode worker request: %v", err)
		}
		if requestBody.PromotionProxyURL != "http://promotion-proxy" || requestBody.CheckoutProxyURL != "http://checkout-proxy" {
			t.Fatalf("unexpected proxy routing: %#v", requestBody)
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"trial":    map[string]any{"state": "eligible", "http": 200, "error": ""},
			"checkout": map[string]any{"kind": "oaics", "payment_methods": []string{"card", "paypal"}, "http": 200, "error": ""},
			"traffic":  map[string]any{"requests": 3, "total_bytes": 4321},
		})
	}))
	defer worker.Close()
	t.Setenv("PYTHON_WORKER_URL", worker.URL)
	t.Setenv("PYTHON_WORKER_TOKEN", "worker-secret")

	result, ok := probeSunnyCommerceViaWorker(context.Background(), "secret-at", "http://promotion-proxy", "http://checkout-proxy")
	if !ok || result.Eligibility != sunnyTrialEligible || result.CheckoutKind != "oaics" {
		t.Fatalf("unexpected result: ok=%v result=%#v", ok, result)
	}
	if got := strings.Join(result.PaymentMethods, ","); got != "card,paypal" {
		t.Fatalf("payment methods = %q", got)
	}
	if result.TrafficBytes != 4321 {
		t.Fatalf("traffic bytes = %d", result.TrafficBytes)
	}
}

func TestSunnyCommerceWorkerUsesBillingContextOverride(t *testing.T) {
	worker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var requestBody struct {
			Country  string `json:"country"`
			Currency string `json:"currency"`
		}
		if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
			t.Fatalf("decode worker request: %v", err)
		}
		if requestBody.Country != "VN" || requestBody.Currency != "VND" {
			t.Fatalf("unexpected billing override: %#v", requestBody)
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"trial":    map[string]any{"state": "eligible", "http": 200},
			"checkout": map[string]any{"kind": "oaics", "payment_methods": []string{"momo"}, "http": 200},
		})
	}))
	defer worker.Close()
	t.Setenv("PYTHON_WORKER_URL", worker.URL)
	ctx := context.WithValue(context.Background(), sunnyCheckoutBillingContextKey{}, sunnyCheckoutBillingOverride{Country: "VN", Currency: "VND"})
	result, ok := probeSunnyCommerceViaWorker(ctx, "secret-at", "http://promotion-proxy", "http://checkout-proxy")
	if !ok || result.CheckoutKind != "oaics" || !strings.Contains(strings.Join(result.PaymentMethods, ","), "momo") {
		t.Fatalf("unexpected MOMO commerce result: ok=%v result=%#v", ok, result)
	}
}

func TestSunnyCommerceUsesWorkerWhenTrafficMeterIsActive(t *testing.T) {
	worker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"trial":    map[string]any{"state": "eligible", "http": 200, "error": ""},
			"checkout": map[string]any{"kind": "oaics", "payment_methods": []string{"card"}, "http": 200, "error": ""},
			"traffic":  map[string]any{"requests": 2, "total_bytes": 7654},
		})
	}))
	defer worker.Close()
	t.Setenv("PYTHON_WORKER_URL", worker.URL)

	meter := &sunnyTrafficMeter{}
	ctx := withSunnyTrafficMeter(context.Background(), meter)
	result := checkSunnyCommerce(ctx, "secret-at", "http://promotion-proxy", "http://checkout-proxy")
	if result.Eligibility != sunnyTrialEligible || result.CheckoutKind != "oaics" {
		t.Fatalf("unexpected commerce result: %#v", result)
	}
	if got := meter.totalBytes(); got != 7654 {
		t.Fatalf("worker traffic was not added to meter: %d", got)
	}
}

func TestSunnyCommerceWorkerPreservesNonJSONChallengeDetail(t *testing.T) {
	worker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"trial":    map[string]any{"state": "", "http": 403, "error": "HTTP 403 returned text/html content"},
			"checkout": map[string]any{"kind": "", "payment_methods": []string{}, "http": 403, "error": "HTTP 403 returned text/html content"},
		})
	}))
	defer worker.Close()
	t.Setenv("PYTHON_WORKER_URL", worker.URL)

	result, ok := probeSunnyCommerceViaWorker(context.Background(), "secret-at", "")
	if !ok || !strings.Contains(result.TrialError, "HTTP 403") || !strings.Contains(result.CheckoutError, "text/html") {
		t.Fatalf("unexpected result: ok=%v result=%#v", ok, result)
	}
}
