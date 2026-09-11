package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type sunnyPaymentRoundTripFunc func(*http.Request) (*http.Response, error)

func (fn sunnyPaymentRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func TestSunnyPaymentProbeStopsAfterCancellation(t *testing.T) {
	s := newSunnySessionTestServer(t)
	var session SunnySession
	if err := s.db.Where("email = ?", "session@example.com").First(&session).Error; err != nil {
		t.Fatal(err)
	}
	if err := s.db.Create(&SunnyProxy{Address: "http://jp.example:8080", Country: "JP", PurposeTags: sunnyProxyPurposePayment, Status: "enabled", Enabled: true}).Error; err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	previousProbe := sunnyProbePaymentMethods
	sunnyProbePaymentMethods = func(ctx context.Context, _, _, _, _ string) sunnyPaymentProbeResponse {
		select {
		case <-started:
		default:
			close(started)
		}
		<-ctx.Done()
		return sunnyPaymentProbeResponse{Error: ctx.Err().Error()}
	}
	t.Cleanup(func() { sunnyProbePaymentMethods = previousProbe })

	task, err := s.createSunnyPaymentProbeTask(map[string]any{"session_ids": []uint{session.ID}, "countries": []string{"JP"}})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		s.executeSunnyPaymentProbeTask(&task, jsonMap(task.PayloadJSON))
		close(done)
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("payment probe did not start")
	}
	recorder := httptest.NewRecorder()
	s.handleTasks(recorder, httptest.NewRequest(http.MethodPost, "/tasks/"+task.ID+"/cancel", nil), "/"+task.ID+"/cancel")
	if recorder.Code != http.StatusOK {
		t.Fatalf("cancel endpoint status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("payment probe did not stop after cancellation")
	}
	var stored Task
	if err := s.db.First(&stored, "id = ?", task.ID).Error; err != nil {
		t.Fatal(err)
	}
	if stored.Status != TaskCancelled || !strings.Contains(stored.Error, "停止支付探测") {
		t.Fatalf("cancelled task status=%q error=%q", stored.Status, stored.Error)
	}
}

func TestSunnyPaymentMethodNormalizationAndFilter(t *testing.T) {
	methods := normalizeSunnyPaymentMethods([]string{"cpmt_paypal", "credit-card", "KakaoPay", "paypal", "iDEAL", "go-pay", "przelewy24", "mbway", "bank_transfer_x"})
	if got := strings.Join(methods, ","); got != "paypal,card,gopay,kakao_pay,ideal,p24,mb_way,bank_transfer_x" {
		t.Fatalf("methods=%q", got)
	}
	if !sunnyHasAllPaymentMethods(methods, []string{"paypal", "card"}) {
		t.Fatal("paypal + card should match")
	}
	if sunnyHasAllPaymentMethods(methods, []string{"paypal", "upi"}) {
		t.Fatal("paypal + upi should not match")
	}
}

func TestSunnyPaymentProbeSupportsIndonesiaCurrencyAndDynamicMethods(t *testing.T) {
	expected := map[string]string{
		"SG": "SGD", "MY": "MYR", "TH": "THB", "IN": "INR", "JP": "JPY",
		"BR": "BRL", "NL": "EUR", "PL": "PLN", "PT": "EUR", "ID": "IDR",
	}
	for country, currency := range expected {
		if got := checkoutCountryCurrency[country]; got != currency {
			t.Fatalf("%s currency=%q, want %q", country, got, currency)
		}
	}
	if got := strings.Join(normalizeSunnyPaymentMethods([]string{"cpmt_gopay", "future_wallet_v2"}), ","); got != "gopay,future_wallet_v2" {
		t.Fatalf("dynamic methods=%q", got)
	}
}

func TestSunnyPaymentProbeUsesPolishZloty(t *testing.T) {
	previousProbe := sunnyProbePaymentMethods
	var probedCountry, probedCurrency string
	sunnyProbePaymentMethods = func(_ context.Context, _, country, currency, _ string) sunnyPaymentProbeResponse {
		probedCountry, probedCurrency = country, currency
		return sunnyPaymentProbeResponse{Methods: []string{"card"}, HTTP: http.StatusOK}
	}
	t.Cleanup(func() { sunnyProbePaymentMethods = previousProbe })

	result := (&Server{}).probeSunnyPaymentCountry(
		sunnyPaymentProbeCandidate{AccessToken: "token"},
		"PL",
		[]SunnyProxy{{ID: 1, Address: "http://pl.example:8080"}},
	)
	if result.Error != "" || probedCountry != "PL" || probedCurrency != "PLN" {
		t.Fatalf("PL probe country=%q currency=%q result=%#v", probedCountry, probedCurrency, result)
	}
}

func TestSunnyPaymentProbeWorkerReceivesTrialPromotion(t *testing.T) {
	receivedPromotion := false
	worker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var requestBody struct {
			UseTrialPromotion bool `json:"use_trial_promotion"`
		}
		if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
			t.Fatalf("decode worker request: %v", err)
		}
		receivedPromotion = requestBody.UseTrialPromotion
		writeJSON(w, http.StatusOK, map[string]any{
			"checkout": map[string]any{"kind": "oaics", "payment_methods": []string{"card"}, "http": 200},
		})
	}))
	defer worker.Close()
	t.Setenv("PYTHON_WORKER_URL", worker.URL)

	result, ok := probeSunnyPaymentMethodsViaWorker(context.Background(), "token", "JP", "JPY", "http://jp-proxy", true)
	if !ok || result.Error != "" || !receivedPromotion {
		t.Fatalf("worker promotion request failed: ok=%v received=%v result=%#v", ok, receivedPromotion, result)
	}
}

func TestSunnyPaymentProbeFallbackCheckoutCarriesTrialPromotion(t *testing.T) {
	receivedPromotion := map[string]any{}
	client := &http.Client{Transport: sunnyPaymentRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		var requestBody map[string]any
		if err := json.NewDecoder(request.Body).Decode(&requestBody); err != nil {
			t.Fatalf("decode checkout request: %v", err)
		}
		receivedPromotion, _ = requestBody["promo_campaign"].(map[string]any)
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(bytes.NewBufferString(`{"checkout_session_id":"oaics_test","payment_method_types":["card"]}`)),
			Request:    request,
		}, nil
	})}

	kind, methods, invalid, err := probeSunnyCheckoutForCountryWithPromotion(context.Background(), client, "token", "JP", "JPY", true)
	if err != nil || invalid || kind != "oaics" || strings.Join(methods, ",") != "card" {
		t.Fatalf("unexpected promoted checkout result: kind=%q methods=%v invalid=%v err=%v", kind, methods, invalid, err)
	}
	if text(receivedPromotion["promo_campaign_id"]) != "plus-1-month-free" || !boolValue(receivedPromotion["is_coupon_from_query_param"], false) {
		t.Fatalf("promotion payload=%#v", receivedPromotion)
	}
}

func TestSunnyPaymentProbeTaskUnionsCountriesAndPersistsImmediately(t *testing.T) {
	s := newSunnySessionTestServer(t)
	var session SunnySession
	if err := s.db.Where("email = ?", "session@example.com").First(&session).Error; err != nil {
		t.Fatal(err)
	}
	proxies := []SunnyProxy{
		{Address: "http://jp.example:8080", Country: "JP", PurposeTags: sunnyProxyPurposePayment, Status: "enabled", Enabled: true, LastCheckOK: true},
		{Address: "http://ph.example:8080", Country: "PH", PurposeTags: sunnyProxyPurposePayment, Status: "enabled", Enabled: true, LastCheckOK: true},
	}
	if err := s.db.Create(&proxies).Error; err != nil {
		t.Fatal(err)
	}
	if err := s.db.Model(&SunnyAccount{}).Where("email = ?", session.Email).Updates(map[string]any{
		"payment_probe_results_json": `{"JP":{"methods":["paypal"]},"PH":{"methods":["old_wallet"]}}`,
		"payment_probe_methods_json": `["paypal","old_wallet"]`,
	}).Error; err != nil {
		t.Fatal(err)
	}
	previousProbe := sunnyProbePaymentMethods
	sunnyProbePaymentMethods = func(_ context.Context, token, country, currency, proxyURL string) sunnyPaymentProbeResponse {
		if token == "" || currency == "" || proxyURL == "" {
			return sunnyPaymentProbeResponse{Error: "missing routing data"}
		}
		if country == "JP" {
			return sunnyPaymentProbeResponse{Methods: []string{"paypal", "card", "link"}, HTTP: http.StatusOK}
		}
		return sunnyPaymentProbeResponse{Methods: []string{"card", "gcash"}, HTTP: http.StatusOK}
	}
	t.Cleanup(func() { sunnyProbePaymentMethods = previousProbe })

	task, err := s.createSunnyPaymentProbeTask(map[string]any{"session_ids": []uint{session.ID}, "countries": []string{"JP", "PH"}})
	if err != nil {
		t.Fatalf("create payment probe task: %v", err)
	}
	s.executeSunnyPaymentProbeTask(&task, jsonMap(task.PayloadJSON))
	if task.Status != TaskSucceeded {
		t.Fatalf("task status=%q error=%q", task.Status, task.Error)
	}
	var account SunnyAccount
	if err := s.db.Where("email = ?", session.Email).First(&account).Error; err != nil {
		t.Fatal(err)
	}
	var methods []string
	if err := json.Unmarshal([]byte(account.PaymentMethodsJSON), &methods); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(methods, ","); got != "paypal,card,link,gcash" {
		t.Fatalf("stored methods=%q", got)
	}
	if account.PaymentProbeMethodsJSON != account.PaymentMethodsJSON {
		t.Fatalf("dedicated methods=%s compatibility methods=%s", account.PaymentProbeMethodsJSON, account.PaymentMethodsJSON)
	}
	if account.PaymentProbedAt == nil || account.PaymentProbeError != "" || !strings.Contains(account.PaymentProbeResultsJSON, `"JP"`) || !strings.Contains(account.PaymentProbeResultsJSON, `"PH"`) {
		t.Fatalf("probe metadata not persisted: %#v", account)
	}
	var events []TaskEvent
	if err := s.db.Where("task_id = ?", task.ID).Order("id asc").Find(&events).Error; err != nil {
		t.Fatalf("load payment probe events: %v", err)
	}
	eventText := ""
	for _, event := range events {
		eventText += "\n" + event.Message
	}
	if !strings.Contains(eventText, "JP 探测完成") || !strings.Contains(eventText, "PH 探测完成") || !strings.Contains(eventText, "账户任务完成：1/1") {
		t.Fatalf("payment probe progress events are incomplete: %s", eventText)
	}
	if err := s.db.Model(&SunnyAccount{}).Where("id = ?", account.ID).Update("payment_methods_json", `["upi"]`).Error; err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	s.sunnySessions(recorder, httptest.NewRequest(http.MethodGet, "/api/sunny/sessions", nil), nil)
	if !strings.Contains(recorder.Body.String(), `"payment_methods":["paypal","card","link","gcash"]`) {
		t.Fatalf("dedicated payment methods were not preferred: %s", recorder.Body.String())
	}
}

func TestSunnyPaymentProbeTriesNextProxyAfterFailure(t *testing.T) {
	previousProbe := sunnyProbePaymentMethods
	calls := 0
	sunnyProbePaymentMethods = func(_ context.Context, _, _, _, _ string) sunnyPaymentProbeResponse {
		calls++
		if calls == 1 {
			return sunnyPaymentProbeResponse{Error: "proxy connection failed"}
		}
		return sunnyPaymentProbeResponse{Methods: []string{"momo"}, HTTP: http.StatusOK}
	}
	t.Cleanup(func() { sunnyProbePaymentMethods = previousProbe })
	s := &Server{}
	result := s.probeSunnyPaymentCountry(
		sunnyPaymentProbeCandidate{AccessToken: "token"},
		"VN",
		[]SunnyProxy{{ID: 1, Address: "http://first"}, {ID: 2, Address: "http://second"}},
	)
	if result.Error != "" || result.Attempts != 2 || strings.Join(result.Methods, ",") != "momo" {
		t.Fatalf("fallback result=%#v calls=%d", result, calls)
	}
}

func TestSunnyPaymentProbeLimitsProxyAttempts(t *testing.T) {
	previousProbe := sunnyProbePaymentMethods
	calls := 0
	sunnyProbePaymentMethods = func(_ context.Context, _, _, _, _ string) sunnyPaymentProbeResponse {
		calls++
		return sunnyPaymentProbeResponse{Error: "proxy connection failed"}
	}
	t.Cleanup(func() { sunnyProbePaymentMethods = previousProbe })
	proxies := make([]SunnyProxy, 0, 100)
	for index := 1; index <= 100; index++ {
		proxies = append(proxies, SunnyProxy{ID: uint(index), Address: fmt.Sprintf("http://proxy-%d.example:8080", index)})
	}
	result := (&Server{}).probeSunnyPaymentCountry(
		sunnyPaymentProbeCandidate{AccessToken: "token"},
		"VN",
		proxies,
	)
	if calls != sunnyPaymentProbeMaxAttempts {
		t.Fatalf("probe calls=%d, want %d", calls, sunnyPaymentProbeMaxAttempts)
	}
	if result.Attempts != sunnyPaymentProbeMaxAttempts || result.Error == "" {
		t.Fatalf("limited result=%#v", result)
	}
}

func TestSunnyPaymentProbeDoesNotRetryDefinitiveClientError(t *testing.T) {
	previousProbe := sunnyProbePaymentMethods
	calls := 0
	sunnyProbePaymentMethods = func(_ context.Context, _, _, _, _ string) sunnyPaymentProbeResponse {
		calls++
		return sunnyPaymentProbeResponse{HTTP: http.StatusBadRequest, Error: "HTTP 400: checkout rejected"}
	}
	t.Cleanup(func() { sunnyProbePaymentMethods = previousProbe })
	result := (&Server{}).probeSunnyPaymentCountry(
		sunnyPaymentProbeCandidate{AccessToken: "token"},
		"VN",
		[]SunnyProxy{{ID: 1, Address: "http://first"}, {ID: 2, Address: "http://second"}, {ID: 3, Address: "http://third"}},
	)
	if calls != 1 || result.Attempts != 1 {
		t.Fatalf("definitive client error should stop after the first attempt: calls=%d result=%#v", calls, result)
	}
}

func TestSunnyPaymentProbeEmitsAttemptProgress(t *testing.T) {
	s := newSunnySessionTestServer(t)
	var session SunnySession
	if err := s.db.Where("email = ?", "session@example.com").First(&session).Error; err != nil {
		t.Fatal(err)
	}
	if err := s.db.Create(&SunnyProxy{Address: "http://jp.example:8080", Country: "JP", PurposeTags: sunnyProxyPurposePayment, Status: "enabled", Enabled: true}).Error; err != nil {
		t.Fatal(err)
	}
	previousProbe := sunnyProbePaymentMethods
	attempts := 0
	sunnyProbePaymentMethods = func(_ context.Context, _, _, _, _ string) sunnyPaymentProbeResponse {
		attempts++
		if attempts < 3 {
			return sunnyPaymentProbeResponse{Error: "proxy connection failed"}
		}
		return sunnyPaymentProbeResponse{Methods: []string{"card"}, HTTP: http.StatusOK}
	}
	t.Cleanup(func() { sunnyProbePaymentMethods = previousProbe })

	if err := s.db.Create(&[]SunnyProxy{
		{Address: "http://jp-1.example:8080", Country: "JP", PurposeTags: sunnyProxyPurposePayment, Status: "enabled", Enabled: true},
		{Address: "http://jp-2.example:8080", Country: "JP", PurposeTags: sunnyProxyPurposePayment, Status: "enabled", Enabled: true},
		{Address: "http://jp-3.example:8080", Country: "JP", PurposeTags: sunnyProxyPurposePayment, Status: "enabled", Enabled: true},
	}).Error; err != nil {
		t.Fatal(err)
	}

	task, err := s.createSunnyPaymentProbeTask(map[string]any{"session_ids": []uint{session.ID}, "countries": []string{"JP"}})
	if err != nil {
		t.Fatal(err)
	}
	s.executeSunnyPaymentProbeTask(&task, jsonMap(task.PayloadJSON))
	if task.Status != TaskSucceeded {
		t.Fatalf("task status=%q error=%q", task.Status, task.Error)
	}
	var events []TaskEvent
	if err := s.db.Where("task_id = ? AND action = ?", task.ID, "payment_probe.attempt").Order("id asc").Find(&events).Error; err != nil {
		t.Fatalf("load attempt events: %v", err)
	}
	if len(events) != 3 {
		t.Fatalf("attempt events=%d, want 3", len(events))
	}
	for index, event := range events {
		detail := jsonMap(event.DetailJSON)
		if intValue(detail["current"], 0) != index+1 || intValue(detail["total"], 0) != 3 {
			t.Fatalf("attempt event #%d detail=%s", index+1, event.DetailJSON)
		}
		if !strings.Contains(event.Message, fmt.Sprintf("%d/%d", index+1, 3)) {
			t.Fatalf("attempt event #%d message=%q", index+1, event.Message)
		}
	}
}

func TestSunnyPaymentProbeTasksSkipOverlappingSessions(t *testing.T) {
	s := newSunnySessionTestServer(t)
	var first SunnySession
	if err := s.db.Where("email = ?", "session@example.com").First(&first).Error; err != nil {
		t.Fatal(err)
	}
	mailbox := SunnyMailbox{Email: "second-payment@example.com", Status: "已注册", AccountType: "free", Enabled: true}
	if err := s.db.Create(&mailbox).Error; err != nil {
		t.Fatal(err)
	}
	account := SunnyAccount{MailboxID: mailbox.ID, Email: mailbox.Email, Status: "registered", AccountType: "free", AccessToken: "second-token"}
	if err := s.db.Create(&account).Error; err != nil {
		t.Fatal(err)
	}
	second := SunnySession{AccountID: account.ID, Email: account.Email, AccessToken: account.AccessToken}
	if err := s.db.Create(&second).Error; err != nil {
		t.Fatal(err)
	}
	if err := s.db.Create(&SunnyProxy{Address: "http://jp.example:8080", Country: "JP", PurposeTags: sunnyProxyPurposePayment, Status: "enabled", Enabled: true}).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := s.createSunnyPaymentProbeTask(map[string]any{"session_ids": []uint{first.ID}, "countries": []string{"JP"}}); err != nil {
		t.Fatal(err)
	}
	task, err := s.createSunnyPaymentProbeTask(map[string]any{"session_ids": []uint{first.ID, second.ID}, "countries": []string{"JP"}})
	if err != nil {
		t.Fatal(err)
	}
	skipped := uintSlice(jsonMap(task.PayloadJSON)["skip_session_ids"])
	if len(skipped) != 1 || skipped[0] != first.ID {
		t.Fatalf("skip_session_ids=%v", skipped)
	}
}

func TestSunnyPaymentProbeRiskMarkerClassification(t *testing.T) {
	risky := []string{
		`IN: RuntimeError: OpenAI Checkout HTTP 400: {"detail":"Our systems have detected unusual activity. Please try again later."}`,
		"VN: OpenAI Checkout HTTP 400 检测到异常活动 (账户风控标记)",
		"VN: OpenAI Checkout HTTP 429 checkout_creation_rate_limited (等待冷却后重试)",
	}
	for _, message := range risky {
		if !sunnyPaymentProbeRiskMessage(message) {
			t.Fatalf("risk message not detected: %s", message)
		}
	}
	benign := []string{
		"",
		"VN: ProxyError: Failed to perform, curl: (56) Proxy CONNECT aborted. See https://curl.se/libcurl/c/libcurl-errors.html first for more details.",
		`IN: RuntimeError: OpenAI Checkout HTTP 500: {"detail":"Internal Server Error"}`,
		"VN: RuntimeError: OpenAI Checkout HTTP 401: token_revoked",
	}
	for _, message := range benign {
		if sunnyPaymentProbeRiskMessage(message) {
			t.Fatalf("benign message misclassified as risk: %s", message)
		}
	}
}

func TestSunnyPaymentProbeProxyFailureExcludesCancellation(t *testing.T) {
	proxyError := sunnyPaymentProbeResponse{Error: "ProxyError: Failed to perform, curl: (56) Proxy CONNECT aborted."}
	if !sunnyPaymentProbeProxyFailure(proxyError, nil) {
		t.Fatal("proxy connection failure should be treated as a proxy failure")
	}
	if sunnyPaymentProbeProxyFailure(proxyError, context.Canceled) {
		t.Fatal("a cancelled task must not be treated as a proxy failure")
	}
	if sunnyPaymentProbeProxyFailure(sunnyPaymentProbeResponse{Error: "context canceled"}, nil) {
		t.Fatal("cancellation error must not be treated as a proxy failure")
	}
	if sunnyPaymentProbeProxyFailure(sunnyPaymentProbeResponse{HTTP: http.StatusBadRequest, Error: `HTTP 400 unusual activity`}, nil) {
		t.Fatal("an HTTP response from OpenAI must not be treated as a proxy failure")
	}
}

func TestSunnyPaymentProbeCountryProbeFlagsRisk(t *testing.T) {
	previousProbe := sunnyProbePaymentMethods
	sunnyProbePaymentMethods = func(_ context.Context, _, _, _, _ string) sunnyPaymentProbeResponse {
		return sunnyPaymentProbeResponse{HTTP: http.StatusTooManyRequests, Error: "OpenAI Checkout HTTP 429 checkout_creation_rate_limited"}
	}
	t.Cleanup(func() { sunnyProbePaymentMethods = previousProbe })

	result := (&Server{}).probeSunnyPaymentCountry(
		sunnyPaymentProbeCandidate{AccessToken: "token"},
		"VN",
		[]SunnyProxy{{ID: 7, Address: "http://vn.example:8080"}},
	)
	if !result.Risk || result.HTTP != http.StatusTooManyRequests {
		t.Fatalf("risk probe result=%#v", result)
	}
}

func TestSunnyPaymentProbeCountryProbeFlagsUnreachableProxy(t *testing.T) {
	previousProbe := sunnyProbePaymentMethods
	sunnyProbePaymentMethods = func(_ context.Context, _, _, _, _ string) sunnyPaymentProbeResponse {
		return sunnyPaymentProbeResponse{Error: "ProxyError: Failed to perform, curl: (56) Proxy CONNECT aborted."}
	}
	t.Cleanup(func() { sunnyProbePaymentMethods = previousProbe })

	result := (&Server{}).probeSunnyPaymentCountry(
		sunnyPaymentProbeCandidate{AccessToken: "token"},
		"VN",
		[]SunnyProxy{{ID: 9, Address: "http://vn.example:8080"}},
	)
	// 代理不可达时请求根本没到达 OpenAI，不构成风控消耗，只需要回写代理健康状态。
	if !result.ProxyFailed || result.Risk || result.ProxyID != 9 {
		t.Fatalf("unreachable proxy result=%#v", result)
	}
}

func TestSunnyPaymentProbeStaleProxyCountriesDetectsOutdatedHealth(t *testing.T) {
	now := time.Now()
	recent := now.Add(-time.Hour)
	outdated := now.Add(-48 * time.Hour)
	groups := map[string][]SunnyProxy{
		"JP": {{ID: 1, Country: "JP", LastCheckOK: true, LastCheckedAt: &recent}},
		"VN": {{ID: 2, Country: "VN", LastCheckOK: true, LastCheckedAt: &outdated}},
		"IN": {{ID: 3, Country: "IN", LastCheckOK: false, LastCheckedAt: &recent}},
		"PH": {{ID: 4, Country: "PH"}},
	}
	if got := strings.Join(sunnyPaymentProbeStaleProxyCountries(groups), ","); got != "IN,PH,VN" {
		t.Fatalf("stale countries=%q", got)
	}
}

func TestSunnyPaymentProbeMomoStatusDecision(t *testing.T) {
	cases := []struct {
		methods []any
		promo   bool
		want    string
		certain bool
	}{
		{[]any{"card", "link", "momo"}, false, "momo_only", true},
		{[]any{"card", "link", "momo"}, true, "momo_only", true},
		{[]any{"card", "link"}, false, "unsupported", true},
		// 带 0 元优惠建单时服务端会剥离 MoMo，无法区分「不满足优惠资格」与
		// 「优惠剥离了 MoMo」，必须保持 unknown 而不是写入错误结论。
		{[]any{"card", "link"}, true, "", false},
	}
	for _, item := range cases {
		got, certain := sunnyMomoProbeStatus(map[string]any{"methods": item.methods}, item.promo)
		if got != item.want || certain != item.certain {
			t.Fatalf("methods=%v promo=%v status=%q certain=%v, want %q/%v", item.methods, item.promo, got, certain, item.want, item.certain)
		}
	}
}

func TestSunnyPaymentProbeRiskBreakerStopsRemainingAccounts(t *testing.T) {
	t.Setenv("SUNNY_PAYMENT_PROBE_CONCURRENCY", "1")
	s := newSunnySessionTestServer(t)
	sessions := []SunnySession{}
	var first SunnySession
	if err := s.db.Where("email = ?", "session@example.com").First(&first).Error; err != nil {
		t.Fatal(err)
	}
	sessions = append(sessions, first)
	for index := 1; index < 5; index++ {
		mailbox := SunnyMailbox{Email: fmt.Sprintf("risk-%d@example.com", index), Status: "已注册", AccountType: "free", Enabled: true}
		if err := s.db.Create(&mailbox).Error; err != nil {
			t.Fatal(err)
		}
		account := SunnyAccount{MailboxID: mailbox.ID, Email: mailbox.Email, Status: "registered", AccountType: "free", AccessToken: fmt.Sprintf("risk-token-%d", index)}
		if err := s.db.Create(&account).Error; err != nil {
			t.Fatal(err)
		}
		session := SunnySession{AccountID: account.ID, Email: account.Email, AccessToken: account.AccessToken}
		if err := s.db.Create(&session).Error; err != nil {
			t.Fatal(err)
		}
		sessions = append(sessions, session)
	}
	now := time.Now()
	if err := s.db.Create(&SunnyProxy{Address: "http://vn.example:8080", Country: "VN", PurposeTags: sunnyProxyPurposePayment, Status: "enabled", Enabled: true, LastCheckOK: true, LastCheckedAt: &now}).Error; err != nil {
		t.Fatal(err)
	}
	previousProbe := sunnyProbePaymentMethods
	probes := 0
	sunnyProbePaymentMethods = func(_ context.Context, _, _, _, _ string) sunnyPaymentProbeResponse {
		probes++
		return sunnyPaymentProbeResponse{
			HTTP:  http.StatusBadRequest,
			Error: `OpenAI Checkout HTTP 400: {"detail":"Our systems have detected unusual activity. Please try again later."}`,
		}
	}
	t.Cleanup(func() { sunnyProbePaymentMethods = previousProbe })

	ids := make([]uint, 0, len(sessions))
	for _, session := range sessions {
		ids = append(ids, session.ID)
	}
	task, err := s.createSunnyPaymentProbeTask(map[string]any{"session_ids": ids, "countries": []string{"VN"}})
	if err != nil {
		t.Fatal(err)
	}
	s.executeSunnyPaymentProbeTask(&task, jsonMap(task.PayloadJSON))

	var stored Task
	if err := s.db.First(&stored, "id = ?", task.ID).Error; err != nil {
		t.Fatal(err)
	}
	result := jsonMap(stored.ResultJSON)
	if !boolValue(result["risk_breaker"], false) {
		t.Fatalf("risk breaker did not open: %s", stored.ResultJSON)
	}
	if stored.ProgressCurrent != sunnyPaymentProbeRiskBreakerLimit {
		t.Fatalf("processed=%d, want %d", stored.ProgressCurrent, sunnyPaymentProbeRiskBreakerLimit)
	}
	if probes >= len(sessions) {
		t.Fatalf("risk breaker kept probing every account: probes=%d accounts=%d", probes, len(sessions))
	}
	if got := intValue(result["skipped"], 0); got != len(sessions)-sunnyPaymentProbeRiskBreakerLimit {
		t.Fatalf("skipped=%d, want %d (result=%s)", got, len(sessions)-sunnyPaymentProbeRiskBreakerLimit, stored.ResultJSON)
	}
	var events []TaskEvent
	if err := s.db.Where("task_id = ? AND action = ?", task.ID, "payment_probe.risk").Find(&events).Error; err != nil {
		t.Fatal(err)
	}
	if len(events) != sunnyPaymentProbeRiskBreakerLimit {
		t.Fatalf("risk events=%d, want %d", len(events), sunnyPaymentProbeRiskBreakerLimit)
	}
	// 熔断中止时在途探测会以 context canceled 结束，不能被误记为代理故障。
	var storedProxy SunnyProxy
	if err := s.db.Where("country = ?", "VN").First(&storedProxy).Error; err != nil {
		t.Fatal(err)
	}
	if !storedProxy.LastCheckOK || storedProxy.LastError != "" {
		t.Fatalf("risk breaker must not mark a reachable proxy unhealthy: %#v", storedProxy)
	}
}

func TestSunnyPaymentProbeMarksUnreachableProxyUnhealthy(t *testing.T) {
	t.Setenv("SUNNY_PAYMENT_PROBE_CONCURRENCY", "1")
	s := newSunnySessionTestServer(t)
	var session SunnySession
	if err := s.db.Where("email = ?", "session@example.com").First(&session).Error; err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	proxy := SunnyProxy{Address: "http://vn.example:8080", Country: "VN", PurposeTags: sunnyProxyPurposePayment, Status: "enabled", Enabled: true, LastCheckOK: true, LastCheckedAt: &now}
	if err := s.db.Create(&proxy).Error; err != nil {
		t.Fatal(err)
	}
	previousProbe := sunnyProbePaymentMethods
	sunnyProbePaymentMethods = func(_ context.Context, _, _, _, _ string) sunnyPaymentProbeResponse {
		return sunnyPaymentProbeResponse{Error: "ProxyError: Failed to perform, curl: (56) Proxy CONNECT aborted."}
	}
	t.Cleanup(func() { sunnyProbePaymentMethods = previousProbe })

	task, err := s.createSunnyPaymentProbeTask(map[string]any{"session_ids": []uint{session.ID}, "countries": []string{"VN"}})
	if err != nil {
		t.Fatal(err)
	}
	s.executeSunnyPaymentProbeTask(&task, jsonMap(task.PayloadJSON))

	var stored SunnyProxy
	if err := s.db.First(&stored, "id = ?", proxy.ID).Error; err != nil {
		t.Fatal(err)
	}
	if stored.LastCheckOK || !strings.Contains(stored.LastError, "Proxy CONNECT aborted") || stored.LastCheckedAt == nil {
		t.Fatalf("unreachable proxy was not marked unhealthy: %#v", stored)
	}
}

func TestSunnyPaymentProbePersistsMomoStatusForVietnam(t *testing.T) {
	t.Setenv("SUNNY_PAYMENT_PROBE_CONCURRENCY", "1")
	s := newSunnySessionTestServer(t)
	var session SunnySession
	if err := s.db.Where("email = ?", "session@example.com").First(&session).Error; err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := s.db.Create(&SunnyProxy{Address: "http://vn.example:8080", Country: "VN", PurposeTags: sunnyProxyPurposePayment, Status: "enabled", Enabled: true, LastCheckOK: true, LastCheckedAt: &now}).Error; err != nil {
		t.Fatal(err)
	}
	previousProbe := sunnyProbePaymentMethods
	sunnyProbePaymentMethods = func(_ context.Context, _, _, _, _ string) sunnyPaymentProbeResponse {
		return sunnyPaymentProbeResponse{Methods: []string{"card", "link", "momo"}, HTTP: http.StatusOK}
	}
	t.Cleanup(func() { sunnyProbePaymentMethods = previousProbe })

	task, err := s.createSunnyPaymentProbeTask(map[string]any{"session_ids": []uint{session.ID}, "countries": []string{"VN"}})
	if err != nil {
		t.Fatal(err)
	}
	s.executeSunnyPaymentProbeTask(&task, jsonMap(task.PayloadJSON))

	var account SunnyAccount
	if err := s.db.Where("email = ?", session.Email).First(&account).Error; err != nil {
		t.Fatal(err)
	}
	if account.MomoPromoStatus != "momo_only" || account.MomoPromoProbedAt == nil || account.MomoPromoError != "" {
		t.Fatalf("momo status not persisted: %#v", account)
	}
	if !strings.Contains(account.MomoPromoResultJSON, `"momo"`) || !strings.Contains(account.MomoPromoResultJSON, `"VND"`) {
		t.Fatalf("momo evidence not persisted: %s", account.MomoPromoResultJSON)
	}
}

func TestSunnyPaymentProbeKeepsMomoUnknownWhenPromotionHidesMethods(t *testing.T) {
	t.Setenv("SUNNY_PAYMENT_PROBE_CONCURRENCY", "1")
	s := newSunnySessionTestServer(t)
	var session SunnySession
	if err := s.db.Where("email = ?", "session@example.com").First(&session).Error; err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := s.db.Create(&SunnyProxy{Address: "http://vn.example:8080", Country: "VN", PurposeTags: sunnyProxyPurposePayment, Status: "enabled", Enabled: true, LastCheckOK: true, LastCheckedAt: &now}).Error; err != nil {
		t.Fatal(err)
	}
	previousProbe := sunnyProbePaymentMethods
	sunnyProbePaymentMethods = func(_ context.Context, _, _, _, _ string) sunnyPaymentProbeResponse {
		return sunnyPaymentProbeResponse{Methods: []string{"card", "link"}, HTTP: http.StatusOK}
	}
	t.Cleanup(func() { sunnyProbePaymentMethods = previousProbe })

	task, err := s.createSunnyPaymentProbeTask(map[string]any{"session_ids": []uint{session.ID}, "countries": []string{"VN"}, "use_trial_promotion": true})
	if err != nil {
		t.Fatal(err)
	}
	s.executeSunnyPaymentProbeTask(&task, jsonMap(task.PayloadJSON))

	var account SunnyAccount
	if err := s.db.Where("email = ?", session.Email).First(&account).Error; err != nil {
		t.Fatal(err)
	}
	if account.MomoPromoStatus != "unknown" || account.MomoPromoProbedAt != nil {
		t.Fatalf("ambiguous promotion probe must not overwrite momo status: %#v", account)
	}
}

func TestSunnyPaymentProbeEmitsStaleProxyWarning(t *testing.T) {
	t.Setenv("SUNNY_PAYMENT_PROBE_CONCURRENCY", "1")
	s := newSunnySessionTestServer(t)
	var session SunnySession
	if err := s.db.Where("email = ?", "session@example.com").First(&session).Error; err != nil {
		t.Fatal(err)
	}
	outdated := time.Now().Add(-72 * time.Hour)
	if err := s.db.Create(&SunnyProxy{Address: "http://vn.example:8080", Country: "VN", PurposeTags: sunnyProxyPurposePayment, Status: "enabled", Enabled: true, LastCheckOK: true, LastCheckedAt: &outdated}).Error; err != nil {
		t.Fatal(err)
	}
	previousProbe := sunnyProbePaymentMethods
	sunnyProbePaymentMethods = func(_ context.Context, _, _, _, _ string) sunnyPaymentProbeResponse {
		return sunnyPaymentProbeResponse{Methods: []string{"momo"}, HTTP: http.StatusOK}
	}
	t.Cleanup(func() { sunnyProbePaymentMethods = previousProbe })

	task, err := s.createSunnyPaymentProbeTask(map[string]any{"session_ids": []uint{session.ID}, "countries": []string{"VN"}})
	if err != nil {
		t.Fatal(err)
	}
	s.executeSunnyPaymentProbeTask(&task, jsonMap(task.PayloadJSON))

	var events []TaskEvent
	if err := s.db.Where("task_id = ? AND level = ?", task.ID, "warning").Find(&events).Error; err != nil {
		t.Fatal(err)
	}
	found := false
	for _, event := range events {
		if strings.Contains(event.Message, "代理健康数据陈旧告警") && strings.Contains(event.Message, "VN") {
			found = true
		}
	}
	if !found {
		t.Fatalf("stale proxy warning missing: %#v", events)
	}
}

func TestSunnyPaymentProbeTaskUsesSelectedCountries(t *testing.T) {
	s := newSunnySessionTestServer(t)
	var session SunnySession
	if err := s.db.Where("email = ?", "session@example.com").First(&session).Error; err != nil {
		t.Fatal(err)
	}
	proxies := []SunnyProxy{
		{Address: "http://jp.example:8080", Country: "JP", PurposeTags: sunnyProxyPurposePayment, Status: "enabled", Enabled: true},
		{Address: "http://ph.example:8080", Country: "PH", PurposeTags: sunnyProxyPurposePayment, Status: "enabled", Enabled: true},
		{Address: "http://disabled.example:8080", Country: "NL", PurposeTags: sunnyProxyPurposePayment, Status: "disabled", Enabled: false},
	}
	if err := s.db.Create(&proxies).Error; err != nil {
		t.Fatal(err)
	}
	if err := s.db.Model(&SunnyAccount{}).Where("email = ?", session.Email).Updates(map[string]any{
		"payment_probe_results_json": `{"JP":{"methods":["paypal"]},"PH":{"methods":["old_wallet"]}}`,
		"payment_probe_methods_json": `["paypal","old_wallet"]`,
	}).Error; err != nil {
		t.Fatal(err)
	}
	previousProbe := sunnyProbePaymentMethods
	calledCountries := []string{}
	calledWithPromotion := false
	sunnyProbePaymentMethods = func(ctx context.Context, _, country, _, _ string) sunnyPaymentProbeResponse {
		calledCountries = append(calledCountries, country)
		calledWithPromotion, _ = ctx.Value(sunnyPaymentPromotionContextKey{}).(bool)
		return sunnyPaymentProbeResponse{Methods: []string{"gcash"}, HTTP: http.StatusOK}
	}
	t.Cleanup(func() { sunnyProbePaymentMethods = previousProbe })

	if _, err := s.createSunnyPaymentProbeTask(map[string]any{"session_ids": []uint{session.ID}}); err == nil || !strings.Contains(err.Error(), "至少选择") {
		t.Fatalf("missing countries should be rejected, got %v", err)
	}
	missingCountryPayload := map[string]any{"session_ids": []uint{session.ID}}
	missingCountryTask := s.createTask(sunnyPaymentProbeTaskType, "sunny", missingCountryPayload, 1)
	s.executeSunnyPaymentProbeTask(&missingCountryTask, missingCountryPayload)
	if missingCountryTask.Status != TaskFailed || len(calledCountries) != 0 {
		t.Fatalf("payment executor accepted a task without selected countries: status=%q countries=%v", missingCountryTask.Status, calledCountries)
	}
	task, err := s.createSunnyPaymentProbeTask(map[string]any{"session_ids": []uint{session.ID}, "countries": []any{"PH", "PH"}, "use_trial_promotion": true})
	if err != nil {
		t.Fatal(err)
	}
	payload := jsonMap(task.PayloadJSON)
	if got := strings.Join(stringSlice(payload["countries"]), ","); got != "PH" {
		t.Fatalf("countries payload=%q", got)
	}
	if !boolValue(payload["use_trial_promotion"], false) {
		t.Fatalf("trial promotion was not persisted in task payload: %#v", payload)
	}
	s.executeSunnyPaymentProbeTask(&task, payload)
	if got := strings.Join(calledCountries, ","); got != "PH" {
		t.Fatalf("probed countries=%q", got)
	}
	if !calledWithPromotion {
		t.Fatal("trial promotion was not propagated to the country probe")
	}
	var account SunnyAccount
	if err := s.db.Where("email = ?", session.Email).First(&account).Error; err != nil {
		t.Fatal(err)
	}
	merged := jsonMap(account.PaymentProbeResultsJSON)
	if _, ok := merged["JP"]; !ok {
		t.Fatalf("unselected JP history was removed: %#v", merged)
	}
	ph, _ := merged["PH"].(map[string]any)
	if got := strings.Join(stringSlice(ph["methods"]), ","); got != "gcash" {
		t.Fatalf("selected PH history was not replaced: %#v", ph)
	}
	var methods []string
	if err := json.Unmarshal([]byte(account.PaymentProbeMethodsJSON), &methods); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(methods, ","); got != "paypal,gcash" {
		t.Fatalf("merged payment methods=%q", got)
	}
	if _, err := s.createSunnyPaymentProbeTask(map[string]any{"session_ids": []uint{session.ID}, "countries": []any{"NL"}}); err == nil || !strings.Contains(err.Error(), "NL") {
		t.Fatalf("expected unavailable country error, got %v", err)
	}

	recorder := httptest.NewRecorder()
	s.sunnySessions(recorder, httptest.NewRequest(http.MethodGet, "/api/sunny/sessions/payment-probe/countries", nil), []string{"payment-probe", "countries"})
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"countries":["JP","PH"]`) {
		t.Fatalf("countries endpoint status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestSunnyPaymentProbeMergesCountrySnapshots(t *testing.T) {
	existing := `{"JP":{"methods":["paypal","card"]},"NL":{"methods":["ideal"]},"PH":{"methods":["gcash"]}}`

	merged, methods := mergeSunnyPaymentProbeResults(existing, map[string]any{
		"PH": map[string]any{"methods": []string{}, "http": http.StatusOK},
	})
	if got := strings.Join(methods, ","); got != "paypal,card,ideal" {
		t.Fatalf("methods after successful empty PH snapshot=%q", got)
	}
	ph := merged["PH"].(map[string]any)
	if len(stringSlice(ph["methods"])) != 0 || text(ph["error"]) != "" {
		t.Fatalf("PH snapshot was not replaced: %#v", ph)
	}

	merged, methods = mergeSunnyPaymentProbeResults(existing, map[string]any{
		"PH": map[string]any{"methods": []string{}, "http": 0, "error": "proxy timeout", "attempts": 2},
	})
	if got := strings.Join(methods, ","); got != "paypal,card,gcash,ideal" {
		t.Fatalf("methods after failed PH snapshot=%q", got)
	}
	ph = merged["PH"].(map[string]any)
	if got := strings.Join(stringSlice(ph["methods"]), ","); got != "gcash" || text(ph["error"]) != "proxy timeout" {
		t.Fatalf("PH previous methods were not preserved with latest error: %#v", ph)
	}
}

func TestSunnySessionPaymentMethodFilterUsesANDSemantics(t *testing.T) {
	s := newSunnySessionTestServer(t)
	if err := s.db.Model(&SunnyAccount{}).Where("email = ?", "session@example.com").Update("payment_methods_json", `["paypal","card"]`).Error; err != nil {
		t.Fatal(err)
	}
	mailbox := SunnyMailbox{Email: "upi@example.com", Status: "已注册", AccountType: "free", Enabled: true}
	if err := s.db.Create(&mailbox).Error; err != nil {
		t.Fatal(err)
	}
	account := SunnyAccount{MailboxID: mailbox.ID, Email: mailbox.Email, Status: "registered", AccountType: "free", AccessToken: "token", PaymentMethodsJSON: `["paypal","upi","future_wallet_v2"]`}
	if err := s.db.Create(&account).Error; err != nil {
		t.Fatal(err)
	}
	if err := s.db.Create(&SunnySession{AccountID: account.ID, Email: account.Email, AccessToken: account.AccessToken}).Error; err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/sunny/sessions?payment_methods=paypal,card", nil)
	s.sunnySessions(recorder, request, nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var payload struct {
		Items                []map[string]any `json:"items"`
		Total                int              `json:"total"`
		PaymentMethodOptions []string         `json:"payment_method_options"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Total != 1 || len(payload.Items) != 1 || payload.Items[0]["email"] != "session@example.com" {
		t.Fatalf("unexpected AND filter result: %#v", payload)
	}
	if !containsString(payload.PaymentMethodOptions, "upi") || !containsString(payload.PaymentMethodOptions, "card") || !containsString(payload.PaymentMethodOptions, "future_wallet_v2") {
		t.Fatalf("dynamic payment method options=%v", payload.PaymentMethodOptions)
	}
}

func TestSunnySessionPaymentProbeUnknownFilterUsesDedicatedProbeTimestamp(t *testing.T) {
	s := newSunnySessionTestServer(t)
	now := time.Now()
	if err := s.db.Model(&SunnyAccount{}).Where("email = ?", "session@example.com").Updates(map[string]any{
		"payment_methods_json":       `[]`,
		"payment_probe_methods_json": `[]`,
		"payment_probed_at":          now,
	}).Error; err != nil {
		t.Fatal(err)
	}
	mailbox := SunnyMailbox{Email: "unchecked@example.com", Status: "已注册", AccountType: "free", Enabled: true}
	if err := s.db.Create(&mailbox).Error; err != nil {
		t.Fatal(err)
	}
	account := SunnyAccount{MailboxID: mailbox.ID, Email: mailbox.Email, Status: "registered", AccountType: "free", AccessToken: "token"}
	if err := s.db.Create(&account).Error; err != nil {
		t.Fatal(err)
	}
	if err := s.db.Create(&SunnySession{AccountID: account.ID, Email: account.Email, AccessToken: account.AccessToken}).Error; err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/sunny/sessions?payment_probe_status=unknown", nil)
	s.sunnySessions(recorder, request, nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var payload struct {
		Items []map[string]any `json:"items"`
		Total int              `json:"total"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Total != 1 || len(payload.Items) != 1 || payload.Items[0]["email"] != "unchecked@example.com" {
		t.Fatalf("unexpected unknown probe filter result: %#v", payload)
	}
}
