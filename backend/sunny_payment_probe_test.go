package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

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
			return sunnyPaymentProbeResponse{Kind: "oaics", Methods: []string{"paypal", "card", "link"}, HTTP: http.StatusOK}
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
	if account.CheckoutKind != "oaics" {
		t.Fatalf("checkout kind was not persisted from payment probe: %q", account.CheckoutKind)
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

func TestSunnyMomoPromoStatusRequiresDiscountAndMomo(t *testing.T) {
	zero, full := 0, 522500
	cases := []struct {
		methods  []string
		amount   *int
		currency string
		want     string
	}{
		{[]string{"card", "momo"}, &zero, "VND", "supported"},
		{[]string{"card"}, &zero, "VND", "promo_only"},
		{[]string{"momo"}, &full, "VND", "momo_only"},
		{[]string{"card"}, &full, "VND", "unsupported"},
	}
	for _, tc := range cases {
		if got := sunnyMomoPromoStatus(tc.methods, tc.amount, tc.currency); got != tc.want {
			t.Fatalf("methods=%v amount=%v currency=%s got=%s want=%s", tc.methods, tc.amount, tc.currency, got, tc.want)
		}
	}
}

func TestSunnyMomoPromoLimitsProxyAttempts(t *testing.T) {
	previousProbe := sunnyProbeMomoPromo
	calls := 0
	sunnyProbeMomoPromo = func(_ context.Context, _, _, _, _ string) sunnyPaymentProbeResponse {
		calls++
		return sunnyPaymentProbeResponse{HTTP: http.StatusServiceUnavailable, Error: "temporary proxy failure"}
	}
	t.Cleanup(func() { sunnyProbeMomoPromo = previousProbe })

	proxies := make([]SunnyProxy, 100)
	for index := range proxies {
		proxies[index] = SunnyProxy{ID: uint(index + 1), Address: "http://vn.example:8080"}
	}
	attempts := []int{}
	result := (&Server{}).probeSunnyPaymentCountryModeProgressContext(context.Background(), sunnyPaymentProbeCandidate{AccessToken: "token"}, "VN", proxies, sunnyPaymentProbeModeMomoPromo, func(current, total int) {
		attempts = append(attempts, current*10+total)
	})
	if calls != sunnyPaymentProbeMaxAttempts || result.Attempts != sunnyPaymentProbeMaxAttempts {
		t.Fatalf("calls=%d attempts=%d, want %d", calls, result.Attempts, sunnyPaymentProbeMaxAttempts)
	}
	if len(attempts) != 3 || attempts[0] != 13 || attempts[1] != 23 || attempts[2] != 33 {
		t.Fatalf("attempt progress=%v", attempts)
	}
}

func TestSunnyPaymentProbeMethodsAlsoLimitsProxyAttempts(t *testing.T) {
	previousProbe := sunnyProbePaymentMethods
	calls := 0
	sunnyProbePaymentMethods = func(_ context.Context, _, _, _, _ string) sunnyPaymentProbeResponse {
		calls++
		return sunnyPaymentProbeResponse{HTTP: http.StatusServiceUnavailable, Error: "temporary proxy failure"}
	}
	t.Cleanup(func() { sunnyProbePaymentMethods = previousProbe })

	proxies := make([]SunnyProxy, 100)
	for index := range proxies {
		proxies[index] = SunnyProxy{ID: uint(index + 1), Address: "http://vn.example:8080"}
	}
	result := (&Server{}).probeSunnyPaymentCountryModeContext(context.Background(), sunnyPaymentProbeCandidate{AccessToken: "token"}, "VN", proxies, sunnyPaymentProbeModeMethods)
	if calls != sunnyPaymentProbeMaxAttempts || result.Attempts != sunnyPaymentProbeMaxAttempts {
		t.Fatalf("methods mode calls=%d attempts=%d, want limit %d (反复建单会触发账号级 429 冷却)", calls, result.Attempts, sunnyPaymentProbeMaxAttempts)
	}
}

func TestSunnyMomoPromoDoesNotRetryDefinitiveClientError(t *testing.T) {
	previousProbe := sunnyProbeMomoPromo
	calls := 0
	sunnyProbeMomoPromo = func(_ context.Context, _, _, _, _ string) sunnyPaymentProbeResponse {
		calls++
		return sunnyPaymentProbeResponse{HTTP: http.StatusBadRequest, Error: "promotion unavailable"}
	}
	t.Cleanup(func() { sunnyProbeMomoPromo = previousProbe })

	result := (&Server{}).probeSunnyPaymentCountryModeContext(context.Background(), sunnyPaymentProbeCandidate{AccessToken: "token"}, "VN", []SunnyProxy{{ID: 1}, {ID: 2}, {ID: 3}}, sunnyPaymentProbeModeMomoPromo)
	if calls != 1 || result.Attempts != 1 {
		t.Fatalf("calls=%d attempts=%d, want one definitive attempt", calls, result.Attempts)
	}
}

func TestSunnyPaymentProbeMomoPromoPersistsSeparateResultAndCheckoutKind(t *testing.T) {
	s := newSunnySessionTestServer(t)
	var session SunnySession
	if err := s.db.Where("email = ?", "session@example.com").First(&session).Error; err != nil {
		t.Fatal(err)
	}
	proxy := SunnyProxy{Address: "http://vn.example:8080", Country: "VN", PurposeTags: sunnyProxyPurposePayment, Status: "enabled", Enabled: true}
	if err := s.db.Create(&proxy).Error; err != nil {
		t.Fatal(err)
	}
	if err := s.db.Model(&SunnyAccount{}).Where("email = ?", session.Email).Updates(map[string]any{
		"payment_methods_json": `["card","momo"]`, "payment_probe_methods_json": `["card","momo"]`,
	}).Error; err != nil {
		t.Fatal(err)
	}
	previousProbe := sunnyProbeMomoPromo
	zero := 0
	sunnyProbeMomoPromo = func(_ context.Context, token, country, currency, proxyURL string) sunnyPaymentProbeResponse {
		if token == "" || country != "VN" || currency != "VND" || proxyURL == "" {
			return sunnyPaymentProbeResponse{Error: "missing routing data"}
		}
		return sunnyPaymentProbeResponse{Kind: "oaics", Methods: []string{"card", "link", "momo"}, Amount: &zero, Currency: "VND", MomoDiscounted: true, HTTP: http.StatusOK}
	}
	t.Cleanup(func() { sunnyProbeMomoPromo = previousProbe })

	task, err := s.createSunnyPaymentProbeTask(map[string]any{"session_ids": []uint{session.ID}, "mode": sunnyPaymentProbeModeMomoPromo})
	if err != nil {
		t.Fatal(err)
	}
	payload := jsonMap(task.PayloadJSON)
	if got := strings.Join(stringSlice(payload["countries"]), ","); got != "VN" {
		t.Fatalf("momo promo countries=%q", got)
	}
	s.executeSunnyPaymentProbeTask(&task, payload)
	var account SunnyAccount
	if err := s.db.Where("email = ?", session.Email).First(&account).Error; err != nil {
		t.Fatal(err)
	}
	if account.MomoPromoStatus != "supported" || account.MomoPromoProbedAt == nil || account.MomoPromoError != "" || account.CheckoutKind != "oaics" {
		t.Fatalf("momo promo metadata not persisted: %#v", account)
	}
	if account.PaymentMethodsJSON != `["card","momo"]` || account.PaymentProbeMethodsJSON != `["card","momo"]` {
		t.Fatalf("promo probe overwrote standard methods: %s / %s", account.PaymentMethodsJSON, account.PaymentProbeMethodsJSON)
	}
	if !strings.Contains(account.MomoPromoResultJSON, `"status":"supported"`) {
		t.Fatalf("momo promo result=%s", account.MomoPromoResultJSON)
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
	sunnyProbePaymentMethods = func(_ context.Context, _, country, _, _ string) sunnyPaymentProbeResponse {
		calledCountries = append(calledCountries, country)
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
	task, err := s.createSunnyPaymentProbeTask(map[string]any{"session_ids": []uint{session.ID}, "countries": []any{"PH", "PH"}})
	if err != nil {
		t.Fatal(err)
	}
	payload := jsonMap(task.PayloadJSON)
	if got := strings.Join(stringSlice(payload["countries"]), ","); got != "PH" {
		t.Fatalf("countries payload=%q", got)
	}
	s.executeSunnyPaymentProbeTask(&task, payload)
	if got := strings.Join(calledCountries, ","); got != "PH" {
		t.Fatalf("probed countries=%q", got)
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
