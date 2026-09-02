package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

const (
	sunnyPaymentProbeTaskType      = "sunny_account_payment_probe"
	sunnyPaymentProbeModeMethods   = "methods"
	sunnyPaymentProbeModeMomoPromo = "momo_promo"
	// 每次探测单个账号在每个国家建立 Checkout 会话的代理尝试上限。
	// 老版本会对每个 VN 代理都创建一次 checkout，账号被反复建单数十次，
	// 直接触发 OpenAI 账号级 checkout_creation_rate_limited 冷却（429）。
	// 成功探测其实一次 HTTP 200 即返回，故统一限制为少量代理即可准确且不再误伤。
	sunnyPaymentProbeMaxAttempts   = 3
	sunnyMomoPromoAttemptTimeout   = 45 * time.Second
)

type sunnyPaymentProbeCandidate struct {
	SessionID   uint
	AccountID   uint
	Email       string
	AccessToken string
	SkipReason  string
	Error       string
}

type sunnyPaymentCountryProbe struct {
	Country        string
	Kind           string
	Methods        []string
	Amount         *int
	Currency       string
	MomoDiscounted bool
	ProxyID        uint
	Attempts       int
	HTTP           int
	InvalidToken   bool
	Error          string
	TrafficBytes   int64
}

type sunnyPaymentAccountProbe struct {
	Candidate    sunnyPaymentProbeCandidate
	Methods      []string
	Countries    map[string]any
	Errors       []string
	Succeeded    int
	InvalidToken bool
	TrafficBytes int64
}

type sunnyPaymentProbeResponse struct {
	Kind           string
	Methods        []string
	Amount         *int
	Currency       string
	MomoDiscounted bool
	HTTP           int
	InvalidToken   bool
	Error          string
	TrafficBytes   int64
}

var sunnyProbePaymentMethods = probeSunnyPaymentMethods
var sunnyProbeMomoPromo = probeSunnyMomoPromo

func normalizeSunnyPaymentProbeMode(value string) string {
	if strings.EqualFold(strings.TrimSpace(value), sunnyPaymentProbeModeMomoPromo) {
		return sunnyPaymentProbeModeMomoPromo
	}
	return sunnyPaymentProbeModeMethods
}

func sunnyMomoPromoStatus(methods []string, amount *int, currency string) string {
	hasMomo := containsString(normalizeSunnyPaymentMethods(methods), "momo")
	discounted := amount != nil && *amount >= 0 && *amount <= 50 && strings.EqualFold(strings.TrimSpace(currency), "VND")
	switch {
	case discounted && hasMomo:
		return "supported"
	case discounted:
		return "promo_only"
	case hasMomo:
		return "momo_only"
	default:
		return "unsupported"
	}
}

func normalizeSunnyPaymentMethod(value string) string {
	method := strings.ToLower(strings.TrimSpace(value))
	method = strings.TrimPrefix(method, "cpmt_")
	method = strings.TrimPrefix(method, "payment_method_")
	method = strings.NewReplacer("-", "_", " ", "_").Replace(method)
	aliases := map[string]string{
		"credit_card": "card", "cards": "card", "paypal_express": "paypal",
		"gcash_wallet": "gcash", "kakao": "kakao_pay", "kakaopay": "kakao_pay",
		"nice_pay": "nicepay", "ideal_bank": "ideal", "momo_wallet": "momo",
		"twint_wallet": "twint", "pix_qr": "pix", "upi_collect": "upi", "go_pay": "gopay",
		"pay_now": "paynow", "grab_pay": "grabpay", "prompt_pay": "promptpay",
		"pay_pay": "paypay", "przelewy24": "p24", "mbway": "mb_way",
	}
	if canonical := aliases[method]; canonical != "" {
		method = canonical
	}
	if len(method) > 64 {
		return ""
	}
	for _, char := range method {
		if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '_' {
			return ""
		}
	}
	return method
}

func normalizeSunnyPaymentMethods(values []string) []string {
	seen := map[string]bool{}
	methods := make([]string, 0, len(values))
	for _, value := range values {
		method := normalizeSunnyPaymentMethod(value)
		if method != "" && !seen[method] {
			seen[method] = true
			methods = append(methods, method)
		}
	}
	priority := map[string]int{
		"paypal": 0, "card": 1, "link": 2, "gcash": 3, "gopay": 4,
		"kakao_pay": 5, "nicepay": 6, "ideal": 7, "momo": 8, "twint": 9,
		"pix": 10, "upi": 11, "paynow": 12, "grabpay": 13, "fpx": 14,
		"promptpay": 15, "paypay": 16, "konbini": 17, "boleto": 18,
		"blik": 19, "p24": 20, "mb_way": 21,
	}
	sort.Slice(methods, func(i, j int) bool {
		left, leftKnown := priority[methods[i]]
		right, rightKnown := priority[methods[j]]
		if leftKnown != rightKnown {
			return leftKnown
		}
		if leftKnown {
			return left < right
		}
		return methods[i] < methods[j]
	})
	return methods
}

func normalizeSunnyPaymentMethodFilter(value string) []string {
	return normalizeSunnyPaymentMethods(strings.FieldsFunc(value, func(char rune) bool {
		return char == ',' || char == ';' || char == '|'
	}))
}

func normalizeSunnyMomoPromoStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "supported", "promo_only", "momo_only", "unsupported", "unknown":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func normalizeSunnyPaymentProbeFilter(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "unknown", "unchecked", "not_checked", "未检测":
		return "unknown"
	default:
		return ""
	}
}

func normalizeSunnyLoginSecretFilter(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "present", "has", "1", "true", "有", "有ls":
		return "present"
	case "missing", "none", "0", "false", "无", "无ls":
		return "missing"
	default:
		return ""
	}
}

func sunnyHasAllPaymentMethods(value any, required []string) bool {
	if len(required) == 0 {
		return true
	}
	available := map[string]bool{}
	if methods, ok := value.([]string); ok {
		for _, method := range normalizeSunnyPaymentMethods(methods) {
			available[method] = true
		}
	} else if methods, ok := value.([]any); ok {
		for _, method := range methods {
			available[normalizeSunnyPaymentMethod(text(method))] = true
		}
	}
	for _, method := range required {
		if !available[method] {
			return false
		}
	}
	return true
}

func probeSunnyPaymentMethods(ctx context.Context, accessToken, country, currency, proxyURL string) sunnyPaymentProbeResponse {
	if workerResult, ok := probeSunnyPaymentMethodsViaWorker(ctx, accessToken, country, currency, proxyURL); ok {
		return workerResult
	}
	meter := sunnyTrafficMeterFromContext(ctx)
	client := sunnyCommerceHTTPClientWithMeter(meter, proxyURL)
	kind, methods, invalid, err := probeSunnyCheckoutForCountry(ctx, client, accessToken, country, currency)
	result := sunnyPaymentProbeResponse{Kind: normalizeSunnyCheckoutKind(kind), Methods: normalizeSunnyPaymentMethods(methods), HTTP: http.StatusOK, InvalidToken: invalid}
	if err != nil {
		result.HTTP = 0
		result.Error = err.Error()
	}
	return result
}

func probeSunnyPaymentMethodsViaWorker(ctx context.Context, accessToken, country, currency, proxyURL string) (sunnyPaymentProbeResponse, bool) {
	return probeSunnyPaymentViaWorker(ctx, "/probe-payment-methods", accessToken, country, currency, proxyURL)
}

func probeSunnyMomoPromo(ctx context.Context, accessToken, country, currency, proxyURL string) sunnyPaymentProbeResponse {
	result, ok := probeSunnyPaymentViaWorker(ctx, "/probe-momo-promo", accessToken, country, currency, proxyURL)
	if !ok {
		result.Error = fallback(result.Error, "Python worker 优惠 MoMo 探测不可用")
	}
	return result
}

func probeSunnyPaymentViaWorker(ctx context.Context, endpoint, accessToken, country, currency, proxyURL string) (sunnyPaymentProbeResponse, bool) {
	result := sunnyPaymentProbeResponse{}
	workerURL := strings.TrimRight(strings.TrimSpace(os.Getenv("PYTHON_WORKER_URL")), "/")
	if workerURL == "" {
		workerURL = "http://127.0.0.1:8765"
	}
	body, _ := json.Marshal(map[string]string{"access_token": accessToken, "proxy_url": proxyURL, "country": country, "currency": currency})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, workerURL+endpoint, bytes.NewReader(body))
	if err != nil {
		return result, false
	}
	req.Header.Set("Content-Type", "application/json")
	if token := secretValue("PYTHON_WORKER_TOKEN", "PYTHON_WORKER_TOKEN_FILE"); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := (&http.Client{Timeout: 100 * time.Second}).Do(req)
	if err != nil {
		return result, false
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	if err != nil || resp.StatusCode == http.StatusNotFound || resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return result, false
	}
	var payload struct {
		Checkout struct {
			Kind           string   `json:"kind"`
			PaymentMethods []string `json:"payment_methods"`
			Amount         *int     `json:"amount"`
			Currency       string   `json:"currency"`
			MomoDiscounted bool     `json:"momo_discounted"`
			HTTP           int      `json:"http"`
			Error          string   `json:"error"`
		} `json:"checkout"`
		Traffic struct {
			TotalBytes int64 `json:"total_bytes"`
		} `json:"traffic"`
	}
	if json.Unmarshal(raw, &payload) != nil {
		return result, false
	}
	result.Kind = normalizeSunnyCheckoutKind(payload.Checkout.Kind)
	result.Methods = normalizeSunnyPaymentMethods(payload.Checkout.PaymentMethods)
	result.Amount = payload.Checkout.Amount
	result.Currency = strings.ToUpper(strings.TrimSpace(payload.Checkout.Currency))
	result.MomoDiscounted = payload.Checkout.MomoDiscounted
	result.HTTP = payload.Checkout.HTTP
	result.InvalidToken = payload.Checkout.HTTP == http.StatusUnauthorized
	result.Error = strings.TrimSpace(payload.Checkout.Error)
	result.TrafficBytes = payload.Traffic.TotalBytes
	if result.HTTP < 200 || result.HTTP >= 300 {
		result.Error = fallback(result.Error, fmt.Sprintf("ChatGPT Checkout 接口返回 HTTP %d", result.HTTP))
	}
	return result, true
}

func (s *Server) sunnyPaymentProbeConcurrency() int {
	return s.sunnyConfiguredConcurrency("payment_probe_concurrency", "SUNNY_PAYMENT_PROBE_CONCURRENCY", 8)
}

func (s *Server) sunnyPaymentCountryConcurrency() int {
	return s.sunnyConfiguredConcurrency("payment_country_concurrency", "SUNNY_PAYMENT_PROBE_COUNTRY_CONCURRENCY", 8)
}

func (s *Server) sunnyPaymentProbeCandidates(ids []uint) ([]sunnyPaymentProbeCandidate, error) {
	if len(ids) == 0 {
		return nil, fmt.Errorf("请选择需要探测支付方式的账户")
	}
	var sessions []SunnySession
	if err := s.db.Where("id IN ?", ids).Order("id asc").Find(&sessions).Error; err != nil {
		return nil, err
	}
	accounts, _ := s.sunnySessionSidecars(sessions)
	candidates := make([]sunnyPaymentProbeCandidate, 0, len(sessions))
	for _, session := range sessions {
		account := accounts[sunnyEmailKey(session.Email)]
		candidate := sunnyPaymentProbeCandidate{
			SessionID: session.ID, AccountID: firstUint(session.AccountID, account.ID), Email: session.Email,
			AccessToken: sunnyPreferredAccessToken(session.AccessToken, sunnyAccessTokenFromSessionJSON(session.SessionJSON), account.AccessToken),
		}
		if strings.TrimSpace(candidate.AccessToken) == "" {
			candidate.Error = "账户缺少 Access Token"
		}
		candidates = append(candidates, candidate)
	}
	return candidates, nil
}

func (s *Server) sunnyPaymentProxyGroups() (map[string][]SunnyProxy, error) {
	var proxies []SunnyProxy
	purposeQuery := "(',' || replace(lower(coalesce(purpose_tags, '')), ' ', '') || ',') LIKE ?"
	if err := s.db.Where("status = ? AND enabled = ?", "enabled", true).
		Where(purposeQuery, "%,"+sunnyProxyPurposePayment+",%").Order("id asc").Find(&proxies).Error; err != nil {
		return nil, err
	}
	groups := map[string][]SunnyProxy{}
	for _, proxy := range proxies {
		country, err := normalizeSunnyProxyCountry(proxy.Country)
		if err == nil {
			groups[country] = append(groups[country], proxy)
		}
	}
	if len(groups) == 0 {
		return nil, fmt.Errorf("请先为支付探测用途配置至少一个已启用且国家代码有效的代理")
	}
	return groups, nil
}

func sunnyPaymentProbeCountryList(groups map[string][]SunnyProxy) []string {
	countries := make([]string, 0, len(groups))
	for country := range groups {
		countries = append(countries, country)
	}
	sort.Strings(countries)
	return countries
}

func selectSunnyPaymentProxyGroups(groups map[string][]SunnyProxy, requested []string) (map[string][]SunnyProxy, []string, error) {
	if requested == nil {
		countries := sunnyPaymentProbeCountryList(groups)
		return groups, countries, nil
	}
	selected := map[string][]SunnyProxy{}
	seen := map[string]bool{}
	for _, value := range requested {
		country, err := normalizeSunnyProxyCountry(value)
		if err != nil {
			return nil, nil, err
		}
		if seen[country] {
			continue
		}
		proxies := groups[country]
		if len(proxies) == 0 {
			return nil, nil, fmt.Errorf("国家 %s 没有已启用的支付探测代理", country)
		}
		seen[country] = true
		selected[country] = proxies
	}
	if len(selected) == 0 {
		return nil, nil, fmt.Errorf("请至少选择一个支付探测国家")
	}
	countries := sunnyPaymentProbeCountryList(selected)
	return selected, countries, nil
}

func (s *Server) activeSunnyPaymentProbeSessionIDs() (map[uint]bool, error) {
	var tasks []Task
	if err := s.db.Where("type = ? AND status NOT IN ?", sunnyPaymentProbeTaskType, []string{TaskSucceeded, TaskFailed, TaskInterrupted, TaskCancelled}).Find(&tasks).Error; err != nil {
		return nil, err
	}
	active := map[uint]bool{}
	for _, task := range tasks {
		payload := jsonMap(task.PayloadJSON)
		skipped := map[uint]bool{}
		for _, id := range uintSlice(payload["skip_session_ids"]) {
			skipped[id] = true
		}
		for _, id := range uintSlice(payload["session_ids"]) {
			if !skipped[id] {
				active[id] = true
			}
		}
	}
	return active, nil
}

func (s *Server) createSunnyPaymentProbeTask(body map[string]any) (Task, error) {
	s.paymentProbeMu.Lock()
	defer s.paymentProbeMu.Unlock()
	ids := uintSlice(body["session_ids"])
	candidates, err := s.sunnyPaymentProbeCandidates(ids)
	if err != nil {
		return Task{}, err
	}
	if len(candidates) == 0 {
		return Task{}, fmt.Errorf("未找到需要探测支付方式的账户")
	}
	groups, err := s.sunnyPaymentProxyGroups()
	if err != nil {
		return Task{}, err
	}
	mode := normalizeSunnyPaymentProbeMode(text(body["mode"]))
	requestedCountries := []string{"VN"}
	rawCountries, exists := body["countries"]
	if mode == sunnyPaymentProbeModeMethods {
		if !exists {
			return Task{}, fmt.Errorf("请至少选择一个支付探测国家")
		}
		requestedCountries = stringSlice(rawCountries)
	}
	_, countries, err := selectSunnyPaymentProxyGroups(groups, requestedCountries)
	if err != nil {
		return Task{}, err
	}
	active, err := s.activeSunnyPaymentProbeSessionIDs()
	if err != nil {
		return Task{}, err
	}
	skipped := make([]uint, 0)
	for _, candidate := range candidates {
		if active[candidate.SessionID] {
			skipped = append(skipped, candidate.SessionID)
		}
	}
	payload := map[string]any{"session_ids": ids, "skip_session_ids": skipped, "countries": countries, "mode": mode}
	return s.createTask(sunnyPaymentProbeTaskType, "sunny", payload, len(candidates)), nil
}

func shuffledSunnyProxies(proxies []SunnyProxy) []SunnyProxy {
	shuffled := append([]SunnyProxy(nil), proxies...)
	rand.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
	return shuffled
}

func (s *Server) probeSunnyPaymentCountry(candidate sunnyPaymentProbeCandidate, country string, proxies []SunnyProxy) sunnyPaymentCountryProbe {
	return s.probeSunnyPaymentCountryModeContext(context.Background(), candidate, country, proxies, sunnyPaymentProbeModeMethods)
}

func (s *Server) probeSunnyPaymentCountryContext(ctx context.Context, candidate sunnyPaymentProbeCandidate, country string, proxies []SunnyProxy) sunnyPaymentCountryProbe {
	return s.probeSunnyPaymentCountryModeContext(ctx, candidate, country, proxies, sunnyPaymentProbeModeMethods)
}

func (s *Server) probeSunnyPaymentCountryModeContext(ctx context.Context, candidate sunnyPaymentProbeCandidate, country string, proxies []SunnyProxy, mode string) sunnyPaymentCountryProbe {
	return s.probeSunnyPaymentCountryModeProgressContext(ctx, candidate, country, proxies, mode, nil)
}

func (s *Server) probeSunnyPaymentCountryModeProgressContext(ctx context.Context, candidate sunnyPaymentProbeCandidate, country string, proxies []SunnyProxy, mode string, onAttempt func(current, total int)) sunnyPaymentCountryProbe {
	result := sunnyPaymentCountryProbe{Country: country}
	currency := checkoutCountryCurrency[country]
	if currency == "" {
		currency = "USD"
	}
	selected := shuffledSunnyProxies(proxies)
	timeout := 105 * time.Second
	if normalizeSunnyPaymentProbeMode(mode) == sunnyPaymentProbeModeMomoPromo {
		timeout = sunnyMomoPromoAttemptTimeout
	}
	// 任意探测模式都限制每个账号在该国家的建单次数，避免反复建单触发
	// OpenAI 账号级 checkout_creation_rate_limited 冷却（老版本全库探测的 429 即由此造成）。
	if limit := sunnyPaymentProbeMaxAttempts; len(selected) > limit {
		selected = selected[:limit]
	}
	for _, proxy := range selected {
		if ctx.Err() != nil {
			result.Error = "任务已取消"
			return result
		}
		result.Attempts++
		if onAttempt != nil {
			onAttempt(result.Attempts, len(selected))
		}
		probeCtx, cancel := context.WithTimeout(ctx, timeout)
		meter := &sunnyTrafficMeter{}
		probeCtx = withSunnyTrafficMeter(probeCtx, meter)
		var probed sunnyPaymentProbeResponse
		if normalizeSunnyPaymentProbeMode(mode) == sunnyPaymentProbeModeMomoPromo {
			probed = sunnyProbeMomoPromo(probeCtx, candidate.AccessToken, country, currency, normalizeSunnyProxyAddress(proxy.Address))
		} else {
			probed = sunnyProbePaymentMethods(probeCtx, candidate.AccessToken, country, currency, normalizeSunnyProxyAddress(proxy.Address))
		}
		cancel()
		result.TrafficBytes += meter.totalBytes() + probed.TrafficBytes
		result.ProxyID, result.HTTP, result.InvalidToken, result.Error = proxy.ID, probed.HTTP, probed.InvalidToken, probed.Error
		result.Kind, result.Amount, result.Currency, result.MomoDiscounted = probed.Kind, probed.Amount, probed.Currency, probed.MomoDiscounted
		if probed.InvalidToken {
			return result
		}
		if strings.TrimSpace(probed.Error) == "" && probed.HTTP >= 200 && probed.HTTP < 300 {
			result.Methods = normalizeSunnyPaymentMethods(probed.Methods)
			return result
		}
		if probed.HTTP >= 400 && probed.HTTP < 500 && probed.HTTP != http.StatusForbidden && probed.HTTP != http.StatusRequestTimeout && probed.HTTP != http.StatusTooManyRequests {
			return result
		}
	}
	result.Error = fallback(result.Error, "该国家没有可用的支付探测代理")
	return result
}

func (s *Server) probeSunnyPaymentAccount(candidate sunnyPaymentProbeCandidate, groups map[string][]SunnyProxy) sunnyPaymentAccountProbe {
	return s.probeSunnyPaymentAccountModeContext(context.Background(), candidate, groups, sunnyPaymentProbeModeMethods)
}

func (s *Server) probeSunnyPaymentAccountContext(ctx context.Context, candidate sunnyPaymentProbeCandidate, groups map[string][]SunnyProxy) sunnyPaymentAccountProbe {
	return s.probeSunnyPaymentAccountModeContext(ctx, candidate, groups, sunnyPaymentProbeModeMethods)
}

func (s *Server) probeSunnyPaymentAccountModeContext(ctx context.Context, candidate sunnyPaymentProbeCandidate, groups map[string][]SunnyProxy, mode string) sunnyPaymentAccountProbe {
	return s.probeSunnyPaymentAccountModeProgressContext(ctx, candidate, groups, mode, nil)
}

func (s *Server) probeSunnyPaymentAccountModeProgressContext(ctx context.Context, candidate sunnyPaymentProbeCandidate, groups map[string][]SunnyProxy, mode string, onAttempt func(country string, current, total int)) sunnyPaymentAccountProbe {
	result := sunnyPaymentAccountProbe{Candidate: candidate, Countries: map[string]any{}}
	if candidate.SkipReason != "" || candidate.Error != "" {
		return result
	}
	countries := make([]string, 0, len(groups))
	for country := range groups {
		countries = append(countries, country)
	}
	sort.Strings(countries)
	probes := streamSunnyWorkerPoolContext(ctx, countries, s.sunnyPaymentCountryConcurrency(), func(country string) sunnyPaymentCountryProbe {
		return s.probeSunnyPaymentCountryModeProgressContext(ctx, candidate, country, groups[country], mode, func(current, total int) {
			if onAttempt != nil {
				onAttempt(country, current, total)
			}
		})
	})
	allMethods := []string{}
	for probe := range probes {
		result.TrafficBytes += probe.TrafficBytes
		detail := map[string]any{"kind": probe.Kind, "methods": probe.Methods, "proxy_id": probe.ProxyID, "attempts": probe.Attempts, "http": probe.HTTP}
		if probe.Amount != nil {
			detail["amount"] = *probe.Amount
		}
		if probe.Currency != "" {
			detail["currency"] = probe.Currency
		}
		if normalizeSunnyPaymentProbeMode(mode) == sunnyPaymentProbeModeMomoPromo {
			detail["momo_discounted"] = probe.MomoDiscounted
			detail["status"] = sunnyMomoPromoStatus(probe.Methods, probe.Amount, probe.Currency)
		}
		if probe.Error != "" {
			detail["error"] = probe.Error
			result.Errors = append(result.Errors, probe.Country+": "+probe.Error)
		} else {
			result.Succeeded++
			allMethods = append(allMethods, probe.Methods...)
		}
		result.InvalidToken = result.InvalidToken || probe.InvalidToken
		result.Countries[probe.Country] = detail
	}
	sort.Strings(result.Errors)
	result.Methods = normalizeSunnyPaymentMethods(allMethods)
	return result
}

func mergeSunnyPaymentProbeResults(existingJSON string, current map[string]any) (map[string]any, []string) {
	merged := jsonMap(existingJSON)
	for country, currentValue := range current {
		currentDetail, ok := currentValue.(map[string]any)
		if !ok {
			currentDetail = map[string]any{}
		}
		if text(currentDetail["error"]) != "" {
			if existingDetail, ok := merged[country].(map[string]any); ok {
				preserved := make(map[string]any, len(existingDetail)+len(currentDetail))
				for key, value := range existingDetail {
					preserved[key] = value
				}
				for key, value := range currentDetail {
					if key == "methods" {
						continue
					}
					preserved[key] = value
				}
				currentDetail = preserved
			}
		}
		merged[country] = currentDetail
	}
	methods := []string{}
	for _, value := range merged {
		detail, ok := value.(map[string]any)
		if !ok {
			continue
		}
		methods = append(methods, stringSlice(detail["methods"])...)
	}
	return merged, normalizeSunnyPaymentMethods(methods)
}

func sunnyPaymentProbeCheckoutKind(countries map[string]any) string {
	for _, country := range sunnyPaymentProbeCountryListFromResults(countries) {
		detail, _ := countries[country].(map[string]any)
		if kind := normalizeSunnyCheckoutKind(text(detail["kind"])); kind != sunnyCheckoutUnknown {
			return kind
		}
	}
	return sunnyCheckoutUnknown
}

func sunnyPaymentProbeCountryListFromResults(results map[string]any) []string {
	countries := make([]string, 0, len(results))
	for country := range results {
		countries = append(countries, country)
	}
	sort.Strings(countries)
	return countries
}

func (s *Server) executeSunnyPaymentProbeTask(task *Task, payload map[string]any) {
	task.Status = TaskRunning
	task.StartedAt = sql.NullTime{Time: time.Now(), Valid: true}
	s.db.Save(task)
	ctx, cancel := s.taskCancellationContext(task)
	defer cancel()
	candidates, err := s.sunnyPaymentProbeCandidates(uintSlice(payload["session_ids"]))
	if err != nil {
		s.failSunnyPaymentProbeTask(task, err.Error())
		return
	}
	groups, err := s.sunnyPaymentProxyGroups()
	if err != nil {
		s.failSunnyPaymentProbeTask(task, err.Error())
		return
	}
	rawCountries, exists := payload["countries"]
	if !exists {
		s.failSunnyPaymentProbeTask(task, "请至少选择一个支付探测国家")
		return
	}
	requestedCountries := stringSlice(rawCountries)
	groups, _, err = selectSunnyPaymentProxyGroups(groups, requestedCountries)
	if err != nil {
		s.failSunnyPaymentProbeTask(task, err.Error())
		return
	}
	mode := normalizeSunnyPaymentProbeMode(text(payload["mode"]))
	selectedCountries := sunnyPaymentProbeCountryList(groups)
	probeLabel := "支付方式"
	if mode == sunnyPaymentProbeModeMomoPromo {
		probeLabel = "0元 MoMo"
	}
	s.appendTaskEvent(task.ID,
		fmt.Sprintf("账户%s探测开始：账户 %d 个，国家 %d 个（%s）", probeLabel, len(candidates), len(selectedCountries), strings.Join(selectedCountries, ", ")),
		"log", "info", map[string]any{
			"scope": "global", "progress_type": "payment_probe", "current": 0, "total": len(candidates),
			"countries": selectedCountries,
		})
	skipped := map[uint]bool{}
	for _, id := range uintSlice(payload["skip_session_ids"]) {
		skipped[id] = true
	}
	for index := range candidates {
		if skipped[candidates[index].SessionID] {
			candidates[index].SkipReason = "已有支付方式探测任务正在执行，已跳过"
		}
	}
	result := map[string]any{"requested": len(candidates), "detected": 0, "partial": 0, "skipped": 0, "failed": 0, "items": []any{}}
	items := make([]any, 0, len(candidates))
	outcomes := streamSunnyWorkerPoolContext(ctx, candidates, s.sunnyPaymentProbeConcurrency(), func(candidate sunnyPaymentProbeCandidate) sunnyPaymentAccountProbe {
		return s.probeSunnyPaymentAccountModeProgressContext(ctx, candidate, groups, mode, func(country string, current, total int) {
			if mode != sunnyPaymentProbeModeMomoPromo {
				return
			}
			s.appendAccountTaskEvent(task.ID, candidate.Email, "payment", "payment_probe.attempt",
				fmt.Sprintf("[%s] [0元 MoMo探测] %s 正在尝试代理 %d/%d", candidate.Email, country, current, total), "info",
				map[string]any{"session_id": candidate.SessionID, "country": country, "current": current, "total": total})
		})
	})
	for outcome := range outcomes {
		if ctx.Err() != nil {
			break
		}
		now := time.Now()
		item := map[string]any{"session_id": outcome.Candidate.SessionID, "email": outcome.Candidate.Email, "payment_methods": outcome.Methods, "countries": outcome.Countries, "proxy_traffic_bytes": outcome.TrafficBytes}
		s.recordSunnyProxyTraffic(outcome.Candidate.Email, outcome.TrafficBytes)
		if outcome.Candidate.SkipReason == "" && outcome.Candidate.Error == "" {
			countries := make([]string, 0, len(outcome.Countries))
			for country := range outcome.Countries {
				countries = append(countries, country)
			}
			sort.Strings(countries)
			for _, country := range countries {
				detail, _ := outcome.Countries[country].(map[string]any)
				methods := stringSlice(detail["methods"])
				errorText := text(detail["error"])
				level := "info"
				message := fmt.Sprintf("[%s] [%s探测] %s 探测完成：%s（HTTP %d，代理 #%d，尝试 %d 次）", outcome.Candidate.Email, probeLabel, country, fallback(strings.Join(methods, ", "), "未识别支付方式"), intValue(detail["http"], 0), intValue(detail["proxy_id"], 0), intValue(detail["attempts"], 0))
				if errorText != "" {
					level = "warning"
					message = fmt.Sprintf("[%s] [%s探测] %s 探测失败：%s（代理 #%d，尝试 %d 次）", outcome.Candidate.Email, probeLabel, country, errorText, intValue(detail["proxy_id"], 0), intValue(detail["attempts"], 0))
				}
				s.appendAccountTaskEvent(task.ID, outcome.Candidate.Email, "payment", "payment_probe.country", message, level, map[string]any{
					"session_id": outcome.Candidate.SessionID, "country": country, "methods": methods,
					"http": detail["http"], "proxy_id": detail["proxy_id"], "attempts": detail["attempts"], "error": errorText,
				})
			}
		}
		switch {
		case outcome.Candidate.SkipReason != "":
			result["skipped"] = result["skipped"].(int) + 1
			item["status"], item["message"] = "skipped", outcome.Candidate.SkipReason
		case outcome.Candidate.Error != "":
			result["failed"] = result["failed"].(int) + 1
			item["status"], item["error"] = "failed", outcome.Candidate.Error
		case outcome.Succeeded == 0:
			message := strings.Join(outcome.Errors, "; ")
			result["failed"] = result["failed"].(int) + 1
			item["status"], item["error"] = "failed", message
			var account SunnyAccount
			if queryErr := s.db.Where("email = ?", outcome.Candidate.Email).First(&account).Error; queryErr == nil {
				if mode == sunnyPaymentProbeModeMomoPromo {
					s.db.Model(&SunnyAccount{}).Where("id = ?", account.ID).Updates(map[string]any{"momo_promo_status": "unknown", "momo_promo_result_json": dumpJSON(outcome.Countries), "momo_promo_error": message})
				} else {
					mergedCountries, mergedMethods := mergeSunnyPaymentProbeResults(account.PaymentProbeResultsJSON, outcome.Countries)
					item["payment_methods"] = mergedMethods
					s.db.Model(&SunnyAccount{}).Where("id = ?", account.ID).Updates(map[string]any{"payment_methods_json": dumpJSON(mergedMethods), "payment_probe_methods_json": dumpJSON(mergedMethods), "payment_probe_results_json": dumpJSON(mergedCountries), "payment_probe_error": message})
				}
			}
		default:
			message := strings.Join(outcome.Errors, "; ")
			status := "detected"
			if message != "" {
				status = "partial"
				result["partial"] = result["partial"].(int) + 1
			} else {
				result["detected"] = result["detected"].(int) + 1
			}
			item["status"] = status
			if message != "" {
				item["error"] = message
			}
			var account SunnyAccount
			queryErr := s.db.Where("email = ?", outcome.Candidate.Email).First(&account).Error
			mergedCountries, mergedMethods := mergeSunnyPaymentProbeResults(account.PaymentProbeResultsJSON, outcome.Countries)
			if mode == sunnyPaymentProbeModeMomoPromo {
				item["payment_methods"] = outcome.Methods
			} else {
				item["payment_methods"] = mergedMethods
			}
			updates := map[string]any{}
			checkoutKind := sunnyPaymentProbeCheckoutKind(outcome.Countries)
			if checkoutKind != sunnyCheckoutUnknown {
				updates["checkout_kind"] = checkoutKind
				updates["commerce_check_error"] = ""
				updates["commerce_checked_at"] = now
			}
			if mode == sunnyPaymentProbeModeMomoPromo {
				detail, _ := outcome.Countries["VN"].(map[string]any)
				promoStatus := text(detail["status"])
				if promoStatus == "" {
					promoStatus = "unsupported"
				}
				item["momo_promo_status"] = promoStatus
				updates["momo_promo_status"] = promoStatus
				updates["momo_promo_result_json"] = dumpJSON(detail)
				updates["momo_promo_error"] = message
				updates["momo_promo_probed_at"] = now
			} else {
				updates["payment_methods_json"] = dumpJSON(mergedMethods)
				updates["payment_probe_methods_json"] = dumpJSON(mergedMethods)
				updates["payment_probe_results_json"] = dumpJSON(mergedCountries)
				updates["payment_probe_error"] = message
				updates["payment_probed_at"] = now
			}
			updateErr := queryErr
			if updateErr == nil {
				updateErr = s.db.Model(&SunnyAccount{}).Where("id = ?", account.ID).Updates(updates).Error
			}
			if updateErr != nil {
				result[status] = result[status].(int) - 1
				result["failed"] = result["failed"].(int) + 1
				item["status"], item["error"] = "failed", updateErr.Error()
			}
		}
		if outcome.InvalidToken {
			errorMessage := fallback(strings.Join(outcome.Errors, "; "), "Access Token 无效或已过期")
			s.db.Model(&SunnySession{}).Where("id = ?", outcome.Candidate.SessionID).Updates(map[string]any{"access_token_status": "invalid", "access_token_error": errorMessage, "access_token_checked_at": now})
		}
		items = append(items, item)
		task.ProgressCurrent++
		s.persistTaskProgress(task, intValue(result["detected"], 0)+intValue(result["partial"], 0), intValue(result["failed"], 0), now)
		status := text(item["status"])
		progressMessage := fmt.Sprintf("[%s] [%s探测] 账户任务完成：%d/%d，结果=%s，支付方式=%s", outcome.Candidate.Email, probeLabel, task.ProgressCurrent, task.ProgressTotal, status, fallback(strings.Join(outcome.Methods, ", "), "-"))
		progressLevel := "info"
		if status == "failed" {
			progressLevel = "error"
		}
		s.appendAccountTaskEvent(task.ID, outcome.Candidate.Email, "payment", "payment_probe.completed", progressMessage, progressLevel, map[string]any{
			"session_id": outcome.Candidate.SessionID, "status": status, "current": task.ProgressCurrent, "total": task.ProgressTotal, "methods": outcome.Methods,
		})
	}
	result["items"] = items
	if s.finishCancelledTask(task, result, "用户已停止支付探测任务") {
		return
	}
	task.Status = TaskSucceeded
	task.SuccessCount = intValue(result["detected"], 0) + intValue(result["partial"], 0)
	task.ErrorCount = intValue(result["failed"], 0)
	task.ResultJSON = dumpJSON(result)
	task.FinishedAt = sql.NullTime{Time: time.Now(), Valid: true}
	s.db.Save(task)
	s.appendTaskEvent(task.ID, "账户"+probeLabel+"探测任务完成", "log", "info", result)
}

func (s *Server) failSunnyPaymentProbeTask(task *Task, message string) {
	task.Status = TaskFailed
	task.Error = message
	task.ErrorCount = task.ProgressTotal
	task.ResultJSON = dumpJSON(map[string]any{"requested": task.ProgressTotal, "detected": 0, "partial": 0, "skipped": 0, "failed": task.ProgressTotal})
	task.FinishedAt = sql.NullTime{Time: time.Now(), Valid: true}
	s.db.Save(task)
	s.appendTaskEvent(task.ID, message, "log", "error", nil)
}
