package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

const (
	sunnyTrialTaskType   = "sunny_account_trial_check"
	sunnyTrialUnknown    = "unknown"
	sunnyTrialEligible   = "eligible"
	sunnyTrialIneligible = "ineligible"
	sunnyCheckoutUnknown = "unknown"
)

var (
	sunnyTrialCheckEndpoint    = "https://chatgpt.com/backend-api/promo_campaign/check_coupon?coupon=plus-1-month-free&is_coupon_from_query_param=true"
	sunnyCheckoutEndpoint      = "https://chatgpt.com/backend-api/payments/checkout"
	sunnyCheckTrialOnly        = checkSunnyTrialOnly
	sunnyCheckTrialEligibility = func(ctx context.Context, accessToken string) (bool, string, bool, error) {
		proxyURL, _ := ctx.Value(sunnyTrialProxyContextKey{}).(string)
		return checkSunnyTrialEligibility(ctx, accessToken, proxyURL)
	}
	sunnyCheckCommerce = func(ctx context.Context, accessToken string) sunnyCommerceProbeResult {
		promotionProxyURL, _ := ctx.Value(sunnyTrialProxyContextKey{}).(string)
		checkoutProxyURL, _ := ctx.Value(sunnyCheckoutProxyContextKey{}).(string)
		result := checkSunnyCommerce(ctx, accessToken, promotionProxyURL, checkoutProxyURL)
		if result.Eligibility != sunnyTrialUnknown || result.TrialError != "" {
			return result
		}
		eligible, message, invalid, err := sunnyCheckTrialEligibility(ctx, accessToken)
		if err == nil {
			if eligible {
				result.Eligibility = sunnyTrialEligible
				result.TrialState = sunnyTrialEligible
			} else {
				result.Eligibility = sunnyTrialIneligible
				result.TrialState = sunnyTrialIneligible
			}
			result.TrialMessage = message
		} else {
			result.Eligibility = sunnyTrialUnknown
			result.TrialState = ""
			result.TrialError = err.Error()
		}
		result.InvalidToken = result.InvalidToken || invalid
		return result
	}
)

type sunnyTrialProxyContextKey struct{}
type sunnyCheckoutProxyContextKey struct{}

type sunnyTrialCandidate struct {
	SessionID   uint
	AccountID   uint
	MailboxID   uint
	Email       string
	AccessToken string
	SkipReason  string
	Error       string
}

type sunnyTrialResult struct {
	SessionID      uint
	AccountID      uint
	Email          string
	Eligibility    string
	TrialState     string
	Message        string
	TrialError     string
	CheckoutKind   string
	PaymentMethods []string
	CheckoutError  string
	SkipReason     string
	InvalidToken   bool
	Retried        bool
	CountryResults map[string]string
	Error          string
	TrafficBytes   int64
}

type sunnyCommerceProbeResult struct {
	Eligibility    string
	TrialState     string
	TrialMessage   string
	CheckoutKind   string
	PaymentMethods []string
	TrialError     string
	CheckoutError  string
	InvalidToken   bool
	TrafficBytes   int64
}

func normalizeSunnyTrialEligibility(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case sunnyTrialEligible, "true", "yes", "有0元试用", "有试用资格":
		return sunnyTrialEligible
	case sunnyTrialIneligible, "false", "no", "无0元试用", "无试用资格":
		return sunnyTrialIneligible
	default:
		return sunnyTrialUnknown
	}
}

func normalizeSunnyTrialFilter(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return ""
	}
	if value == sunnyTrialUnknown {
		return sunnyTrialUnknown
	}
	if value = normalizeSunnyTrialEligibility(value); value == sunnyTrialEligible || value == sunnyTrialIneligible {
		return value
	}
	return ""
}

func sunnyTrialEligibilityFor(accountValue, mailboxValue string) string {
	if value := normalizeSunnyTrialEligibility(accountValue); value != sunnyTrialUnknown {
		return value
	}
	return normalizeSunnyTrialEligibility(mailboxValue)
}

func sunnyManualTrialCheckedAt(eligibility string) *time.Time {
	if normalizeSunnyTrialEligibility(eligibility) == sunnyTrialUnknown {
		return nil
	}
	now := time.Now()
	return &now
}

func sunnyTrialApplies(status, plan string) bool {
	return normalizeSunnyDisplayStatus(status) == "已注册" && normalizeSunnyPlanType(plan) == "free"
}

func sunnyCommerceHTTPClient(proxyURLs ...string) *http.Client {
	return sunnyCommerceHTTPClientWithMeter(nil, proxyURLs...)
}

func sunnyCommerceHTTPClientWithMeter(meter *sunnyTrafficMeter, proxyURLs ...string) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if len(proxyURLs) > 0 {
		proxyText := strings.TrimSpace(proxyURLs[0])
		if proxyText != "" {
			if proxy, parseErr := url.Parse(proxyText); parseErr == nil && proxy.Scheme != "" && proxy.Host != "" {
				transport.Proxy = http.ProxyURL(proxy)
			}
		}
	}
	var roundTripper http.RoundTripper = transport
	if meter != nil {
		roundTripper = &sunnyTrafficTransport{base: transport, meter: meter}
	}
	return &http.Client{Timeout: 45 * time.Second, Transport: roundTripper}
}

func sunnyCommerceHeaders(req *http.Request, accessToken string) {
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(accessToken))
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("OAI-Language", "en-US")
	req.Header.Set("Referer", "https://chatgpt.com/")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/136.0.0.0 Safari/537.36")
}

func readSunnyCommerceResponse(resp *http.Response) (map[string]any, []byte, error) {
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	if err != nil {
		return nil, nil, err
	}
	payload := map[string]any{}
	if len(bytes.TrimSpace(raw)) > 0 {
		if err := json.Unmarshal(raw, &payload); err != nil {
			return nil, raw, fmt.Errorf("响应不是有效 JSON")
		}
	}
	return payload, raw, nil
}

func sunnyCommerceErrorMessage(payload map[string]any, raw []byte) string {
	if message := firstText(text(payload["message"]), text(payload["detail"])); message != "" {
		return message
	}
	if value, ok := payload["error"].(map[string]any); ok {
		if message := firstText(text(value["message"]), text(value["detail"])); message != "" {
			return message
		}
	}
	message := strings.TrimSpace(string(raw))
	if len(message) > 240 {
		message = message[:240]
	}
	return message
}

func probeSunnyTrial(ctx context.Context, client *http.Client, accessToken string) (string, string, string, bool, error) {
	method := http.MethodGet
	var body io.Reader
	if strings.HasPrefix(strings.TrimSpace(sunnyTrialCheckEndpoint), "http://127.0.0.1:") || strings.HasPrefix(strings.TrimSpace(sunnyTrialCheckEndpoint), "http://localhost:") {
		method = http.MethodPost
		payload, _ := json.Marshal(map[string]string{"access_token": strings.TrimSpace(accessToken)})
		body = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, sunnyTrialCheckEndpoint, body)
	if err != nil {
		return sunnyTrialUnknown, "", "", false, err
	}
	sunnyCommerceHeaders(req, accessToken)
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return sunnyTrialUnknown, "", "", false, fmt.Errorf("连接 ChatGPT 试用接口失败: %w", err)
	}
	defer resp.Body.Close()
	payload, raw, err := readSunnyCommerceResponse(resp)
	if err != nil {
		return sunnyTrialUnknown, "", "", false, fmt.Errorf("读取 ChatGPT 试用接口失败: %w", err)
	}
	message := sunnyCommerceErrorMessage(payload, raw)
	if resp.StatusCode == http.StatusUnauthorized {
		return sunnyTrialUnknown, "", message, true, fmt.Errorf("%s", fallback(message, "Access Token 无效或已过期"))
	}
	if resp.StatusCode != http.StatusOK {
		return sunnyTrialUnknown, "", message, false, fmt.Errorf("ChatGPT 试用接口返回 HTTP %d: %s", resp.StatusCode, fallback(message, "无法确认试用资格"))
	}
	state := strings.ToLower(strings.TrimSpace(text(payload["state"])))
	if eligible, ok := payload["eligible"].(bool); ok {
		if eligible {
			state = "eligible"
		} else {
			state = "ineligible"
		}
	}
	switch state {
	case "eligible":
		return sunnyTrialEligible, state, fallback(message, "该账户有 ChatGPT Plus 0 元试用资格"), false, nil
	case "not_eligible", "ineligible":
		return sunnyTrialIneligible, state, fallback(message, "该账户没有 ChatGPT Plus 0 元试用资格"), false, nil
	default:
		return sunnyTrialUnknown, state, message, false, fmt.Errorf("ChatGPT 试用接口返回未确认状态 %q", fallback(state, "empty"))
	}
}

func sunnyCheckoutBilling() (string, string) {
	country := strings.ToUpper(strings.TrimSpace(os.Getenv("SUNNY_CHECKOUT_COUNTRY")))
	if country == "" {
		country = "US"
	}
	currency := strings.ToUpper(strings.TrimSpace(os.Getenv("SUNNY_CHECKOUT_CURRENCY")))
	if currency == "" {
		currency = map[string]string{"DE": "EUR", "JP": "JPY", "GB": "GBP"}[country]
		if currency == "" {
			currency = "USD"
		}
	}
	return country, currency
}

func sunnyFindStringByKeys(value any, keys map[string]bool) string {
	switch node := value.(type) {
	case map[string]any:
		for key, child := range node {
			if keys[strings.ToLower(strings.TrimSpace(key))] {
				if result := strings.TrimSpace(text(child)); result != "" {
					return result
				}
			}
		}
		for _, child := range node {
			if result := sunnyFindStringByKeys(child, keys); result != "" {
				return result
			}
		}
	case []any:
		for _, child := range node {
			if result := sunnyFindStringByKeys(child, keys); result != "" {
				return result
			}
		}
	}
	return ""
}

func sunnyCheckoutSessionID(payload map[string]any) string {
	for _, key := range []string{"checkout_session_id", "session_id", "id"} {
		if value := strings.TrimSpace(text(payload[key])); value != "" {
			return value
		}
	}
	return sunnyFindStringByKeys(payload, map[string]bool{"checkout_session_id": true, "session_id": true})
}

func sunnyAppendPaymentMethods(value any, methods *[]string, seen map[string]bool) {
	appendMethod := func(raw string) {
		method := strings.ToLower(strings.TrimSpace(raw))
		if method == "" || seen[method] || len(method) > 64 {
			return
		}
		seen[method] = true
		*methods = append(*methods, method)
	}
	switch node := value.(type) {
	case string:
		appendMethod(node)
	case []any:
		for _, child := range node {
			sunnyAppendPaymentMethods(child, methods, seen)
		}
	case map[string]any:
		appendMethod(firstText(text(node["type"]), text(node["id"]), text(node["name"])))
	}
}

func sunnyPaymentMethods(value any) []string {
	methods := []string{}
	seen := map[string]bool{}
	var walk func(any)
	walk = func(node any) {
		switch current := node.(type) {
		case map[string]any:
			for key, child := range current {
				normalized := strings.ToLower(strings.TrimSpace(key))
				if normalized == "payment_method_types" || normalized == "custom_payment_methods" || normalized == "payment_methods" || normalized == "available_payment_methods" {
					sunnyAppendPaymentMethods(child, &methods, seen)
				}
				walk(child)
			}
		case []any:
			for _, child := range current {
				walk(child)
			}
		}
	}
	walk(value)
	return methods
}

func probeSunnyCheckout(ctx context.Context, client *http.Client, accessToken string) (string, []string, bool, error) {
	country, currency := sunnyCheckoutBilling()
	return probeSunnyCheckoutForCountry(ctx, client, accessToken, country, currency)
}

func probeSunnyCheckoutForCountry(ctx context.Context, client *http.Client, accessToken, country, currency string) (string, []string, bool, error) {
	country = strings.ToUpper(strings.TrimSpace(country))
	currency = strings.ToUpper(strings.TrimSpace(currency))
	body, err := json.Marshal(map[string]any{
		"entry_point":      "all_plans_pricing_modal",
		"plan_name":        "chatgptplusplan",
		"billing_details":  map[string]string{"country": country, "currency": currency},
		"cancel_url":       "https://chatgpt.com/",
		"checkout_ui_mode": "custom",
		"check_card_proxy": true,
	})
	if err != nil {
		return sunnyCheckoutUnknown, nil, false, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, sunnyCheckoutEndpoint, bytes.NewReader(body))
	if err != nil {
		return sunnyCheckoutUnknown, nil, false, err
	}
	sunnyCommerceHeaders(req, accessToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-OpenAI-Target-Path", "/backend-api/payments/checkout")
	req.Header.Set("X-OpenAI-Target-Route", "/backend-api/payments/checkout")
	resp, err := client.Do(req)
	if err != nil {
		return sunnyCheckoutUnknown, nil, false, fmt.Errorf("连接 ChatGPT Checkout 接口失败: %w", err)
	}
	defer resp.Body.Close()
	payload, raw, err := readSunnyCommerceResponse(resp)
	if err != nil {
		return sunnyCheckoutUnknown, nil, false, fmt.Errorf("读取 ChatGPT Checkout 接口失败: %w", err)
	}
	message := sunnyCommerceErrorMessage(payload, raw)
	if resp.StatusCode == http.StatusUnauthorized {
		return sunnyCheckoutUnknown, nil, true, fmt.Errorf("%s", fallback(message, "Access Token 无效或已过期"))
	}
	if resp.StatusCode != http.StatusOK {
		return sunnyCheckoutUnknown, nil, false, fmt.Errorf("ChatGPT Checkout 接口返回 HTTP %d: %s", resp.StatusCode, fallback(message, "无法创建 Checkout"))
	}
	sessionID := sunnyCheckoutSessionID(payload)
	kind := sunnyCheckoutUnknown
	switch {
	case strings.HasPrefix(sessionID, "oaics_"):
		kind = "oaics"
	case strings.HasPrefix(sessionID, "cs_live_"):
		kind = "cs_live"
	case strings.HasPrefix(sessionID, "cs_test_"):
		kind = "cs_test"
	}
	if kind == sunnyCheckoutUnknown {
		return kind, sunnyPaymentMethods(payload), false, fmt.Errorf("Checkout 响应未包含可识别的会话类型")
	}
	return kind, sunnyPaymentMethods(payload), false, nil
}

func checkSunnyCommerce(ctx context.Context, accessToken string, proxyURLs ...string) sunnyCommerceProbeResult {
	result := sunnyCommerceProbeResult{Eligibility: sunnyTrialUnknown, CheckoutKind: sunnyCheckoutUnknown, PaymentMethods: []string{}}
	token := strings.TrimSpace(accessToken)
	if token == "" {
		result.TrialError = "账户缺少 Access Token"
		result.CheckoutError = result.TrialError
		return result
	}
	promotionProxyURL := ""
	checkoutProxyURL := ""
	if len(proxyURLs) > 0 {
		promotionProxyURL = strings.TrimSpace(proxyURLs[0])
	}
	if len(proxyURLs) > 1 {
		checkoutProxyURL = strings.TrimSpace(proxyURLs[1])
	}
	if checkoutProxyURL == "" {
		checkoutProxyURL = promotionProxyURL
	}
	if workerResult, ok := probeSunnyCommerceViaWorker(ctx, token, promotionProxyURL, checkoutProxyURL); ok {
		sunnyTrafficMeterFromContext(ctx).addExternal(workerResult.TrafficBytes)
		return workerResult
	}
	client := sunnyCommerceHTTPClientWithMeter(sunnyTrafficMeterFromContext(ctx), checkoutProxyURL)
	checkoutKind, methods, checkoutInvalid, checkoutErr := probeSunnyCheckout(ctx, client, token)
	result.CheckoutKind, result.PaymentMethods = checkoutKind, methods
	result.InvalidToken = result.InvalidToken || checkoutInvalid
	if checkoutErr != nil {
		result.CheckoutError = checkoutErr.Error()
	}
	return result
}

func probeSunnyCommerceViaWorker(ctx context.Context, accessToken, promotionProxyURL string, checkoutProxyURLs ...string) (sunnyCommerceProbeResult, bool) {
	result := sunnyCommerceProbeResult{Eligibility: sunnyTrialUnknown, CheckoutKind: sunnyCheckoutUnknown, PaymentMethods: []string{}}
	workerURL := strings.TrimRight(strings.TrimSpace(os.Getenv("PYTHON_WORKER_URL")), "/")
	if workerURL == "" {
		workerURL = "http://127.0.0.1:8765"
	}
	country, currency := sunnyCheckoutBilling()
	checkoutProxyURL := promotionProxyURL
	if len(checkoutProxyURLs) > 0 && strings.TrimSpace(checkoutProxyURLs[0]) != "" {
		checkoutProxyURL = strings.TrimSpace(checkoutProxyURLs[0])
	}
	body, _ := json.Marshal(map[string]string{
		"access_token":        accessToken,
		"proxy_url":           promotionProxyURL,
		"promotion_proxy_url": promotionProxyURL,
		"checkout_proxy_url":  checkoutProxyURL,
		"country":             country,
		"currency":            currency,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, workerURL+"/probe-commerce", bytes.NewReader(body))
	if err != nil {
		return result, false
	}
	req.Header.Set("Content-Type", "application/json")
	if token := secretValue("PYTHON_WORKER_TOKEN", "PYTHON_WORKER_TOKEN_FILE"); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := (&http.Client{Timeout: 90 * time.Second}).Do(req)
	if err != nil {
		return result, false
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	if err != nil || resp.StatusCode == http.StatusNotFound || resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return result, false
	}
	var payload struct {
		Trial struct {
			State string `json:"state"`
			HTTP  int    `json:"http"`
			Error string `json:"error"`
		} `json:"trial"`
		Checkout struct {
			Kind           string   `json:"kind"`
			PaymentMethods []string `json:"payment_methods"`
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
	result.TrialState = strings.ToLower(strings.TrimSpace(payload.Trial.State))
	switch result.TrialState {
	case "eligible":
		result.Eligibility = sunnyTrialEligible
	case "not_eligible", "ineligible":
		result.Eligibility = sunnyTrialIneligible
	default:
		result.TrialError = fallback(strings.TrimSpace(payload.Trial.Error), fmt.Sprintf("ChatGPT 试用接口返回 HTTP %d，未提供有效状态", payload.Trial.HTTP))
	}
	result.CheckoutKind = normalizeSunnyCheckoutKind(payload.Checkout.Kind)
	result.PaymentMethods = payload.Checkout.PaymentMethods
	if result.CheckoutKind == sunnyCheckoutUnknown {
		result.CheckoutError = fallback(strings.TrimSpace(payload.Checkout.Error), fmt.Sprintf("ChatGPT Checkout 接口返回 HTTP %d，未提供可识别类型", payload.Checkout.HTTP))
	}
	result.InvalidToken = payload.Trial.HTTP == http.StatusUnauthorized || payload.Checkout.HTTP == http.StatusUnauthorized
	result.TrafficBytes = payload.Traffic.TotalBytes
	return result, true
}

func probeSunnyTrialViaWorker(ctx context.Context, accessToken, proxyURL string) (sunnyCommerceProbeResult, bool) {
	result := sunnyCommerceProbeResult{Eligibility: sunnyTrialUnknown, CheckoutKind: sunnyCheckoutUnknown, PaymentMethods: []string{}}
	workerURL := strings.TrimRight(strings.TrimSpace(os.Getenv("PYTHON_WORKER_URL")), "/")
	if workerURL == "" {
		workerURL = "http://127.0.0.1:8765"
	}
	body, _ := json.Marshal(map[string]string{"access_token": accessToken, "proxy_url": proxyURL})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, workerURL+"/probe-trial", bytes.NewReader(body))
	if err != nil {
		return result, false
	}
	req.Header.Set("Content-Type", "application/json")
	if token := secretValue("PYTHON_WORKER_TOKEN", "PYTHON_WORKER_TOKEN_FILE"); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := (&http.Client{Timeout: 70 * time.Second}).Do(req)
	if err != nil {
		return result, false
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	if err != nil || resp.StatusCode == http.StatusNotFound || resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return result, false
	}
	var payload struct {
		Trial struct {
			State string `json:"state"`
			HTTP  int    `json:"http"`
			Error string `json:"error"`
		} `json:"trial"`
		Traffic struct {
			TotalBytes int64 `json:"total_bytes"`
		} `json:"traffic"`
	}
	if json.Unmarshal(raw, &payload) != nil {
		return result, false
	}
	result.TrialState = strings.ToLower(strings.TrimSpace(payload.Trial.State))
	switch result.TrialState {
	case sunnyTrialEligible:
		result.Eligibility = sunnyTrialEligible
		result.TrialMessage = "该账户有 ChatGPT Plus 0 元试用资格"
	case "not_eligible", sunnyTrialIneligible:
		result.Eligibility = sunnyTrialIneligible
		result.TrialMessage = "该账户没有 ChatGPT Plus 0 元试用资格"
	default:
		result.TrialError = fallback(strings.TrimSpace(payload.Trial.Error), fmt.Sprintf("ChatGPT 试用接口返回 HTTP %d，未提供有效状态", payload.Trial.HTTP))
	}
	result.InvalidToken = payload.Trial.HTTP == http.StatusUnauthorized
	result.TrafficBytes = payload.Traffic.TotalBytes
	return result, true
}

func checkSunnyTrialOnly(ctx context.Context, accessToken string) sunnyCommerceProbeResult {
	result := sunnyCommerceProbeResult{Eligibility: sunnyTrialUnknown, CheckoutKind: sunnyCheckoutUnknown, PaymentMethods: []string{}}
	token := strings.TrimSpace(accessToken)
	if token == "" {
		result.TrialError = "账户缺少 Access Token"
		return result
	}
	proxyURL, _ := ctx.Value(sunnyTrialProxyContextKey{}).(string)
	if workerResult, ok := probeSunnyTrialViaWorker(ctx, token, proxyURL); ok {
		sunnyTrafficMeterFromContext(ctx).addExternal(workerResult.TrafficBytes)
		return workerResult
	}
	client := sunnyCommerceHTTPClientWithMeter(sunnyTrafficMeterFromContext(ctx), proxyURL)
	eligibility, state, message, invalid, err := probeSunnyTrial(ctx, client, token)
	result.Eligibility, result.TrialState, result.TrialMessage, result.InvalidToken = eligibility, state, message, invalid
	if err != nil {
		result.TrialError = err.Error()
	}
	return result
}

func checkSunnyTrialEligibility(ctx context.Context, accessToken string, proxyURLs ...string) (bool, string, bool, error) {
	client := sunnyCommerceHTTPClientWithMeter(sunnyTrafficMeterFromContext(ctx), proxyURLs...)
	eligibility, _, message, invalid, err := probeSunnyTrial(ctx, client, accessToken)
	return eligibility == sunnyTrialEligible, message, invalid, err
}

func (s *Server) sunnyTrialConcurrency() int {
	return s.sunnyConfiguredConcurrency("trial_concurrency", "SUNNY_TRIAL_CONCURRENCY", 16)
}

func sunnyCommerceProbeNeedsRetry(result sunnyCommerceProbeResult) bool {
	if result.InvalidToken {
		return false
	}
	return normalizeSunnyTrialEligibility(result.Eligibility) == sunnyTrialUnknown || normalizeSunnyCheckoutKind(result.CheckoutKind) == sunnyCheckoutUnknown
}

func mergeSunnyCommerceProbeResults(initial, retried sunnyCommerceProbeResult) sunnyCommerceProbeResult {
	merged := retried
	if normalizeSunnyTrialEligibility(retried.Eligibility) == sunnyTrialUnknown {
		if normalizeSunnyTrialEligibility(initial.Eligibility) != sunnyTrialUnknown {
			merged.Eligibility = initial.Eligibility
			merged.TrialState = initial.TrialState
			merged.TrialMessage = initial.TrialMessage
			merged.TrialError = initial.TrialError
		} else if strings.TrimSpace(merged.TrialError) == "" {
			merged.TrialError = initial.TrialError
		}
	}
	if normalizeSunnyCheckoutKind(retried.CheckoutKind) == sunnyCheckoutUnknown {
		if normalizeSunnyCheckoutKind(initial.CheckoutKind) != sunnyCheckoutUnknown {
			merged.CheckoutKind = initial.CheckoutKind
			merged.PaymentMethods = initial.PaymentMethods
			merged.CheckoutError = initial.CheckoutError
		} else if strings.TrimSpace(merged.CheckoutError) == "" {
			merged.CheckoutError = initial.CheckoutError
		}
	}
	merged.InvalidToken = initial.InvalidToken || retried.InvalidToken
	return merged
}

func checkSunnyCommerceWithRetry(ctx context.Context, accessToken string) (sunnyCommerceProbeResult, bool) {
	initial := sunnyCheckCommerce(ctx, accessToken)
	if !sunnyCommerceProbeNeedsRetry(initial) {
		return initial, false
	}
	retried := sunnyCheckCommerce(ctx, accessToken)
	return mergeSunnyCommerceProbeResults(initial, retried), true
}

func checkSunnyTrialWithRetry(ctx context.Context, accessToken string) (sunnyCommerceProbeResult, bool) {
	initial := sunnyCheckTrialOnly(ctx, accessToken)
	if initial.InvalidToken || normalizeSunnyTrialEligibility(initial.Eligibility) != sunnyTrialUnknown {
		return initial, false
	}
	retried := sunnyCheckTrialOnly(ctx, accessToken)
	if normalizeSunnyTrialEligibility(retried.Eligibility) == sunnyTrialUnknown && strings.TrimSpace(retried.TrialError) == "" {
		retried.TrialError = initial.TrialError
	}
	retried.InvalidToken = initial.InvalidToken || retried.InvalidToken
	return retried, true
}

// sunnyCommerceProxyGroups returns the enabled account-detection proxies grouped
// by their validated country code. The country list is intentionally derived
// from the configured pool instead of being hard-coded in the UI or API.
func (s *Server) sunnyCommerceProxyGroups() (map[string][]SunnyProxy, error) {
	var proxies []SunnyProxy
	purposeQuery := "(',' || replace(lower(coalesce(purpose_tags, '')), ' ', '') || ',') LIKE ?"
	if err := s.db.Where("status = ? AND enabled = ?", "enabled", true).
		Where(purposeQuery, "%,"+sunnyProxyPurposeCommerce+",%").Order("id asc").Find(&proxies).Error; err != nil {
		return nil, err
	}
	groups := map[string][]SunnyProxy{}
	for _, proxy := range proxies {
		country, err := normalizeSunnyProxyCountry(proxy.Country)
		if err == nil && normalizeSunnyProxyAddress(proxy.Address) != "" {
			groups[country] = append(groups[country], proxy)
		}
	}
	if len(groups) == 0 {
		return nil, fmt.Errorf("请先为账户检测用途配置至少一个已启用且国家代码有效的代理")
	}
	return groups, nil
}

func sunnyCommerceProxyCountryList(groups map[string][]SunnyProxy) []string {
	countries := make([]string, 0, len(groups))
	for country := range groups {
		countries = append(countries, country)
	}
	sort.Slice(countries, func(i, j int) bool {
		if countries[i] == "JP" {
			return countries[j] != "JP"
		}
		if countries[j] == "JP" {
			return false
		}
		return countries[i] < countries[j]
	})
	return countries
}

func selectSunnyCommerceProxyCountries(groups map[string][]SunnyProxy, requested []string) ([]string, error) {
	if requested == nil {
		return sunnyCommerceProxyCountryList(groups), nil
	}
	seen := map[string]bool{}
	selected := make([]string, 0, len(requested))
	for _, value := range requested {
		country, err := normalizeSunnyProxyCountry(value)
		if err != nil {
			return nil, err
		}
		if seen[country] {
			continue
		}
		if len(groups[country]) == 0 {
			return nil, fmt.Errorf("国家 %s 没有已启用的账户检测代理", country)
		}
		seen[country] = true
		selected = append(selected, country)
	}
	if len(selected) == 0 {
		return nil, fmt.Errorf("请至少选择一个账户检测国家")
	}
	// Keep the same predictable ordering as the country picker, with JP first.
	selectedGroups := map[string][]SunnyProxy{}
	for _, country := range selected {
		selectedGroups[country] = groups[country]
	}
	return sunnyCommerceProxyCountryList(selectedGroups), nil
}

func (s *Server) sunnyCommerceProxyURLForCountries(accountKey string, countries []string) string {
	if len(countries) == 0 {
		return s.sunnyCommerceProxyURL(accountKey)
	}
	groups, err := s.sunnyCommerceProxyGroups()
	if err != nil {
		return ""
	}
	selected, err := selectSunnyCommerceProxyCountries(groups, countries)
	if err != nil || len(selected) == 0 {
		return ""
	}
	hash := fnv.New32a()
	_, _ = hash.Write([]byte(strings.ToLower(strings.TrimSpace(accountKey))))
	country := selected[int(hash.Sum32())%len(selected)]
	proxies := groups[country]
	return normalizeSunnyProxyAddress(proxies[int(hash.Sum32()/uint32(len(selected)))%len(proxies)].Address)
}

func sunnyProxyURLFromCountryGroup(accountKey string, proxies []SunnyProxy) string {
	if len(proxies) == 0 {
		return ""
	}
	hash := fnv.New32a()
	_, _ = hash.Write([]byte(strings.ToLower(strings.TrimSpace(accountKey))))
	return normalizeSunnyProxyAddress(proxies[int(hash.Sum32())%len(proxies)].Address)
}

func (s *Server) sunnyTrialCandidates(ids []uint) ([]sunnyTrialCandidate, error) {
	if len(ids) == 0 {
		return nil, fmt.Errorf("请选择需要检测试用资格的账户")
	}
	var sessions []SunnySession
	if err := s.db.Where("id IN ?", ids).Order("id asc").Find(&sessions).Error; err != nil {
		return nil, err
	}
	accounts, mailboxes := s.sunnySessionSidecars(sessions)
	candidates := make([]sunnyTrialCandidate, 0, len(sessions))
	for _, session := range sessions {
		account := accounts[sunnyEmailKey(session.Email)]
		item := s.serializeSunnySession(session, accounts, mailboxes)
		candidate := sunnyTrialCandidate{
			SessionID:   session.ID,
			AccountID:   firstUint(session.AccountID, account.ID),
			MailboxID:   account.MailboxID,
			Email:       session.Email,
			AccessToken: sunnyPreferredAccessToken(session.AccessToken, sunnyAccessTokenFromSessionJSON(session.SessionJSON), account.AccessToken),
		}
		if candidate.MailboxID == 0 {
			candidate.MailboxID = mailboxes[sunnyEmailKey(session.Email)].ID
		}
		if !sunnyTrialApplies(text(item["status"]), text(item["plan_type"])) {
			candidate.SkipReason = "仅已注册且套餐为 free 的账户支持试用资格检测"
		} else if strings.TrimSpace(candidate.AccessToken) == "" {
			candidate.Error = "账户缺少 Access Token"
		}
		candidates = append(candidates, candidate)
	}
	return candidates, nil
}

func mergeSunnyTrialCountryResults(accountJSON, mailboxJSON string, current map[string]string) (map[string]string, string) {
	merged := sunnyTrialCountryResults(accountJSON, mailboxJSON)
	for country, eligibility := range current {
		country = strings.ToUpper(strings.TrimSpace(country))
		eligibility = normalizeSunnyTrialEligibility(eligibility)
		if country != "" && eligibility != sunnyTrialUnknown {
			merged[country] = eligibility
		}
	}
	overall := sunnyTrialUnknown
	for _, eligibility := range merged {
		if eligibility == sunnyTrialEligible {
			return merged, sunnyTrialEligible
		}
		if eligibility == sunnyTrialIneligible {
			overall = sunnyTrialIneligible
		}
	}
	return merged, overall
}

func (s *Server) persistSunnyTrialSidecars(candidate sunnyTrialCandidate, currentCountryResults map[string]string, accountUpdates, mailboxUpdates map[string]any) (map[string]string, string, error) {
	tx := s.db.Begin()
	if tx.Error != nil {
		return nil, sunnyTrialUnknown, tx.Error
	}
	accountQuery := tx.Model(&SunnyAccount{})
	if candidate.AccountID != 0 {
		accountQuery = accountQuery.Where("id = ?", candidate.AccountID)
	} else {
		accountQuery = accountQuery.Where("lower(trim(email)) = lower(trim(?))", candidate.Email)
	}
	var account SunnyAccount
	if err := accountQuery.First(&account).Error; err != nil {
		tx.Rollback()
		return nil, sunnyTrialUnknown, fmt.Errorf("账户 %s 不存在，试用资格未保存", candidate.Email)
	}
	mailboxQuery := tx.Model(&SunnyMailbox{})
	if candidate.MailboxID != 0 {
		mailboxQuery = mailboxQuery.Where("id = ?", candidate.MailboxID)
	} else {
		mailboxQuery = mailboxQuery.Where("lower(trim(email)) = lower(trim(?))", candidate.Email)
	}
	var mailbox SunnyMailbox
	if err := mailboxQuery.First(&mailbox).Error; err != nil {
		tx.Rollback()
		return nil, sunnyTrialUnknown, fmt.Errorf("邮箱 %s 不存在，试用资格未保存", candidate.Email)
	}
	mergedCountryResults, eligibility := mergeSunnyTrialCountryResults(account.TrialCountryResultsJSON, mailbox.TrialCountryResultsJSON, currentCountryResults)
	countryResultsJSON := dumpJSON(mergedCountryResults)
	accountUpdates["trial_country_results_json"] = countryResultsJSON
	accountUpdates["trial_eligibility"] = eligibility
	mailboxUpdates["trial_country_results_json"] = countryResultsJSON
	mailboxUpdates["trial_eligibility"] = eligibility
	accountResult := tx.Model(&SunnyAccount{}).Where("id = ?", account.ID).Updates(accountUpdates)
	if accountResult.Error != nil {
		tx.Rollback()
		return nil, sunnyTrialUnknown, accountResult.Error
	}
	mailboxResult := tx.Model(&SunnyMailbox{}).Where("id = ?", mailbox.ID).Updates(mailboxUpdates)
	if mailboxResult.Error != nil {
		tx.Rollback()
		return nil, sunnyTrialUnknown, mailboxResult.Error
	}
	if err := tx.Commit().Error; err != nil {
		return nil, sunnyTrialUnknown, err
	}
	return mergedCountryResults, eligibility, nil
}

func (s *Server) activeSunnyTrialSessionIDs() (map[uint]bool, error) {
	var tasks []Task
	if err := s.db.Where("type = ? AND status NOT IN ?", sunnyTrialTaskType, []string{TaskSucceeded, TaskFailed, TaskInterrupted, TaskCancelled}).Find(&tasks).Error; err != nil {
		return nil, err
	}
	active := make(map[uint]bool)
	for _, task := range tasks {
		payload := jsonMap(task.PayloadJSON)
		skipped := make(map[uint]bool)
		for _, sessionID := range uintSlice(payload["skip_session_ids"]) {
			skipped[sessionID] = true
		}
		for _, sessionID := range uintSlice(payload["session_ids"]) {
			if skipped[sessionID] {
				continue
			}
			active[sessionID] = true
		}
	}
	return active, nil
}

func firstUint(values ...uint) uint {
	for _, value := range values {
		if value != 0 {
			return value
		}
	}
	return 0
}

func (s *Server) createSunnyTrialTask(body map[string]any) (Task, error) {
	s.trialCheckMu.Lock()
	defer s.trialCheckMu.Unlock()

	ids := uintSlice(body["session_ids"])
	if len(ids) == 0 {
		return Task{}, fmt.Errorf("请选择需要检测试用资格的账户")
	}
	candidates, err := s.sunnyTrialCandidates(ids)
	if err != nil {
		return Task{}, err
	}
	if len(candidates) == 0 {
		return Task{}, fmt.Errorf("未找到需要检测试用资格的账户")
	}
	rawCountries, exists := body["countries"]
	if !exists {
		return Task{}, fmt.Errorf("请至少选择一个账户检测国家")
	}
	groups, err := s.sunnyCommerceProxyGroups()
	if err != nil {
		return Task{}, err
	}
	requestedCountries, err := selectSunnyCommerceProxyCountries(groups, stringSlice(rawCountries))
	if err != nil {
		return Task{}, err
	}
	active, err := s.activeSunnyTrialSessionIDs()
	if err != nil {
		return Task{}, err
	}
	skipSessionIDs := make([]uint, 0)
	seen := make(map[uint]bool)
	for _, candidate := range candidates {
		if active[candidate.SessionID] && !seen[candidate.SessionID] {
			skipSessionIDs = append(skipSessionIDs, candidate.SessionID)
			seen[candidate.SessionID] = true
		}
	}
	payload := map[string]any{"session_ids": ids, "skip_session_ids": skipSessionIDs, "countries": requestedCountries}
	return s.createTask(sunnyTrialTaskType, "sunny", payload, len(candidates)), nil
}

func (s *Server) executeSunnyTrialTask(task *Task, payload map[string]any) {
	task.Status = TaskRunning
	task.StartedAt = sql.NullTime{Time: time.Now(), Valid: true}
	s.db.Save(task)
	candidates, err := s.sunnyTrialCandidates(uintSlice(payload["session_ids"]))
	if err != nil {
		s.failSunnyTrialTask(task, err.Error())
		return
	}
	rawCountries, exists := payload["countries"]
	if !exists {
		s.failSunnyTrialTask(task, "请至少选择一个账户检测国家")
		return
	}
	trialProxyGroups, err := s.sunnyCommerceProxyGroups()
	if err != nil {
		s.failSunnyTrialTask(task, err.Error())
		return
	}
	trialCountries, err := selectSunnyCommerceProxyCountries(trialProxyGroups, stringSlice(rawCountries))
	if err != nil {
		s.failSunnyTrialTask(task, err.Error())
		return
	}
	skipSessionIDs := make(map[uint]bool)
	for _, sessionID := range uintSlice(payload["skip_session_ids"]) {
		skipSessionIDs[sessionID] = true
	}
	for index := range candidates {
		if skipSessionIDs[candidates[index].SessionID] {
			candidates[index].SkipReason = "已有试用资格检测任务正在执行，已跳过"
		}
	}
	result := map[string]any{"requested": len(candidates), "eligible": 0, "ineligible": 0, "retried": 0, "skipped": 0, "failed": 0, "items": []any{}}
	invalidAccounts := []uint{}
	invalidSessions := []uint{}
	seenAccounts := map[uint]bool{}
	items := make([]any, 0, len(candidates))
	candidateBySession := make(map[uint]sunnyTrialCandidate, len(candidates))
	for _, candidate := range candidates {
		candidateBySession[candidate.SessionID] = candidate
	}
	concurrency := s.sunnyTrialConcurrency()
	results := streamSunnyWorkerPool(candidates, concurrency, func(candidate sunnyTrialCandidate) sunnyTrialResult {
		outcome := sunnyTrialResult{SessionID: candidate.SessionID, AccountID: candidate.AccountID, Email: candidate.Email, SkipReason: candidate.SkipReason, Error: candidate.Error}
		if outcome.SkipReason == "" && outcome.Error == "" {
			meter := &sunnyTrafficMeter{}
			outcome.CountryResults = map[string]string{}
			for _, country := range trialCountries {
				trialCtx := withSunnyTrafficMeter(context.Background(), meter)
				proxyURL := sunnyProxyURLFromCountryGroup(candidate.Email, trialProxyGroups[country])
				trialCtx = context.WithValue(trialCtx, sunnyTrialProxyContextKey{}, proxyURL)
				trial, retried := checkSunnyTrialWithRetry(trialCtx, candidate.AccessToken)
				eligibility := normalizeSunnyTrialEligibility(trial.Eligibility)
				if country != "" && eligibility != sunnyTrialUnknown {
					outcome.CountryResults[country] = eligibility
				}
				if eligibility == sunnyTrialEligible || (outcome.Eligibility != sunnyTrialEligible && eligibility == sunnyTrialIneligible) {
					outcome.Eligibility = eligibility
				}
				if outcome.TrialState == "" {
					outcome.TrialState = trial.TrialState
				}
				if outcome.Message == "" {
					outcome.Message = trial.TrialMessage
				}
				if outcome.TrialError == "" {
					outcome.TrialError = trial.TrialError
				}
				outcome.InvalidToken = outcome.InvalidToken || trial.InvalidToken
				outcome.Retried = outcome.Retried || retried
				if trial.InvalidToken {
					break
				}
			}
			if outcome.Eligibility == "" {
				outcome.Eligibility = sunnyTrialUnknown
			}
			if outcome.Eligibility != sunnyTrialUnknown {
				outcome.TrialError = ""
			}
			outcome.TrafficBytes = meter.totalBytes()
		}
		return outcome
	})
	for outcome := range results {
		item := map[string]any{"session_id": outcome.SessionID, "email": outcome.Email}
		s.recordSunnyProxyTraffic(outcome.Email, outcome.TrafficBytes)
		item["proxy_traffic_bytes"] = outcome.TrafficBytes
		if outcome.Retried {
			result["retried"] = result["retried"].(int) + 1
			item["retried"] = true
		}
		now := time.Now()
		switch {
		case outcome.SkipReason != "":
			result["skipped"] = result["skipped"].(int) + 1
			item["status"], item["message"] = "skipped", outcome.SkipReason
		case outcome.Error != "":
			result["failed"] = result["failed"].(int) + 1
			item["status"], item["error"] = "failed", outcome.Error
			accountUpdates := map[string]any{"trial_eligibility": sunnyTrialUnknown, "trial_check_error": outcome.Error, "trial_checked_at": now}
			mailboxUpdates := map[string]any{"trial_eligibility": sunnyTrialUnknown, "trial_check_error": outcome.Error, "trial_checked_at": now}
			if _, _, persistErr := s.persistSunnyTrialSidecars(candidateBySession[outcome.SessionID], outcome.CountryResults, accountUpdates, mailboxUpdates); persistErr != nil {
				item["status"], item["error"] = "failed", persistErr.Error()
			}
		default:
			probeEligibility := normalizeSunnyTrialEligibility(outcome.Eligibility)
			item["trial_state"] = outcome.TrialState
			if outcome.TrialError != "" {
				item["trial_error"] = outcome.TrialError
			}
			accountUpdates := map[string]any{
				"trial_eligibility": probeEligibility, "trial_check_error": outcome.TrialError, "trial_checked_at": now,
			}
			mailboxUpdates := map[string]any{"trial_eligibility": probeEligibility, "trial_check_error": outcome.TrialError, "trial_checked_at": now}
			countryResults, eligibility, updateErr := s.persistSunnyTrialSidecars(candidateBySession[outcome.SessionID], outcome.CountryResults, accountUpdates, mailboxUpdates)
			if updateErr != nil {
				result["failed"] = result["failed"].(int) + 1
				item["status"], item["error"] = "failed", updateErr.Error()
			} else {
				item["trial_eligibility"] = eligibility
				if len(countryResults) > 0 {
					item["trial_country_results"] = countryResults
				}
				if eligibility == sunnyTrialEligible || eligibility == sunnyTrialIneligible {
					result[eligibility] = result[eligibility].(int) + 1
					item["status"], item["message"] = eligibility, outcome.Message
				} else {
					result["failed"] = result["failed"].(int) + 1
					item["status"], item["error"] = "failed", fallback(outcome.TrialError, "无法确认试用资格")
				}
			}
			if item["status"] == "failed" {
				s.appendAccountTaskEvent(task.ID, outcome.Email, "trial", "trial.check_failed", fmt.Sprintf("账户 %s 试用资格检测失败：%s", outcome.Email, item["error"]), "warning", map[string]any{"error": item["error"]})
			} else {
				s.appendAccountTaskEvent(task.ID, outcome.Email, "trial", "trial.checked", fmt.Sprintf("账户 %s 试用资格检测完成：%s", outcome.Email, eligibility), "info", map[string]any{"trial_eligibility": eligibility})
			}
			if outcome.InvalidToken {
				errorMessage := fallback(outcome.TrialError, "Access Token 无效或已过期")
				s.db.Model(&SunnySession{}).Where("id = ?", outcome.SessionID).Updates(map[string]any{"access_token_status": "invalid", "access_token_error": errorMessage, "access_token_checked_at": now})
				invalidSessions = append(invalidSessions, outcome.SessionID)
				if outcome.AccountID != 0 && !seenAccounts[outcome.AccountID] {
					seenAccounts[outcome.AccountID] = true
					invalidAccounts = append(invalidAccounts, outcome.AccountID)
				}
			}
		}
		items = append(items, item)
		task.ProgressCurrent++
		s.db.Model(&Task{}).Where("id = ?", task.ID).Updates(map[string]any{"progress_current": task.ProgressCurrent, "updated_at": now})
	}
	if len(invalidAccounts) > 0 {
		renewalAccounts := s.filterActiveSunnyRenewalAccounts(invalidAccounts)
		if len(renewalAccounts) > 0 {
			renewalTask := s.createSunnyAccessTokenRenewalTask(task, "trial_check", renewalAccounts)
			if renewalTask.ID != "" {
				queuedAccounts := make(map[uint]bool, len(renewalAccounts))
				for _, accountID := range renewalAccounts {
					queuedAccounts[accountID] = true
				}
				queuedSessions := make([]uint, 0, len(invalidSessions))
				for _, sessionID := range invalidSessions {
					if queuedAccounts[candidateBySession[sessionID].AccountID] {
						queuedSessions = append(queuedSessions, sessionID)
					}
				}
				result["renewal_task_id"] = renewalTask.ID
				result["renewal_queued"] = len(renewalAccounts)
				result["invalid_session_ids"] = queuedSessions
			}
		}
	}
	result["items"] = items
	s.completeSunnyTrialTask(task, result)
}

func (s *Server) sunnyPurposeProxyURL(purpose, accountKey, preferredCountry string) string {
	var proxies []SunnyProxy
	query := "(',' || replace(lower(coalesce(purpose_tags, '')), ' ', '') || ',') LIKE ?"
	if err := s.db.Where("status = ? AND enabled = ? AND last_check_ok = ?", "enabled", true, true).
		Where(query, "%,"+purpose+",%").
		Order("updated_at desc, id asc").Find(&proxies).Error; err != nil || len(proxies) == 0 {
		return ""
	}
	country := strings.ToUpper(strings.TrimSpace(preferredCountry))
	matched := make([]SunnyProxy, 0, len(proxies))
	if country != "" {
		for _, proxy := range proxies {
			if strings.EqualFold(strings.TrimSpace(proxy.Country), country) {
				matched = append(matched, proxy)
			}
		}
	}
	if len(matched) > 0 {
		proxies = matched
	}
	hash := fnv.New32a()
	_, _ = hash.Write([]byte(strings.ToLower(strings.TrimSpace(accountKey))))
	return normalizeSunnyProxyAddress(proxies[int(hash.Sum32())%len(proxies)].Address)
}

// Registration/login and account-detection checks use separate proxy purposes.
func (s *Server) sunnyRegisterProxyURL(accountKey string) string {
	return s.sunnyPurposeProxyURL(sunnyProxyPurposeRegister, accountKey, "")
}

// Checkout checks retain the dedicated account-check proxy pool and prefer the
// configured billing country when that country has an available proxy.
func (s *Server) sunnyCommerceProxyURL(accountKey string) string {
	country, _ := sunnyCheckoutBilling()
	return s.sunnyPurposeProxyURL(sunnyProxyPurposeCommerce, accountKey, country)
}

func (s *Server) failSunnyTrialTask(task *Task, message string) {
	task.Status = TaskFailed
	task.Error = message
	task.FinishedAt = sql.NullTime{Time: time.Now(), Valid: true}
	task.ResultJSON = dumpJSON(map[string]any{"requested": task.ProgressTotal, "eligible": 0, "ineligible": 0, "skipped": 0, "failed": task.ProgressTotal})
	s.db.Save(task)
	s.appendTaskEvent(task.ID, message, "log", "error", nil)
}

func (s *Server) completeSunnyTrialTask(task *Task, result map[string]any) {
	task.Status = TaskSucceeded
	task.SuccessCount = intValue(result["eligible"], 0) + intValue(result["ineligible"], 0)
	task.ErrorCount = intValue(result["failed"], 0)
	task.ResultJSON = dumpJSON(result)
	task.FinishedAt = sql.NullTime{Time: time.Now(), Valid: true}
	s.db.Save(task)
	s.appendTaskEvent(task.ID, "账户试用资格检测任务完成", "log", "info", result)
}

func compactStrings(values ...string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			result = append(result, value)
		}
	}
	return result
}

func normalizeSunnyCheckoutKind(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "oaics":
		return "oaics"
	case "cs_live":
		return "cs_live"
	case "cs_test":
		return "cs_test"
	default:
		return sunnyCheckoutUnknown
	}
}

func normalizeSunnyCheckoutFilter(value string) string {
	raw := strings.ToLower(strings.TrimSpace(value))
	if raw == "" {
		return ""
	}
	normalized := normalizeSunnyCheckoutKind(raw)
	if normalized == sunnyCheckoutUnknown && raw != sunnyCheckoutUnknown {
		return ""
	}
	return normalized
}
