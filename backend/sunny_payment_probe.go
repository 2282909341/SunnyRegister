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
	"strconv"
	"strings"
	"time"
)

const sunnyPaymentProbeTaskType = "sunny_account_payment_probe"

// 每个账户在每个国家建立 Checkout 会话的代理尝试上限。逐个遍历全部支付代理
// 会让同一账号短时间内被反复建单数十次，直接触发 OpenAI 账号级
// checkout_creation_rate_limited 冷却（429）；成功探测一次 HTTP 200 即返回，
// 少量代理即可覆盖偶发故障，探测期间全程无反馈的问题也随之消失。
const sunnyPaymentProbeMaxAttempts = 3

// 风控熔断阈值。OpenAI 对支付探测返回 HTTP 400 unusual activity / HTTP 429
// checkout_creation_rate_limited 时，说明当前出口或账号已被风控标记。实测
// （2026-09-01 全库探测）对 9 个不同账号跨段抽样全部返回 429，限流与账号
// 无关而是出口级普遍限流；此时继续遍历剩余账号只会继续抬高账号风险评分
// 并延长冷却窗口，因此累计命中达到阈值后立即中止整个任务，把剩余账号
// 留给冷却窗口之后的下一轮探测。0 表示关闭熔断。
const sunnyPaymentProbeRiskBreakerLimit = 3

const sunnyPaymentProbeRiskBreakerKey = "payment_probe_risk_breaker"

// 代理健康数据陈旧阈值。代理列表里的 last_check_ok 可能长期没有刷新
// （例如健康检查任务停跑），任务会拿着已经失效的代理反复探测。超过该
// 时长仍未复检的代理会在任务开始时触发告警事件，提示先做一次代理健康
// 检查，避免整批探测白跑并污染探测结果。
const sunnyPaymentProbeProxyStaleHours = 12

// sunnyPaymentProbeRiskMarkers 是 OpenAI 侧风控/限流的错误特征。命中即认为
// 该次探测消耗了账号风险额度，需要计入熔断计数。
var sunnyPaymentProbeRiskMarkers = []string{
	"unusual activity",
	"检测到异常活动",
	"账户风控标记",
	"checkout_creation_rate_limited",
	"rate_limited",
}

func sunnyPaymentProbeRiskMessage(message string) bool {
	lowered := strings.ToLower(strings.TrimSpace(message))
	if lowered == "" {
		return false
	}
	for _, marker := range sunnyPaymentProbeRiskMarkers {
		if strings.Contains(lowered, marker) {
			return true
		}
	}
	return false
}

// sunnyPaymentProbeProxyFailure 判断一次探测是否属于「请求根本没到达 OpenAI」
// 的代理/网络类失败：这类失败不消耗账号风控额度，但说明出口代理已经不可用，
// 需要立刻回写代理健康状态。任务取消属于控制流而不是代理故障，必须排除，
// 否则熔断中止任务时会把整批可用代理误标成失效。
func sunnyPaymentProbeProxyFailure(probed sunnyPaymentProbeResponse, ctxErr error) bool {
	if probed.HTTP != 0 || ctxErr != nil {
		return false
	}
	message := strings.ToLower(strings.TrimSpace(probed.Error))
	if message == "" || strings.Contains(message, "cancel") {
		return false
	}
	return true
}

// sunnyMomoProbeStatus 依据一次 VN Checkout 探测结果推导 MoMo 与 0 元优惠的
// 兼容状态；第二个返回值为 false 表示本次结果不足以给出确定结论，调用方
// 应保持 unknown 不写库。
//
// 判定需要两个独立信号：本次建单是否请求了 0 元优惠（useTrialPromotion），
// 以及 Checkout 的实际金额（amount/currency）。只有金额落在 MoMo 优惠区间
// （VND 且 0 <= amount <= sunnyMomoPromoAmountLimitVND）才认定优惠已生效。
//
// 注意：早期结论「带 0 元优惠建单时服务端必然把 MoMo 剥离成 card/link」已被
// 2026-09-02 的落库数据证伪 —— 存在 amount=0、currency=VND 且
// payment_methods 同时包含 momo 的 Checkout（momo_discounted=true），两者
// 可以并存。因此不能再凭「探到 momo」直接判为 momo_only。金额未知时保持
// unknown，避免把「优惠未生效的全价单」误写成 0 元双资格。
func sunnyMomoProbeStatus(countryDetail map[string]any, useTrialPromotion bool) (string, bool) {
	methods := normalizeSunnyPaymentMethods(stringSlice(countryDetail["methods"]))
	hasMomo := containsString(methods, "momo")
	if !useTrialPromotion {
		if hasMomo {
			return "momo_only", true
		}
		return "unsupported", true
	}
	amount, known := sunnyProbeAmountMinor(countryDetail["amount"])
	if !known {
		return "", false
	}
	promoApplied := sunnyIsMomoPromoAmount(amount, text(countryDetail["currency"]))
	switch {
	case hasMomo && promoApplied:
		return "supported", true
	case hasMomo:
		return "momo_only", true
	case promoApplied:
		return "promo_only", true
	default:
		return "unsupported", true
	}
}

// sunnyMomoPromoAmountLimitVND 与 Python 侧
// tools/pay153_checkout/provider_checkout.py 的 MOMO_PROMO_AMOUNT_LIMIT_VND 对齐。
const sunnyMomoPromoAmountLimitVND = 50

// sunnyProbeAmountMinor 读取探测结果里的 Checkout 金额（最小货币单位）。
// 第二个返回值为 false 表示本次探测没有回传金额，调用方必须按未知处理。
func sunnyProbeAmountMinor(value any) (int64, bool) {
	switch typed := value.(type) {
	case int:
		return int64(typed), true
	case int64:
		return typed, true
	case float64:
		return int64(typed), true
	case json.Number:
		if parsed, err := typed.Int64(); err == nil {
			return parsed, true
		}
		if parsed, err := typed.Float64(); err == nil {
			return int64(parsed), true
		}
	case string:
		if parsed, err := strconv.ParseInt(strings.TrimSpace(typed), 10, 64); err == nil {
			return parsed, true
		}
	}
	return 0, false
}

// sunnyIsMomoPromoAmount 与 Python 侧 is_momo_promo_amount 保持一致：
// 仅 VND 且金额落在 [0, 50] 视为 MoMo 0 元优惠已生效。
func sunnyIsMomoPromoAmount(amount int64, currency string) bool {
	if !strings.EqualFold(strings.TrimSpace(currency), "VND") {
		return false
	}
	return amount >= 0 && amount <= sunnyMomoPromoAmountLimitVND
}

type sunnyPaymentPromotionContextKey struct{}

type sunnyPaymentProbeCandidate struct {
	SessionID   uint
	AccountID   uint
	Email       string
	AccessToken string
	SkipReason  string
	Error       string
}

type sunnyPaymentCountryProbe struct {
	Country      string
	Methods      []string
	ProxyID      uint
	Attempts     int
	HTTP         int
	Amount       int64
	AmountKnown  bool
	Currency     string
	InvalidToken bool
	Risk         bool
	ProxyFailed  bool
	Error        string
	TrafficBytes int64
}

type sunnyPaymentAccountProbe struct {
	Candidate      sunnyPaymentProbeCandidate
	Methods        []string
	Countries      map[string]any
	Errors         []string
	Succeeded      int
	InvalidToken   bool
	Risk           bool
	FailedProxyIDs []uint
	TrafficBytes   int64
}

type sunnyPaymentProbeResponse struct {
	Kind         string
	Methods      []string
	HTTP         int
	Amount       int64
	AmountKnown  bool
	Currency     string
	InvalidToken bool
	Error        string
	TrafficBytes int64
}

var sunnyProbePaymentMethods = probeSunnyPaymentMethods

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
	useTrialPromotion, _ := ctx.Value(sunnyPaymentPromotionContextKey{}).(bool)
	if workerResult, ok := probeSunnyPaymentMethodsViaWorker(ctx, accessToken, country, currency, proxyURL, useTrialPromotion); ok {
		return workerResult
	}
	meter := sunnyTrafficMeterFromContext(ctx)
	client := sunnyCommerceHTTPClientWithMeter(meter, proxyURL)
	kind, methods, invalid, err := probeSunnyCheckoutForCountryWithPromotion(ctx, client, accessToken, country, currency, useTrialPromotion)
	result := sunnyPaymentProbeResponse{Kind: normalizeSunnyCheckoutKind(kind), Methods: normalizeSunnyPaymentMethods(methods), HTTP: http.StatusOK, InvalidToken: invalid}
	if err != nil {
		result.HTTP = 0
		result.Error = err.Error()
	}
	return result
}

func probeSunnyPaymentMethodsViaWorker(ctx context.Context, accessToken, country, currency, proxyURL string, useTrialPromotion bool) (sunnyPaymentProbeResponse, bool) {
	result := sunnyPaymentProbeResponse{}
	workerURL := strings.TrimRight(strings.TrimSpace(os.Getenv("PYTHON_WORKER_URL")), "/")
	if workerURL == "" {
		workerURL = "http://127.0.0.1:8765"
	}
	body, _ := json.Marshal(map[string]any{"access_token": accessToken, "proxy_url": proxyURL, "country": country, "currency": currency, "use_trial_promotion": useTrialPromotion})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, workerURL+"/probe-payment-methods", bytes.NewReader(body))
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
			HTTP           int      `json:"http"`
			Error          string   `json:"error"`
			Amount         *int64   `json:"amount"`
			Currency       string   `json:"currency"`
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
	result.HTTP = payload.Checkout.HTTP
	result.Currency = strings.TrimSpace(payload.Checkout.Currency)
	if payload.Checkout.Amount != nil {
		result.Amount = *payload.Checkout.Amount
		result.AmountKnown = true
	}
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

// sunnyPaymentProbeRiskBreaker 返回风控熔断阈值；0 表示关闭熔断。
func (s *Server) sunnyPaymentProbeRiskBreaker() int {
	s.maintenanceMu.RLock()
	raw, configured := s.maintenance[sunnyPaymentProbeRiskBreakerKey]
	s.maintenanceMu.RUnlock()
	if configured {
		return max(0, min(intValue(raw, sunnyPaymentProbeRiskBreakerLimit), 100))
	}
	if fromEnv := strings.TrimSpace(os.Getenv("SUNNY_PAYMENT_PROBE_RISK_BREAKER")); fromEnv != "" {
		return max(0, min(intValue(fromEnv, sunnyPaymentProbeRiskBreakerLimit), 100))
	}
	return sunnyPaymentProbeRiskBreakerLimit
}

// markSunnyPaymentProbeProxyUnhealthy 把探测期间确认不可达的代理立刻回写为
// 失效。代理列表的 last_check_ok 可能长期未刷新（陈旧 true），不回写会让
// 后续每一轮探测继续拿已失效的代理建单。
func (s *Server) markSunnyPaymentProbeProxyUnhealthy(proxyID uint, message string) {
	if s.db == nil || proxyID == 0 {
		return
	}
	detail := strings.TrimSpace(message)
	if len(detail) > 500 {
		detail = detail[:500]
	}
	s.db.Model(&SunnyProxy{}).Where("id = ?", proxyID).Updates(map[string]any{
		"last_check_ok":   false,
		"last_error":      detail,
		"last_checked_at": time.Now(),
	})
}

// sunnyPaymentProbeStaleProxyCountries 返回没有任何「近期复检且通过」代理的
// 国家列表。这些国家的探测大概率会直接失败，任务开始时先告警避免整批白跑。
func sunnyPaymentProbeStaleProxyCountries(groups map[string][]SunnyProxy) []string {
	now := time.Now()
	stale := make([]string, 0, len(groups))
	for country, proxies := range groups {
		fresh := false
		for _, proxy := range proxies {
			if proxy.LastCheckedAt != nil && proxy.LastCheckOK && now.Sub(*proxy.LastCheckedAt) <= time.Duration(sunnyPaymentProbeProxyStaleHours)*time.Hour {
				fresh = true
				break
			}
		}
		if !fresh {
			stale = append(stale, country)
		}
	}
	sort.Strings(stale)
	return stale
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
	rawCountries, exists := body["countries"]
	if !exists {
		return Task{}, fmt.Errorf("请至少选择一个支付探测国家")
	}
	requestedCountries := stringSlice(rawCountries)
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
	payload := map[string]any{"session_ids": ids, "skip_session_ids": skipped, "countries": countries, "use_trial_promotion": boolValue(body["use_trial_promotion"], false)}
	return s.createTask(sunnyPaymentProbeTaskType, "sunny", payload, len(candidates)), nil
}

func shuffledSunnyProxies(proxies []SunnyProxy) []SunnyProxy {
	shuffled := append([]SunnyProxy(nil), proxies...)
	rand.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
	return shuffled
}

func (s *Server) probeSunnyPaymentCountry(candidate sunnyPaymentProbeCandidate, country string, proxies []SunnyProxy) sunnyPaymentCountryProbe {
	return s.probeSunnyPaymentCountryContext(context.Background(), candidate, country, proxies, nil)
}

func (s *Server) probeSunnyPaymentCountryContext(ctx context.Context, candidate sunnyPaymentProbeCandidate, country string, proxies []SunnyProxy, onAttempt func(current, total int)) sunnyPaymentCountryProbe {
	result := sunnyPaymentCountryProbe{Country: country}
	currency := checkoutCountryCurrency[country]
	if currency == "" {
		currency = "USD"
	}
	selected := shuffledSunnyProxies(proxies)
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
		probeCtx, cancel := context.WithTimeout(ctx, 105*time.Second)
		meter := &sunnyTrafficMeter{}
		probeCtx = withSunnyTrafficMeter(probeCtx, meter)
		probed := sunnyProbePaymentMethods(probeCtx, candidate.AccessToken, country, currency, normalizeSunnyProxyAddress(proxy.Address))
		cancel()
		result.TrafficBytes += meter.totalBytes() + probed.TrafficBytes
		result.ProxyID, result.HTTP, result.InvalidToken, result.Error = proxy.ID, probed.HTTP, probed.InvalidToken, probed.Error
		result.Amount, result.AmountKnown, result.Currency = probed.Amount, probed.AmountKnown, probed.Currency
		result.Risk = probed.HTTP == http.StatusTooManyRequests || sunnyPaymentProbeRiskMessage(probed.Error)
		result.ProxyFailed = sunnyPaymentProbeProxyFailure(probed, ctx.Err())
		if probed.InvalidToken {
			return result
		}
		if strings.TrimSpace(probed.Error) == "" && probed.HTTP >= 200 && probed.HTTP < 300 {
			result.Methods = normalizeSunnyPaymentMethods(probed.Methods)
			return result
		}
		// 明确的客户端错误（资格不符、参数被拒、账号级限流等）换代理也不会有
		// 不同结果，立即返回；403 风控、408 超时仍允许换代理重试。429 的
		// checkout_creation_rate_limited 是账号级限流，换代理无效且会延长
		// 冷却时间，因此也立即返回不再重试。
		if probed.HTTP >= 400 && probed.HTTP < 500 && probed.HTTP != http.StatusForbidden && probed.HTTP != http.StatusRequestTimeout {
			return result
		}
	}
	result.Error = fallback(result.Error, "该国家没有可用的支付探测代理")
	return result
}

func (s *Server) probeSunnyPaymentAccount(candidate sunnyPaymentProbeCandidate, groups map[string][]SunnyProxy) sunnyPaymentAccountProbe {
	return s.probeSunnyPaymentAccountContext(context.Background(), candidate, groups, nil)
}

func (s *Server) probeSunnyPaymentAccountContext(ctx context.Context, candidate sunnyPaymentProbeCandidate, groups map[string][]SunnyProxy, onAttempt func(country string, current, total int)) sunnyPaymentAccountProbe {
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
		return s.probeSunnyPaymentCountryContext(ctx, candidate, country, groups[country], func(current, total int) {
			if onAttempt != nil {
				onAttempt(country, current, total)
			}
		})
	})
	allMethods := []string{}
	for probe := range probes {
		result.TrafficBytes += probe.TrafficBytes
		detail := map[string]any{"methods": probe.Methods, "proxy_id": probe.ProxyID, "attempts": probe.Attempts, "http": probe.HTTP}
		if probe.AmountKnown {
			detail["amount"] = probe.Amount
			detail["currency"] = probe.Currency
			detail["promo_applied"] = sunnyIsMomoPromoAmount(probe.Amount, probe.Currency)
		}
		if probe.Error != "" {
			detail["error"] = probe.Error
			result.Errors = append(result.Errors, probe.Country+": "+probe.Error)
		} else {
			result.Succeeded++
			allMethods = append(allMethods, probe.Methods...)
		}
		result.InvalidToken = result.InvalidToken || probe.InvalidToken
		result.Risk = result.Risk || probe.Risk
		if probe.ProxyFailed && probe.ProxyID != 0 {
			result.FailedProxyIDs = append(result.FailedProxyIDs, probe.ProxyID)
		}
		if probe.Risk {
			detail["risk"] = true
		}
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
	selectedCountries := sunnyPaymentProbeCountryList(groups)
	useTrialPromotion := boolValue(payload["use_trial_promotion"], false)
	promotionLabel := "不使用0元优惠"
	if useTrialPromotion {
		promotionLabel = "使用0元优惠"
	}
	s.appendTaskEvent(task.ID,
		fmt.Sprintf("账户支付方式探测开始：账户 %d 个，国家 %d 个（%s），%s", len(candidates), len(selectedCountries), strings.Join(selectedCountries, ", "), promotionLabel),
		"log", "info", map[string]any{
			"scope": "global", "progress_type": "payment_probe", "current": 0, "total": len(candidates),
			"countries": selectedCountries, "use_trial_promotion": useTrialPromotion,
		})
	if stale := sunnyPaymentProbeStaleProxyCountries(groups); len(stale) > 0 {
		s.appendTaskEvent(task.ID,
			fmt.Sprintf("代理健康数据陈旧告警：%s 的支付探测代理超过 %d 小时未复检，或最近一次复检未通过。请先执行一次代理健康检查再探测，否则这些国家的探测会直接失败。",
				strings.Join(stale, ", "), sunnyPaymentProbeProxyStaleHours),
			"log", "warning", map[string]any{"countries": stale, "stale_hours": sunnyPaymentProbeProxyStaleHours})
	}
	skipped := map[uint]bool{}
	for _, id := range uintSlice(payload["skip_session_ids"]) {
		skipped[id] = true
	}
	for index := range candidates {
		if skipped[candidates[index].SessionID] && candidates[index].SkipReason == "" {
			candidates[index].SkipReason = "已有支付方式探测任务正在执行，已跳过"
		}
	}
	result := map[string]any{"requested": len(candidates), "detected": 0, "partial": 0, "skipped": 0, "failed": 0, "items": []any{}, "use_trial_promotion": useTrialPromotion}
	items := make([]any, 0, len(candidates))
	riskBreaker := s.sunnyPaymentProbeRiskBreaker()
	riskHits := 0
	riskBreakerOpen := false
	probeCtx := context.WithValue(ctx, sunnyPaymentPromotionContextKey{}, useTrialPromotion)
	outcomes := streamSunnyWorkerPoolContext(probeCtx, candidates, s.sunnyPaymentProbeConcurrency(), func(candidate sunnyPaymentProbeCandidate) sunnyPaymentAccountProbe {
		return s.probeSunnyPaymentAccountContext(probeCtx, candidate, groups, func(country string, current, total int) {
			// 每次代理尝试都实时上报，探测期间前端轮询任务事件即可看到
			// 1/3、2/3、3/3 的进度，而不是直到账号级结果才出现反馈。
			s.appendAccountTaskEvent(task.ID, candidate.Email, "payment", "payment_probe.attempt",
				fmt.Sprintf("[%s] [支付探测] %s 正在尝试代理 %d/%d", candidate.Email, country, current, total), "info",
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
		for _, proxyID := range outcome.FailedProxyIDs {
			s.markSunnyPaymentProbeProxyUnhealthy(proxyID, fallback(strings.Join(outcome.Errors, "; "), "支付探测代理不可达"))
		}
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
				message := fmt.Sprintf("[%s] [支付探测] %s 探测完成：%s（HTTP %d，代理 #%d，尝试 %d 次）", outcome.Candidate.Email, country, fallback(strings.Join(methods, ", "), "未识别支付方式"), intValue(detail["http"], 0), intValue(detail["proxy_id"], 0), intValue(detail["attempts"], 0))
				if errorText != "" {
					level = "warning"
					message = fmt.Sprintf("[%s] [支付探测] %s 探测失败：%s（代理 #%d，尝试 %d 次）", outcome.Candidate.Email, country, errorText, intValue(detail["proxy_id"], 0), intValue(detail["attempts"], 0))
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
				mergedCountries, mergedMethods := mergeSunnyPaymentProbeResults(account.PaymentProbeResultsJSON, outcome.Countries)
				item["payment_methods"] = mergedMethods
				failed := map[string]any{"payment_methods_json": dumpJSON(mergedMethods), "payment_probe_methods_json": dumpJSON(mergedMethods), "payment_probe_results_json": dumpJSON(mergedCountries), "payment_probe_error": message}
				if vnDetail, ok := outcome.Countries["VN"].(map[string]any); ok {
					if vnError := text(vnDetail["error"]); vnError != "" {
						failed["momo_promo_error"] = vnError
					}
				}
				s.db.Model(&SunnyAccount{}).Where("id = ?", account.ID).Updates(failed)
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
			item["payment_methods"] = mergedMethods
			updates := map[string]any{"payment_methods_json": dumpJSON(mergedMethods), "payment_probe_methods_json": dumpJSON(mergedMethods), "payment_probe_results_json": dumpJSON(mergedCountries), "payment_probe_error": message, "payment_probed_at": now}
			// VN 探测结果同时回写 MoMo 专用字段，让「MoMo 可用性」不再只能
			// 依赖外部脚本落库；只写入有确定结论的场景，不确定时保持原值。
			if vnDetail, ok := outcome.Countries["VN"].(map[string]any); ok {
				if vnError := text(vnDetail["error"]); vnError != "" {
					updates["momo_promo_error"] = vnError
				} else if momoStatus, certain := sunnyMomoProbeStatus(vnDetail, useTrialPromotion); certain {
					updates["momo_promo_status"] = momoStatus
					updates["momo_promo_error"] = ""
					updates["momo_promo_probed_at"] = now
					updates["momo_promo_result_json"] = dumpJSON(map[string]any{
						"status": momoStatus, "country": "VN", "currency": "VND",
						"methods": normalizeSunnyPaymentMethods(stringSlice(vnDetail["methods"])),
						"http":    intValue(vnDetail["http"], 0), "proxy_id": intValue(vnDetail["proxy_id"], 0),
						"attempts": intValue(vnDetail["attempts"], 0), "use_trial_promotion": useTrialPromotion,
					})
				}
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
		// 风控熔断：本轮探测被 OpenAI 标记为异常活动或建单限流后，剩余账号
		// 大概率会被同样标记。此时主动停下，避免把整批账号的风险评分打高。
		if outcome.Risk {
			riskHits++
			riskDetail := strings.Join(outcome.Errors, "; ")
			s.appendAccountTaskEvent(task.ID, outcome.Candidate.Email, "payment", "payment_probe.risk",
				fmt.Sprintf("[%s] [支付探测] OpenAI 风控命中（累计 %d/%d）：%s", outcome.Candidate.Email, riskHits, riskBreaker, fallback(riskDetail, "unusual activity / rate limited")),
				"warning", map[string]any{"session_id": outcome.Candidate.SessionID, "risk_hits": riskHits, "limit": riskBreaker, "error": riskDetail})
			if riskBreaker > 0 && riskHits >= riskBreaker {
				riskBreakerOpen = true
				s.appendTaskEvent(task.ID,
					fmt.Sprintf("支付探测风控熔断：累计 %d 个账户被 OpenAI 风控标记（unusual activity / checkout_creation_rate_limited），已中止剩余账户探测。继续探测只会抬高账户风险评分并延长冷却窗口，请等待冷却窗口后重试，并优先更换已被标记的出口代理。", riskHits),
					"log", "warning", map[string]any{"risk_hits": riskHits, "limit": riskBreaker, "processed": task.ProgressCurrent, "total": task.ProgressTotal})
			}
		}
		items = append(items, item)
		task.ProgressCurrent++
		s.persistTaskProgress(task, intValue(result["detected"], 0)+intValue(result["partial"], 0), intValue(result["failed"], 0), now)
		status := text(item["status"])
		progressMessage := fmt.Sprintf("[%s] [支付探测] 账户任务完成：%d/%d，结果=%s，支付方式=%s", outcome.Candidate.Email, task.ProgressCurrent, task.ProgressTotal, status, fallback(strings.Join(outcome.Methods, ", "), "-"))
		progressLevel := "info"
		if status == "failed" {
			progressLevel = "error"
		}
		s.appendAccountTaskEvent(task.ID, outcome.Candidate.Email, "payment", "payment_probe.completed", progressMessage, progressLevel, map[string]any{
			"session_id": outcome.Candidate.SessionID, "status": status, "current": task.ProgressCurrent, "total": task.ProgressTotal, "methods": outcome.Methods,
		})
		if riskBreakerOpen {
			cancel()
			break
		}
	}
	result["items"] = items
	result["risk_hits"] = riskHits
	if riskBreakerOpen {
		result["risk_breaker"] = true
		result["skipped"] = result["skipped"].(int) + max(0, len(candidates)-task.ProgressCurrent)
	}
	if s.finishCancelledTask(task, result, "用户已停止支付探测任务") {
		return
	}
	task.Status = TaskSucceeded
	task.SuccessCount = intValue(result["detected"], 0) + intValue(result["partial"], 0)
	task.ErrorCount = intValue(result["failed"], 0)
	task.ResultJSON = dumpJSON(result)
	task.FinishedAt = sql.NullTime{Time: time.Now(), Valid: true}
	s.db.Save(task)
	s.appendTaskEvent(task.ID, "账户支付方式探测任务完成", "log", "info", result)
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
