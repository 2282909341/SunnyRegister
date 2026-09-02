package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const sunnyCheckoutTaskType = "sunny_checkout_link"

var checkoutProviders = []map[string]string{
	{"value": "hosted", "label": "Hosted", "hint": "官方支付长链", "country": "US", "currency": "USD"},
	{"value": "ph_short", "label": "菲律宾短链", "hint": "US Checkout / TR 优惠", "country": "PH", "currency": "PHP"},
	{"value": "paypal", "label": "PayPal", "hint": "Approve 跳转", "country": "US", "currency": "USD"},
	{"value": "ideal", "label": "iDEAL", "hint": "荷兰银行支付", "country": "NL", "currency": "EUR"},
	{"value": "twint", "label": "TWINT", "hint": "瑞士移动支付", "country": "CH", "currency": "CHF"},
	{"value": "upi", "label": "UPI", "hint": "印度二维码", "country": "IN", "currency": "INR"},
	{"value": "pix", "label": "PIX", "hint": "巴西即时支付", "country": "BR", "currency": "BRL"},
	{"value": "momo", "label": "MoMo", "hint": "越南电子钱包", "country": "VN", "currency": "VND"},
	{"value": "gcash", "label": "GCash", "hint": "菲律宾电子钱包", "country": "PH", "currency": "PHP"},
	{"value": "gopay", "label": "GoPay", "hint": "印尼 Midtrans 跳转", "country": "ID", "currency": "IDR"},
	{"value": "blik", "label": "BLIK", "hint": "波兰银行动态码支付", "country": "PL", "currency": "PLN"},
	{"value": "kakao", "label": "Kakao Pay", "hint": "韩国 Nicepay 跳转", "country": "KR", "currency": "KRW"},
}

var checkoutProviderSet = func() map[string]bool {
	out := map[string]bool{}
	for _, item := range checkoutProviders {
		out[item["value"]] = true
	}
	return out
}()

var checkoutCountryCurrency = map[string]string{
	"US": "USD", "DE": "EUR", "FR": "EUR", "NL": "EUR", "PT": "EUR",
	"IN": "INR", "ID": "IDR", "BR": "BRL", "VN": "VND", "GB": "GBP",
	"JP": "JPY", "KR": "KRW", "PH": "PHP", "SG": "SGD", "MY": "MYR",
	"TH": "THB", "AU": "AUD", "CA": "CAD", "CH": "CHF", "PL": "PLN",
}

type sunnyCheckoutRequest struct {
	SystemAT         bool     `json:"system_at"`
	SessionIDs       []uint   `json:"session_ids"`
	ExternalATs      []string `json:"external_ats"`
	CheckoutProxies  string   `json:"checkout_proxies"`
	PromotionProxies string   `json:"promotion_proxies"`
	CheckoutKinds    []string `json:"checkout_kinds"`
	Plan             string   `json:"plan"`
	LinkType         string   `json:"link_type"`
	Country          string   `json:"country"`
	Currency         string   `json:"currency"`
	RetryCount       int      `json:"retry_count"`
	Concurrency      int      `json:"concurrency"`
	UsePromo         bool     `json:"use_promo"`
	PromoCampaign    string   `json:"promo_campaign"`
	PromoCode        string   `json:"promo_code"`
	WorkspaceName    string   `json:"workspace_name"`
	WorkspaceID      string   `json:"workspace_id"`
	SeatQuantity     int      `json:"seat_quantity"`
	PriceInterval    string   `json:"price_interval"`
	CreditQuantity   int      `json:"credit_quantity"`
	PixTaxID         string   `json:"pix_tax_id"`
	PixAutoKind      string   `json:"pix_auto_kind"`
	IdealBank        string   `json:"ideal_bank"`
	ForceMomo        bool     `json:"force_momo"`
	PromoCountry     string   `json:"promo_country"`
}

type sunnyCheckoutPrecheckRequest struct {
	SystemAT         bool     `json:"system_at"`
	SessionIDs       []uint   `json:"session_ids"`
	ExternalATs      []string `json:"external_ats"`
	CheckoutProxies  string   `json:"checkout_proxies"`
	PromotionProxies string   `json:"promotion_proxies"`
	UsePromo         bool     `json:"use_promo"`
	Country          string   `json:"country"`
	Currency         string   `json:"currency"`
}

type sunnyCheckoutCredential struct {
	Token        string
	Email        string
	CheckoutKind string
	SessionID    uint
	External     bool
}

type checkoutSecret struct {
	Tokens    map[string]string
	Checkout  []string
	Promotion []string
}

func splitCheckoutPool(raw string) ([]string, error) {
	lines := strings.FieldsFunc(raw, func(r rune) bool { return r == '\r' || r == '\n' })
	seen := map[string]bool{}
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || seen[line] {
			continue
		}
		normalized, err := normalizeCheckoutProxy(line)
		if err != nil {
			return nil, fmt.Errorf("代理格式无效: %s", line)
		}
		if seen[normalized] {
			continue
		}
		seen[normalized] = true
		out = append(out, normalized)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("代理池不能为空")
	}
	if len(out) > 500 {
		return nil, fmt.Errorf("代理池最多填写 500 条")
	}
	return out, nil
}

func normalizeCheckoutProxy(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", fmt.Errorf("empty proxy")
	}
	if !strings.Contains(value, "://") {
		parts := strings.Split(value, ":")
		if len(parts) >= 4 {
			if _, err := strconv.Atoi(parts[1]); err == nil {
				value = fmt.Sprintf("http://%s:%s@%s:%s", url.QueryEscape(parts[2]), url.QueryEscape(strings.Join(parts[3:], ":")), parts[0], parts[1])
			} else if _, err := strconv.Atoi(parts[len(parts)-1]); err == nil {
				value = fmt.Sprintf("http://%s:%s@%s:%s", url.QueryEscape(parts[0]), url.QueryEscape(strings.Join(parts[1:len(parts)-2], ":")), parts[len(parts)-2], parts[len(parts)-1])
			} else {
				return "", fmt.Errorf("invalid proxy")
			}
		} else {
			value = "http://" + value
		}
	}
	u, err := url.Parse(value)
	if err != nil || u.Hostname() == "" || u.Port() == "" {
		return "", fmt.Errorf("invalid proxy")
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https", "socks5", "socks5h":
	default:
		return "", fmt.Errorf("unsupported proxy scheme")
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 {
		return "", fmt.Errorf("invalid proxy port")
	}
	if strings.HasSuffix(strings.ToLower(u.Hostname()), "kookeey.info") && (port == 1000 || port == 1086) && (u.Scheme == "http" || u.Scheme == "https") {
		u.Scheme = "socks5h"
	}
	return u.String(), nil
}

func checkoutProviderDefaults(value string) (string, string) {
	for _, item := range checkoutProviders {
		if item["value"] == value {
			return item["country"], item["currency"]
		}
	}
	return "US", "USD"
}

func normalizeCheckoutRequest(in sunnyCheckoutRequest) (sunnyCheckoutRequest, []string, []string, error) {
	in.Plan = strings.ToLower(strings.TrimSpace(in.Plan))
	if in.Plan == "" {
		in.Plan = "plus"
	}
	if !map[string]bool{"plus": true, "pro": true, "team": true, "codex_low": true}[in.Plan] {
		return in, nil, nil, fmt.Errorf("不支持的套餐")
	}
	in.LinkType = strings.ToLower(strings.TrimSpace(in.LinkType))
	if !checkoutProviderSet[in.LinkType] {
		return in, nil, nil, fmt.Errorf("不支持的支付路径")
	}
	in.Country = strings.ToUpper(strings.TrimSpace(in.Country))
	in.Currency = strings.ToUpper(strings.TrimSpace(in.Currency))
	if in.Country == "" || in.Currency == "" {
		in.Country, in.Currency = checkoutProviderDefaults(in.LinkType)
	}
	if in.LinkType == "gcash" {
		in.Country, in.Currency, in.PromoCountry = "PH", "PHP", "PH"
	}
	if in.LinkType == "gopay" {
		in.Country, in.Currency = "ID", "IDR"
	}
	if checkoutCountryCurrency[in.Country] == "" {
		return in, nil, nil, fmt.Errorf("不支持的国家/地区")
	}
	if in.RetryCount < 0 {
		in.RetryCount = 10
	}
	if in.RetryCount > 50 {
		in.RetryCount = 50
	}
	if in.Concurrency < 1 {
		in.Concurrency = 3
	}
	if in.Concurrency > 100 {
		in.Concurrency = 100
	}
	if in.SeatQuantity < 2 {
		in.SeatQuantity = 5
	}
	if in.CreditQuantity < 1 {
		in.CreditQuantity = 13
	}
	in.PromoCountry = strings.ToUpper(strings.TrimSpace(in.PromoCountry))
	if in.PromoCountry != "" && checkoutCountryCurrency[in.PromoCountry] == "" && in.PromoCountry != "TR" {
		return in, nil, nil, fmt.Errorf("不支持的 Promotion 国家/地区")
	}
	if in.LinkType == "ph_short" && in.Plan != "plus" {
		return in, nil, nil, fmt.Errorf("菲律宾短链仅支持 Plus")
	}
	if in.LinkType == "pix" {
		digits := regexp.MustCompile(`\D`).ReplaceAllString(in.PixTaxID, "")
		if digits != "" && len(digits) != 11 && len(digits) != 14 {
			return in, nil, nil, fmt.Errorf("PIX 需要填写 11 位 CPF 或 14 位 CNPJ")
		}
		in.PixTaxID = digits
	}
	checkout, err := splitCheckoutPool(in.CheckoutProxies)
	if err != nil {
		return in, nil, nil, fmt.Errorf("Checkout 代理池: %w", err)
	}
	// Promotion is a separate route only when the caller explicitly enables
	// the Plus promotion. With the toggle off, the Checkout route is enough and
	// an empty Promotion pool must not block a no-promo payment task.
	promotion := append([]string(nil), checkout...)
	if in.UsePromo && in.LinkType != "gcash" {
		promotion, err = splitCheckoutPool(in.PromotionProxies)
		if err != nil {
			return in, nil, nil, fmt.Errorf("Promotion 代理池: %w", err)
		}
	}
	return in, checkout, promotion, nil
}

func normalizeCheckoutPrecheckBilling(country, currency string) (string, string, error) {
	country = strings.ToUpper(strings.TrimSpace(country))
	currency = strings.ToUpper(strings.TrimSpace(currency))
	if country == "" && currency == "" {
		country, currency = sunnyCheckoutBilling()
		return country, currency, nil
	}
	if country == "" {
		return "", "", fmt.Errorf("预检国家/地区不能为空")
	}
	expected := checkoutCountryCurrency[country]
	if expected == "" {
		return "", "", fmt.Errorf("不支持的预检国家/地区")
	}
	if currency == "" {
		currency = expected
	}
	if currency != expected {
		return "", "", fmt.Errorf("预检国家/地区与币种不匹配")
	}
	return country, currency, nil
}

func checkoutCredentialID() string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%d-%d", time.Now().UnixNano(), len(checkoutProviders))))
	return base64.RawURLEncoding.EncodeToString(sum[:])[:24]
}

func (s *Server) sunnyCheckout(w http.ResponseWriter, r *http.Request, parts []string) {
	if len(parts) == 1 && parts[0] == "providers" && r.Method == http.MethodGet {
		writeJSON(w, 200, map[string]any{"items": checkoutProviders, "countries": checkoutCountryCurrency})
		return
	}
	if len(parts) >= 2 && parts[0] == "gcash-orders" && (r.Method == http.MethodGet || r.Method == http.MethodPost) {
		s.proxySunnyGcashOrder(w, r, parts[1:])
		return
	}
	if len(parts) == 1 && parts[0] == "precheck" && r.Method == http.MethodPost {
		var body sunnyCheckoutPrecheckRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, "请求格式无效")
			return
		}
		country, currency, err := normalizeCheckoutPrecheckBilling(body.Country, body.Currency)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		checkout, err := splitCheckoutPool(body.CheckoutProxies)
		if err != nil {
			writeError(w, http.StatusBadRequest, "Checkout 代理池: "+err.Error())
			return
		}
		promotion := append([]string(nil), checkout...)
		if body.UsePromo {
			promotion, err = splitCheckoutPool(body.PromotionProxies)
			if err != nil {
				writeError(w, http.StatusBadRequest, "Promotion 代理池: "+err.Error())
				return
			}
		}
		type candidate struct {
			Email, Token string
			SessionID    uint
		}
		candidates := []candidate{}
		if body.SystemAT {
			var sessions []SunnySession
			s.db.Where("id IN ?", body.SessionIDs).Find(&sessions)
			var accounts []SunnyAccount
			s.db.Select("email", "access_token").Where("email IN ?", func() []string {
				out := make([]string, 0, len(sessions))
				for _, row := range sessions {
					out = append(out, row.Email)
				}
				return out
			}()).Find(&accounts)
			accountTokens := map[string]string{}
			for _, account := range accounts {
				accountTokens[sunnyEmailKey(account.Email)] = account.AccessToken
			}
			for _, row := range sessions {
				candidates = append(candidates, candidate{Email: row.Email, SessionID: row.ID, Token: sunnyPreferredAccessToken(row.AccessToken, sunnyAccessTokenFromSessionJSON(row.SessionJSON), accountTokens[sunnyEmailKey(row.Email)])})
			}
		} else {
			for _, raw := range body.ExternalATs {
				token, email := parseCheckoutExternalAT(raw)
				candidates = append(candidates, candidate{Email: email, Token: token})
			}
		}
		items := make([]any, 0, len(candidates))
		for candidateIndex, item := range candidates {
			if item.Token == "" {
				items = append(items, map[string]any{"email": item.Email, "session_id": item.SessionID, "check_status": "invalid", "check_error": "AT 为空、格式无效或已过期", "trial_eligibility": sunnyTrialUnknown, "checkout_kind": sunnyCheckoutUnknown, "payment_methods": []string{}})
				continue
			}
			probeCtx := context.WithValue(context.Background(), sunnyTrialProxyContextKey{}, promotion[candidateIndex%len(promotion)])
			probeCtx = context.WithValue(probeCtx, sunnyCheckoutProxyContextKey{}, checkout[candidateIndex%len(checkout)])
			probeCtx = context.WithValue(probeCtx, sunnyCheckoutBillingContextKey{}, sunnyCheckoutBillingOverride{Country: country, Currency: currency})
			var commerce sunnyCommerceProbeResult
			if body.UsePromo {
				commerce = sunnyCheckCommerce(probeCtx, item.Token)
			} else {
				// No-promotion prechecks are intentionally Checkout-only. This
				// avoids trial/coupon calls and keeps the disabled branch free of
				// Promotion side effects.
				commerce = checkSunnyCheckoutOnly(probeCtx, item.Token, checkout[candidateIndex%len(checkout)])
			}
			trial := normalizeSunnyTrialEligibility(commerce.Eligibility)
			checkStatus := "checked"
			if commerce.InvalidToken {
				checkStatus = "invalid"
			}
			checkError := strings.Join(compactStrings(commerce.TrialError, commerce.CheckoutError), "; ")
			items = append(items, map[string]any{"email": item.Email, "session_id": item.SessionID, "check_status": checkStatus, "check_error": checkError, "trial_eligibility": trial, "trial_message": commerce.TrialMessage, "checkout_kind": commerce.CheckoutKind, "payment_methods": commerce.PaymentMethods, "checkout_error": commerce.CheckoutError})
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": items})
		return
	}
	if len(parts) == 0 && r.Method == http.MethodPost {
		var body sunnyCheckoutRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, 2<<20)).Decode(&body); err != nil {
			writeError(w, 400, "请求格式无效")
			return
		}
		body, checkout, promotion, err := normalizeCheckoutRequest(body)
		if err != nil {
			writeError(w, 400, err.Error())
			return
		}
		creds := []sunnyCheckoutCredential{}
		if body.SystemAT {
			if len(body.SessionIDs) == 0 {
				writeError(w, 400, "请选择至少一个账户")
				return
			}
			var sessions []SunnySession
			s.db.Where("id IN ?", body.SessionIDs).Find(&sessions)
			accounts := map[string]SunnyAccount{}
			var accountRows []SunnyAccount
			emails := make([]string, 0, len(sessions))
			for _, sess := range sessions {
				emails = append(emails, sess.Email)
			}
			if len(emails) > 0 {
				s.db.Select("email", "access_token", "checkout_kind").Where("email IN ?", emails).Find(&accountRows)
				for _, account := range accountRows {
					accounts[sunnyEmailKey(account.Email)] = account
				}
			}
			for _, sess := range sessions {
				account := accounts[sunnyEmailKey(sess.Email)]
				token := sunnyPreferredAccessToken(sess.AccessToken, sunnyAccessTokenFromSessionJSON(sess.SessionJSON), account.AccessToken)
				if token != "" {
					creds = append(creds, sunnyCheckoutCredential{Token: token, Email: sess.Email, CheckoutKind: normalizeSunnyCheckoutKind(account.CheckoutKind), SessionID: sess.ID})
				}
			}
		} else {
			for externalIndex, raw := range body.ExternalATs {
				token, email := parseCheckoutExternalAT(raw)
				if token == "" {
					if strings.EqualFold(strings.TrimSpace(body.LinkType), "momo") {
						writeError(w, http.StatusBadRequest, fmt.Sprintf("第 %d 个外部 AT 为空、格式无效或已过期", externalIndex+1))
						return
					}
					continue
				}
				checkoutKind := sunnyCheckoutUnknown
				if externalIndex < len(body.CheckoutKinds) {
					checkoutKind = normalizeSunnyCheckoutKind(body.CheckoutKinds[externalIndex])
				}
				creds = append(creds, sunnyCheckoutCredential{Token: token, Email: email, CheckoutKind: checkoutKind, External: true})
			}
			if len(creds) == 0 {
				writeError(w, 400, "请导入至少一个有效 AT")
				return
			}
		}
		if len(creds) == 0 {
			writeError(w, 400, "所选账户没有可用 AT")
			return
		}
		id := checkoutCredentialID()
		values := map[string]string{}
		for i, c := range creds {
			values[fmt.Sprintf("%d", i)] = c.Token
		}
		s.checkoutMu.Lock()
		s.checkoutCreds[id] = checkoutSecret{Tokens: values, Checkout: checkout, Promotion: promotion}
		s.checkoutMu.Unlock()
		payload := map[string]any{"credential_id": id, "credentials": make([]map[string]any, len(creds)), "plan": body.Plan, "link_type": body.LinkType, "country": body.Country, "currency": body.Currency, "retry_count": body.RetryCount, "concurrency": body.Concurrency, "use_promo": body.UsePromo, "promo_campaign": body.PromoCampaign, "promo_country": body.PromoCountry, "promo_code": body.PromoCode, "workspace_name": body.WorkspaceName, "workspace_id": body.WorkspaceID, "seat_quantity": body.SeatQuantity, "price_interval": body.PriceInterval, "credit_quantity": body.CreditQuantity, "pix_tax_id": body.PixTaxID, "pix_auto_kind": body.PixAutoKind, "ideal_bank": body.IdealBank, "force_momo": body.ForceMomo}
		items := payload["credentials"].([]map[string]any)
		for i, c := range creds {
			items[i] = map[string]any{"index": i, "email": c.Email, "checkout_kind": c.CheckoutKind, "session_id": c.SessionID, "external": c.External}
		}
		task := s.createTask(sunnyCheckoutTaskType, "chatgpt", payload, len(creds))
		writeJSON(w, http.StatusAccepted, serializeTask(task))
		return
	}
	writeError(w, 404, "not found")
}

func (s *Server) proxySunnyGcashOrder(w http.ResponseWriter, r *http.Request, parts []string) {
	if len(parts) == 0 || len(parts) > 2 {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	workerURL := strings.TrimRight(strings.TrimSpace(os.Getenv("PYTHON_WORKER_URL")), "/")
	if workerURL == "" {
		workerURL = "http://127.0.0.1:8765"
	}
	path := "/api/gcash/orders/" + url.PathEscape(parts[0])
	if len(parts) == 2 {
		if (parts[1] != "callback" && parts[1] != "qr") || r.Method != http.MethodPost {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		path += "/callback"
		if parts[1] == "qr" {
			path = strings.TrimSuffix(path, "/callback") + "/qr"
		}
	} else if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	target, err := url.Parse(workerURL + path)
	if err != nil {
		writeError(w, http.StatusBadGateway, "提链引擎地址无效")
		return
	}
	target.RawQuery = r.URL.RawQuery
	var body io.Reader
	if r.Method == http.MethodPost {
		body = io.LimitReader(r.Body, 1<<20)
	}
	req, err := http.NewRequestWithContext(r.Context(), r.Method, target.String(), body)
	if err != nil {
		writeError(w, http.StatusBadGateway, "无法创建提链回调请求")
		return
	}
	if r.Method == http.MethodPost {
		req.Header.Set("Content-Type", r.Header.Get("Content-Type"))
	}
	if token := secretValue("PYTHON_WORKER_TOKEN", "PYTHON_WORKER_TOKEN_FILE"); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if callbackToken := r.Header.Get("X-GCash-Callback-Token"); callbackToken != "" {
		req.Header.Set("X-GCash-Callback-Token", callbackToken)
	}
	resp, err := (&http.Client{Timeout: 75 * time.Second}).Do(req)
	if err != nil {
		writeError(w, http.StatusBadGateway, "无法连接 GCash 回调服务")
		return
	}
	defer resp.Body.Close()
	w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, io.LimitReader(resp.Body, 2<<20))
}

var checkoutATEmail = regexp.MustCompile(`(?i)[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}`)

func parseCheckoutExternalAT(raw string) (string, string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", ""
	}
	token := ""
	email := ""
	if strings.HasPrefix(raw, "{") {
		var v map[string]any
		if json.Unmarshal([]byte(raw), &v) == nil {
			for _, k := range []string{"access_token", "accessToken", "token"} {
				if t := strings.TrimSpace(text(v[k])); t != "" {
					token = t
					break
				}
			}
			email = strings.TrimSpace(text(v["email"]))
		}
	}
	if token == "" {
		parts := strings.Fields(raw)
		token = parts[0]
		if m := checkoutATEmail.FindString(raw); m != "" {
			email = m
		}
	}
	if !strings.Contains(token, ".") || !strings.HasPrefix(token, "eyJ") {
		return "", ""
	}
	claims := decodeJWTPayload(token)
	if exp := intValue(claims["exp"], 0); exp > 0 && time.Unix(int64(exp), 0).Before(time.Now()) {
		return "", email
	}
	if email == "" {
		if value, ok := claims["email"].(string); ok {
			email = strings.TrimSpace(value)
		}
		if profile, ok := claims["https://api.openai.com/profile"].(map[string]any); ok {
			if value, ok := profile["email"].(string); ok && email == "" {
				email = strings.TrimSpace(value)
			}
		}
	}
	return token, email
}

func (s *Server) checkoutCredential(taskID string, index int) string {
	s.checkoutMu.Lock()
	defer s.checkoutMu.Unlock()
	values := s.checkoutCreds[taskID]
	return values.Tokens[fmt.Sprintf("%d", index)]
}

func (s *Server) releaseCheckoutCredential(credentialID string) {
	credentialID = strings.TrimSpace(credentialID)
	if credentialID == "" {
		return
	}
	s.checkoutMu.Lock()
	delete(s.checkoutCreds, credentialID)
	s.checkoutMu.Unlock()
}

func (s *Server) executeSunnyCheckoutTask(task *Task, payload map[string]any) {
	credentialID := text(payload["credential_id"])
	defer s.releaseCheckoutCredential(credentialID)
	now := time.Now()
	// Claim the task atomically. The cancel endpoint can change a claimed task
	// to cancel_requested before this goroutine gets scheduled; saving the
	// stale in-memory task here would otherwise resurrect it as running.
	started := s.db.Model(&Task{}).
		Where("id = ? AND status = ?", task.ID, TaskClaimed).
		Updates(map[string]any{
			"status":     TaskRunning,
			"started_at": now,
			"updated_at": now,
		})
	if started.Error != nil {
		s.appendTaskEvent(task.ID, "提链任务启动状态写入失败", "log", "error", map[string]any{"error": started.Error.Error()})
		return
	}
	if started.RowsAffected == 0 {
		// Re-read before deciding whether to stop. In particular, do not use the
		// stale task pointer with Save, because it may still contain claimed.
		var current Task
		if err := s.db.First(&current, "id = ?", task.ID).Error; err == nil {
			if current.Status == TaskCancelRequested {
				_ = s.finishCancelledTask(&current, jsonMap(current.ResultJSON), "用户已停止提链任务")
			}
		}
		return
	}
	task.Status = TaskRunning
	task.StartedAt.Valid = true
	task.StartedAt.Time = now
	task.UpdatedAt = now
	ctx, cancel := s.taskCancellationContext(task)
	defer cancel()
	var rows []map[string]any
	if raw, ok := payload["credentials"].([]any); ok {
		for _, v := range raw {
			if m, ok := v.(map[string]any); ok {
				rows = append(rows, m)
			}
		}
	}
	s.checkoutMu.Lock()
	secret := s.checkoutCreds[credentialID]
	s.checkoutMu.Unlock()
	if len(secret.Tokens) == 0 || len(secret.Checkout) == 0 || len(secret.Promotion) == 0 {
		s.finishTask(task, TaskFailed, "临时提链凭据已不存在；服务重启后的临时任务不能恢复，请重新提交", map[string]any{"requested": len(rows), "success": 0, "failed": len(rows), "items": []any{}})
		return
	}
	result := map[string]any{"requested": len(rows), "success": 0, "failed": 0, "items": []any{}, "errors": []any{}}
	var mu sync.Mutex
	sem := make(chan struct{}, intValue(payload["concurrency"], 3))
	var wg sync.WaitGroup
	for idx, row := range rows {
		idx, row := idx, row
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()
			if ctx.Err() != nil {
				return
			}
			token := s.checkoutCredential(credentialID, intValue(row["index"], idx))
			email := text(row["email"])
			accountID := uint(intValue(row["session_id"], 0))
			rowIndex := intValue(row["index"], idx)
			s.appendCheckoutProgress(task, email, accountID, rowIndex, 3, "已领取提链任务")
			item := s.runSunnyCheckoutAttempt(ctx, task, payload, row, token, secret)
			if ctx.Err() != nil {
				return
			}
			item["index"] = rowIndex
			if accountID > 0 {
				item["account_id"] = accountID
			}
			itemCopy := make(map[string]any, len(item))
			for key, value := range item {
				itemCopy[key] = value
			}
			mu.Lock()
			recordSunnyCheckoutResult(task, result, item)
			s.persistTaskProgress(task, intValue(result["success"], 0), intValue(result["failed"], 0), time.Now())
			// Keep partial result items available to polling clients without
			// overwriting a concurrent cancel_requested status.
			s.db.Model(&Task{}).Where("id = ?", task.ID).Updates(map[string]any{"result_json": task.ResultJSON})
			mu.Unlock()
			level := "info"
			if text(item["status"]) != "succeeded" {
				level = "warning"
			}
			s.appendTaskEventWithContext(task.ID, fmt.Sprintf("账户 %s 提链%s", fallback(email, fmt.Sprintf("#%d", rowIndex)), map[bool]string{true: "成功", false: "失败"}[text(item["status"]) == "succeeded"]), "checkout_result", level, map[string]any{
				"email": email, "account_id": accountID, "index": rowIndex, "progress": 100, "result": itemCopy,
			}, TaskEventContext{Email: email, AccountID: accountID, Module: "checkout", Action: "checkout.result", Scope: "account", SubjectType: "account"})
		}()
	}
	wg.Wait()
	s.finishSunnyCheckoutTask(task, result)
}

func (s *Server) finishSunnyCheckoutTask(task *Task, result map[string]any) {
	if s.finishCancelledTask(task, result, "用户已停止提链任务") {
		return
	}
	status := TaskSucceeded
	if intValue(result["success"], 0) == 0 {
		status = TaskFailed
	}
	finishedAt := time.Now()
	task.ResultJSON = dumpJSON(result)
	task.Status = status
	task.FinishedAt.Valid = true
	task.FinishedAt.Time = finishedAt
	// Complete only an active task. A cancel request may arrive after the
	// worker goroutines finish but before this write; the conditional update
	// preserves that request for the cancellation path to finalize.
	updated := s.db.Model(&Task{}).
		Where("id = ? AND status IN ?", task.ID, []string{TaskClaimed, TaskRunning}).
		Updates(map[string]any{
			"status":      status,
			"error":       "",
			"result_json": task.ResultJSON,
			"finished_at": finishedAt,
			"updated_at":  finishedAt,
		})
	if updated.RowsAffected == 0 {
		_ = s.finishCancelledTask(task, result, "用户已停止提链任务")
	}
}

func recordSunnyCheckoutResult(task *Task, result map[string]any, item map[string]any) {
	items, _ := result["items"].([]any)
	result["items"] = append(items, item)
	if text(item["status"]) == "succeeded" {
		result["success"] = intValue(result["success"], 0) + 1
	} else {
		result["failed"] = intValue(result["failed"], 0) + 1
	}
	task.ProgressCurrent++
	task.SuccessCount = intValue(result["success"], 0)
	task.ErrorCount = intValue(result["failed"], 0)
	// Persist partial items while the batch is still running so polling can
	// recover account results when an SSE connection misses an event.
	task.ResultJSON = dumpJSON(result)
}

func (s *Server) runSunnyCheckoutAttempt(ctx context.Context, task *Task, payload, row map[string]any, token string, secret checkoutSecret) map[string]any {
	email := text(row["email"])
	accountID := uint(intValue(row["session_id"], 0))
	rowIndex := intValue(row["index"], 0)
	if token == "" {
		s.appendCheckoutProgress(task, email, accountID, rowIndex, 100, "AT 为空或已失效")
		return map[string]any{"email": email, "status": "failed", "error": "AT 为空或已失效"}
	}
	item, err := s.requestSunnyCheckout(ctx, task, token, text(row["checkout_kind"]), payload, secret.Checkout, secret.Promotion, email, accountID, rowIndex)
	if err != nil {
		message := sanitizeCheckoutError(err.Error())
		s.appendCheckoutProgress(task, email, accountID, rowIndex, 100, message)
		s.appendTaskEvent(task.ID, fmt.Sprintf("账户 %s 提链失败", email), "log", "warning", map[string]any{"email": email, "error": message})
		return map[string]any{"email": email, "status": "failed", "error": message}
	}
	item["email"] = email
	item["status"] = "succeeded"
	s.appendCheckoutProgress(task, email, accountID, rowIndex, 100, "支付链接已提取")
	if detectedKind := normalizeSunnyCheckoutKind(text(item["checkout_kind"])); detectedKind != sunnyCheckoutUnknown {
		// The created Checkout session is the authoritative type for future
		// trial checks and PayPal branch selection.
		s.db.Model(&SunnyAccount{}).Where("email = ?", email).Update("checkout_kind", detectedKind)
	}
	// Keep the latest successful payment material on the account so the account
	// table remains useful after the task view is refreshed or reopened.
	if accountID > 0 {
		stored := map[string]any{
			"status": "succeeded", "email": email,
			"link_type": text(item["link_type"]), "payment_link": text(item["payment_link"]),
			"qr_data": text(item["qr_data"]), "qr_image": text(item["qr_image"]),
			"checkout_session_id": text(item["checkout_session_id"]),
			"country":             text(item["country"]), "currency": text(item["currency"]),
			"checkout_amount": item["checkout_amount"],
		}
		if text(item["link_type"]) == "gcash" {
			stored["payment_status"] = text(item["payment_status"])
			stored["gcash_order_id"] = text(item["gcash_order_id"])
			stored["payment_callback_path"] = text(item["payment_callback_path"])
			stored["payment_expires_at"] = item["payment_expires_at"]
			stored["gcash_authorization_url"] = text(item["gcash_authorization_url"])
			stored["gcash_net_auth_id"] = text(item["gcash_net_auth_id"])
			stored["gcash_client_id"] = text(item["gcash_client_id"])
			stored["qr_status"] = text(item["qr_status"])
			stored["qr_expires_at"] = item["qr_expires_at"]
		}
		s.db.Model(&SunnyAccount{}).Where("id = ? OR email = ?", accountID, email).Update("checkout_result_json", dumpJSON(stored))
	}
	return item
}

func (s *Server) requestSunnyCheckout(ctx context.Context, task *Task, token, checkoutKind string, payload map[string]any, checkoutProxies, promotionProxies []string, email string, accountID uint, rowIndex int) (map[string]any, error) {
	body := map[string]any{
		"token": token, "checkout_proxies": checkoutProxies, "promotion_proxies": promotionProxies,
		"checkout_kind": checkoutKind,
		"plan":          payload["plan"], "link_type": payload["link_type"], "country": payload["country"], "currency": payload["currency"],
		"retry_count": payload["retry_count"], "use_promo": payload["use_promo"], "promo_campaign": payload["promo_campaign"], "promo_country": payload["promo_country"],
		"promo_code": payload["promo_code"], "workspace_name": payload["workspace_name"], "workspace_id": payload["workspace_id"], "seat_quantity": payload["seat_quantity"],
		"price_interval": payload["price_interval"], "credit_quantity": payload["credit_quantity"], "ideal_bank": payload["ideal_bank"], "pix_tax_id": payload["pix_tax_id"], "pix_auto_kind": payload["pix_auto_kind"],
		"force_momo": payload["force_momo"],
	}
	data, _ := json.Marshal(body)
	workerURL := strings.TrimRight(strings.TrimSpace(os.Getenv("PYTHON_WORKER_URL")), "/")
	if workerURL == "" {
		workerURL = "http://127.0.0.1:8765"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, workerURL+"/checkout/jobs", bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if workerToken := secretValue("PYTHON_WORKER_TOKEN", "PYTHON_WORKER_TOKEN_FILE"); workerToken != "" {
		req.Header.Set("Authorization", "Bearer "+workerToken)
	}
	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("无法连接提链引擎: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("提链引擎 HTTP %d", resp.StatusCode)
	}
	var started map[string]any
	if json.Unmarshal(raw, &started) != nil || text(started["job_id"]) == "" {
		return nil, fmt.Errorf("提链引擎返回格式无效")
	}
	jobID := text(started["job_id"])
	workerLogSequence := 0
	s.appendCheckoutProgress(task, email, accountID, rowIndex, 8, "已提交提链引擎")
	for poll := 0; poll < 800; poll++ {
		timer := time.NewTimer(1500 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			_ = cancelSunnyCheckoutWorkerJob(context.Background(), workerURL, jobID)
			return nil, ctx.Err()
		case <-timer.C:
		}
		status, err := sunnyCheckoutWorkerStatus(ctx, client, workerURL, jobID)
		if err != nil {
			continue
		}
		if logs, ok := status["logs"].([]any); ok {
			for _, rawLog := range logs {
				entry, _ := rawLog.(map[string]any)
				sequence := intValue(entry["sequence"], 0)
				if sequence <= workerLogSequence {
					continue
				}
				if message := strings.TrimSpace(text(entry["message"])); message != "" {
					progress := 10 + minInt(80, workerLogSequence+1)
					s.appendCheckoutProgress(task, email, accountID, rowIndex, progress, message)
				}
				workerLogSequence = sequence
			}
		}
		switch text(status["status"]) {
		case "done":
			s.appendCheckoutProgress(task, email, accountID, rowIndex, 95, "提链引擎已返回结果，正在整理")
			if result, ok := status["result"].(map[string]any); ok {
				return result, nil
			}
			return nil, fmt.Errorf("提链引擎未返回结果")
		case "error":
			return nil, fmt.Errorf("%s", fallback(text(status["error"]), "提链引擎执行失败"))
		case "cancelled":
			return nil, fmt.Errorf("任务已取消")
		}
	}
	_ = cancelSunnyCheckoutWorkerJob(context.Background(), workerURL, jobID)
	return nil, fmt.Errorf("提链引擎执行超时")
}

func minInt(left, right int) int {
	if left < right {
		return left
	}
	return right
}

func (s *Server) appendCheckoutProgress(task *Task, email string, accountID uint, rowIndex, progress int, message string) {
	if task == nil {
		return
	}
	if progress < 0 {
		progress = 0
	}
	if progress > 100 {
		progress = 100
	}
	s.appendTaskEventWithContext(task.ID, message, "checkout_progress", "info", map[string]any{
		"email": email, "account_id": accountID, "index": rowIndex, "progress": progress, "current_log": message,
	}, TaskEventContext{Email: email, AccountID: accountID, Module: "checkout", Action: "checkout.progress", Scope: "account", SubjectType: "account"})
}

func sunnyCheckoutWorkerStatus(ctx context.Context, client *http.Client, workerURL, jobID string) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, workerURL+"/checkout/jobs/"+url.PathEscape(jobID), nil)
	if err != nil {
		return nil, err
	}
	if token := secretValue("PYTHON_WORKER_TOKEN", "PYTHON_WORKER_TOKEN_FILE"); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var result map[string]any
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&result) != nil {
		return nil, fmt.Errorf("提链引擎状态读取失败")
	}
	return result, nil
}

func cancelSunnyCheckoutWorkerJob(ctx context.Context, workerURL, jobID string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, workerURL+"/checkout/jobs/"+url.PathEscape(jobID)+"/cancel", nil)
	if err != nil {
		return err
	}
	if token := secretValue("PYTHON_WORKER_TOKEN", "PYTHON_WORKER_TOKEN_FILE"); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

var checkoutSecretPattern = regexp.MustCompile(`(?i)(https?://)[^\s/@:]+:[^\s/@]+@|eyJ[A-Za-z0-9_.-]{40,}`)
var sunnyGopayMidtransPath = regexp.MustCompile(`(?i)^/snap/v[34]/redirection/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/?$`)

func isSunnyGopayMidtransURL(value string) bool {
	parsed, err := url.Parse(strings.TrimSpace(value))
	return err == nil && strings.EqualFold(parsed.Scheme, "https") &&
		strings.EqualFold(strings.TrimSuffix(parsed.Host, "."), "app.midtrans.com") &&
		sunnyGopayMidtransPath.MatchString(parsed.EscapedPath())
}

func isSunnyBlikPaymentURL(value string) bool {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil || !strings.EqualFold(parsed.Scheme, "https") {
		return false
	}
	host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	path := strings.ToLower(parsed.EscapedPath())
	if host == "pay.openai.com" || host == "checkout.stripe.com" {
		// Stripe Hosted Checkout URLs contain signed/session state.  The worker
		// must preserve the provider URL exactly instead of appending synthetic
		// redirect_pm_type, lid or ui_mode query parameters.
		query := parsed.Query()
		return strings.HasPrefix(path, "/c/pay/cs_") &&
			!query.Has("redirect_pm_type") && !query.Has("lid") && !query.Has("ui_mode")
	}
	return (host == "chatgpt.com" || host == "chat.openai.com") &&
		strings.Contains(path, "/checkout/") && strings.Contains(path, "/oaics_")
}

func sanitizeCheckoutError(value string) string {
	clean := checkoutSecretPattern.ReplaceAllStringFunc(value, func(match string) string {
		if strings.HasPrefix(strings.ToLower(match), "http") {
			return strings.Split(match, "://")[0] + "://[PROXY]@"
		}
		return "[TOKEN]"
	})
	if len(clean) > 600 {
		clean = clean[:600]
	}
	return clean
}

func extractSunnyCheckoutResult(v map[string]any, provider string) map[string]any {
	out := map[string]any{"link_type": provider, "checkout_session_id": "", "payment_link": "", "qr_data": "", "qr_image": "", "raw_provider": ""}
	gopayMidtransURL := ""
	blikPaymentURL := ""
	if provider == "gcash" {
		out["qr_status"] = ""
		out["qr_expires_at"] = nil
		out["gcash_authorization_url"] = ""
		out["gcash_net_auth_id"] = ""
		out["gcash_client_id"] = ""
		out["payment_status"] = ""
		out["gcash_order_id"] = ""
		out["payment_callback_path"] = ""
		out["payment_expires_at"] = nil
	}
	var walk func(any)
	walk = func(x any) {
		switch n := x.(type) {
		case map[string]any:
			for k, val := range n {
				lk := strings.ToLower(k)
				if s, ok := val.(string); ok {
					if provider == "gopay" && isSunnyGopayMidtransURL(s) {
						gopayMidtransURL = strings.TrimSpace(s)
					}
					if provider == "blik" && (lk == "blik_payment_url" || lk == "provider_redirect_url") && isSunnyBlikPaymentURL(s) {
						blikPaymentURL = strings.TrimSpace(s)
					}
					if strings.Contains(lk, "checkout_session") || lk == "session_id" {
						out["checkout_session_id"] = s
					}
					if strings.Contains(lk, "qr") && strings.TrimSpace(s) != "" {
						if provider != "gcash" || (!strings.Contains(strings.ToLower(s), "m.gcash.com") && !strings.Contains(strings.ToLower(s), "checkoutshopper")) {
							out["qr_data"] = s
						}
					}
					if provider == "gcash" {
						switch strings.NewReplacer("_", "", "-", "").Replace(lk) {
						case "qrstatus":
							out["qr_status"] = s
						case "gcashauthorizationurl":
							out["gcash_authorization_url"] = s
						case "gcashnetauthid":
							out["gcash_net_auth_id"] = s
						case "gcashclientid":
							out["gcash_client_id"] = s
						case "paymentstatus":
							out["payment_status"] = s
						case "gcashorderid":
							out["gcash_order_id"] = s
						case "paymentcallbackpath":
							out["payment_callback_path"] = s
						}
					}
					if strings.Contains(lk, "url") || strings.Contains(lk, "link") || strings.Contains(lk, "redirect") {
						if strings.HasPrefix(s, "http") {
							out["payment_link"] = s
						}
					}
				} else if provider == "gcash" {
					switch strings.NewReplacer("_", "", "-", "").Replace(lk) {
					case "qrexpiresat":
						out["qr_expires_at"] = val
					case "paymentexpiresat":
						out["payment_expires_at"] = val
					}
				}
				walk(val)
			}
		case []any:
			for _, v := range n {
				walk(v)
			}
		}
	}
	walk(v)
	if gopayMidtransURL != "" {
		out["payment_link"] = gopayMidtransURL
	}
	if blikPaymentURL != "" {
		out["payment_link"] = blikPaymentURL
	}
	if text(out["payment_link"]) == "" {
		sid := text(out["checkout_session_id"])
		if sid != "" {
			out["payment_link"] = "https://chatgpt.com/checkout/openai_llc/" + sid
		}
	}
	if provider == "ph_short" && text(out["payment_link"]) != "" {
		out["payment_link"] = strings.Replace(text(out["payment_link"]), "/checkout/openai_llc/", "/checkout/", 1)
	}
	return out
}

func sunnyCheckoutResultJSON(raw string) map[string]any {
	result := map[string]any{}
	if strings.TrimSpace(raw) == "" || json.Unmarshal([]byte(raw), &result) != nil {
		return result
	}
	return result
}
