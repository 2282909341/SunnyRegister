package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"gorm.io/gorm"
)

const sunnyCfgDomainMailbox = "domain_mailbox"

var domainMailOTPPattern = regexp.MustCompile(`(?:^|\D)(\d{6})(?:\D|$)`)

func defaultDomainMailboxConfig() map[string]any {
	return map[string]any{
		"enabled":                  true,
		"enabled_for_registration": false,
		"enabled_for_rebinding":    false,
		"base_url":                 "",
		"auth_token":               "",
		"site_password":            "",
		"pickup_base_url":          "",
		"domain":                   "",
		"domains":                  []string{},
		"random_local_length":      12,
		"auto_add_user":            true,
		"retain_failed_mailboxes":  true,
	}
}

type domainMailClient struct {
	baseURL      string
	token        string
	sitePassword string
	client       *http.Client
}

func newDomainMailClient(cfg map[string]any) (*domainMailClient, error) {
	base := strings.TrimRight(strings.TrimSpace(text(cfg["base_url"])), "/")
	token := strings.TrimSpace(text(cfg["auth_token"]))
	sitePassword := strings.TrimSpace(text(cfg["site_password"]))
	if base == "" || token == "" || sitePassword == "" {
		return nil, fmt.Errorf("自建域名邮箱配置不完整：请填写 API 地址、PUBLIC_API_TOKEN、站点密码和邮箱域名")
	}
	if _, err := domainMailboxDomains(cfg); err != nil {
		return nil, err
	}
	parsed, err := url.Parse(base)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return nil, fmt.Errorf("自建域名邮箱 API 地址无效")
	}
	return &domainMailClient{baseURL: base, token: token, sitePassword: sitePassword, client: &http.Client{Timeout: 30 * time.Second}}, nil
}

func domainMailboxDomains(cfg map[string]any) ([]string, error) {
	values := make([]string, 0)
	domainsExplicitlyConfigured := false
	var appendValue func(any)
	appendValue = func(value any) {
		switch item := value.(type) {
		case []string:
			for _, entry := range item {
				appendValue(entry)
			}
		case []any:
			for _, entry := range item {
				appendValue(entry)
			}
		default:
			for _, entry := range strings.FieldsFunc(text(item), func(r rune) bool { return r == ',' || r == ';' || r == '\n' || r == '\r' }) {
				domain := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(entry, "@")))
				if domain != "" {
					values = append(values, domain)
				}
			}
		}
	}
	if raw, ok := cfg["domains"]; ok {
		switch value := raw.(type) {
		case string:
			domainsExplicitlyConfigured = true
		case []any:
			domainsExplicitlyConfigured = len(value) > 0
		case []string:
			domainsExplicitlyConfigured = len(value) > 0
		}
		appendValue(raw)
	}
	if len(values) == 0 && !domainsExplicitlyConfigured {
		appendValue(cfg["domain"])
	}
	unique := make([]string, 0, len(values))
	seen := map[string]bool{}
	for _, domain := range values {
		if seen[domain] {
			continue
		}
		if strings.ContainsAny(domain, " @\t\r\n") || !strings.Contains(domain, ".") {
			return nil, fmt.Errorf("自建域名无效：%s", domain)
		}
		seen[domain] = true
		unique = append(unique, domain)
	}
	if len(unique) == 0 {
		return nil, fmt.Errorf("自建域名邮箱配置不完整：请至少填写一个邮箱域名")
	}
	return unique, nil
}

var domainMailboxRotation uint64

func nextDomainMailboxDomain(cfg map[string]any) (string, error) {
	domains, err := domainMailboxDomains(cfg)
	if err != nil {
		return "", err
	}
	index := atomic.AddUint64(&domainMailboxRotation, 1) - 1
	return domains[index%uint64(len(domains))], nil
}

func domainMailResponseSummary(raw []byte) string {
	value := strings.Join(strings.Fields(strings.TrimSpace(string(raw))), " ")
	if len([]rune(value)) > 300 {
		value = string([]rune(value)[:300]) + "..."
	}
	return value
}

func domainMailPlainTextSuccess(value string) bool {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if normalized == "" || len([]rune(normalized)) > 300 || strings.Contains(normalized, "<html") || strings.Contains(normalized, "<!doctype") {
		return false
	}
	for _, marker := range []string{"失败", "错误", "无权限", "未授权", "unauthorized", "forbidden", "invalid", "error", "failed"} {
		if strings.Contains(normalized, marker) {
			return false
		}
	}
	if normalized == "ok" {
		return true
	}
	for _, marker := range []string{"成功", "success", "created", "创建完成", "添加完成"} {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	return false
}

func (c *domainMailClient) request(ctx context.Context, method, path string, body any, allowPlainTextSuccess bool) (any, error) {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = strings.NewReader(string(encoded))
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", c.token)
	req.Header.Set("X-Auth-Token", c.token)
	req.Header.Set("x-custom-auth", c.sitePassword)
	req.Header.Set("User-Agent", "SunnyRegister/1.0")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("自建域名邮箱请求失败：%w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	responseSummary := domainMailResponseSummary(raw)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("自建域名邮箱请求失败：HTTP %d：%s", resp.StatusCode, responseSummary)
	}
	var payload any
	if responseSummary != "" {
		if err := json.Unmarshal(raw, &payload); err != nil {
			if allowPlainTextSuccess && domainMailPlainTextSuccess(responseSummary) {
				return responseSummary, nil
			}
			return nil, fmt.Errorf("自建域名邮箱返回内容不是有效 JSON：%s", responseSummary)
		}
	}
	if obj, ok := payload.(map[string]any); ok {
		if code := text(obj["code"]); code != "" && code != "200" && code != "0" {
			return nil, fmt.Errorf("自建域名邮箱请求失败：%s", fallback(firstText(obj["message"], obj["error"], obj["detail"]), code))
		}
	}
	return payload, nil
}

func (c *domainMailClient) addUser(ctx context.Context, email string) error {
	password := randomDomainSecret(18)
	_, err := c.request(ctx, http.MethodPost, "/api/public/addUser", map[string]any{
		"list": []map[string]string{{"email": email, "password": password}},
	}, true)
	return err
}

func (c *domainMailClient) deleteUser(ctx context.Context, email string) error {
	var lastErr error
	for _, method := range []string{http.MethodDelete, http.MethodPost} {
		for _, body := range []any{
			map[string]any{"email": email},
			map[string]any{"emails": []string{email}},
			map[string]any{"list": []string{email}},
			map[string]any{"list": []map[string]string{{"email": email}}},
		} {
			_, err := c.request(ctx, method, "/api/public/deleteUser", body, true)
			if err == nil {
				return nil
			}
			lastErr = err
			if !strings.Contains(err.Error(), "HTTP 404") && !strings.Contains(err.Error(), "HTTP 405") && !strings.Contains(err.Error(), "HTTP 501") {
				return err
			}
		}
	}
	return lastErr
}

func (c *domainMailClient) listMessages(ctx context.Context, email string) ([]map[string]any, error) {
	payload, err := c.request(ctx, http.MethodPost, "/api/public/emailList", map[string]any{
		"toEmail": email, "timeSort": "desc", "type": 0, "isDel": 0, "num": 1, "size": 20,
	}, false)
	if err != nil {
		return nil, err
	}
	return domainMailMessageList(payload), nil
}

func domainMailMessageList(payload any) []map[string]any {
	if list, ok := payload.([]any); ok {
		return domainMailMapList(list)
	}
	if obj, ok := payload.(map[string]any); ok {
		for _, key := range []string{"data", "items", "messages", "result", "list", "rows", "records"} {
			if found := domainMailMessageList(obj[key]); len(found) > 0 {
				return found
			}
		}
	}
	return nil
}

func domainMailMapList(raw []any) []map[string]any {
	items := make([]map[string]any, 0, len(raw))
	for _, value := range raw {
		if item, ok := value.(map[string]any); ok {
			items = append(items, item)
		}
	}
	return items
}

func domainMailMessageCode(message map[string]any) string {
	for _, key := range []string{"body", "html", "content", "bodyPreview", "text", "subject"} {
		if match := domainMailOTPPattern.FindStringSubmatch(domainMailPlainText(text(message[key]))); len(match) > 1 {
			return match[1]
		}
	}
	for _, key := range []string{"verificationCode", "verification_code", "otp", "code"} {
		value := strings.TrimSpace(text(message[key]))
		if len(value) == 6 && domainMailOTPPattern.MatchString(value) {
			return value
		}
	}
	return ""
}

var domainMailHTMLTagPattern = regexp.MustCompile(`(?is)<(?:script|style)\b[^>]*>.*?</(?:script|style)>|<[^>]+>`)

func domainMailPlainText(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || (!strings.Contains(value, "<") && !strings.Contains(value, ">")) {
		return value
	}
	return strings.Join(strings.Fields(html.UnescapeString(domainMailHTMLTagPattern.ReplaceAllString(value, " "))), " ")
}

func domainMailMessageHTML(message map[string]any) string {
	for _, key := range []string{"html", "bodyPreview", "body_preview", "content", "body"} {
		value := strings.TrimSpace(text(message[key]))
		if strings.Contains(value, "<") && strings.Contains(value, ">") {
			return value
		}
	}
	return ""
}

func domainMailItems(messages []map[string]any, email string) []map[string]any {
	items := make([]map[string]any, 0, len(messages))
	for _, message := range messages {
		body := domainMailPlainText(firstText(message["text"], message["body"], message["content"], message["html"], message["bodyPreview"]))
		bodyPreview := domainMailPlainText(firstText(message["text"], message["body"], message["content"], message["bodyPreview"], message["html"]))
		items = append(items, map[string]any{
			"id":           firstText(message["emailId"], message["id"], message["messageId"]),
			"email":        firstText(message["toEmail"], message["recipient"], message["to"], email),
			"folder":       "自建域名邮箱",
			"subject":      text(message["subject"]),
			"from":         firstText(message["sendEmail"], message["sender"], message["from"]),
			"to":           firstText(message["toEmail"], message["recipient"], message["to"], email),
			"date":         firstText(message["createTime"], message["receivedAt"], message["received_at"], message["date"]),
			"body":         body,
			"body_preview": bodyPreview,
			"raw_html":     domainMailMessageHTML(message),
			"otp":          domainMailMessageCode(message),
			"source":       "domain_api",
		})
	}
	return items
}

func domainMailMessageReceivedAt(message map[string]any) (string, time.Time, bool) {
	values := []any{message["receivedAt"], message["received_at"], message["createTime"], message["created_at"], message["timestamp"], message["time"], message["date"]}
	receivedAt := firstText(values...)
	if receivedAt == "" {
		return "", time.Time{}, false
	}
	if numeric, err := strconv.ParseFloat(receivedAt, 64); err == nil && numeric > 0 {
		// Providers commonly return Unix seconds, milliseconds, or microseconds.
		for numeric > 1e11 {
			numeric /= 1000
		}
		return receivedAt, time.Unix(int64(numeric), int64((numeric-float64(int64(numeric)))*1e9)), true
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05Z07:00", "2006-01-02 15:04:05"} {
		parsed, err := time.Parse(layout, receivedAt)
		if err == nil {
			return receivedAt, parsed, true
		}
	}
	return receivedAt, time.Time{}, false
}

func firstDomainMailValue(values ...any) any {
	for _, value := range values {
		if value != nil && text(value) != "" {
			return value
		}
	}
	return ""
}

func domainMailPublicItems(messages []map[string]any, email string, now time.Time) []map[string]any {
	type messageWithTime struct {
		item map[string]any
		at   time.Time
	}
	cutoff := now.Add(-72 * time.Hour)
	filtered := make([]messageWithTime, 0, len(messages))
	for _, message := range messages {
		receivedAt, parsedAt, ok := domainMailMessageReceivedAt(message)
		if !ok {
			// Keep messages with an unsupported provider timestamp. The worker
			// already establishes a baseline key before begin(), so retaining an
			// unknown-time message is safer than dropping a newly delivered OTP.
			item := map[string]any{
				"id":          firstDomainMailValue(message["id"], message["emailId"], message["messageId"]),
				"sender":      firstText(message["sender"], message["sendEmail"], message["from"]),
				"recipient":   firstText(message["recipient"], message["toEmail"], message["to"], email),
				"receivedAt":  receivedAt,
				"subject":     text(message["subject"]),
				"bodyPreview": domainMailPlainText(firstText(message["text"], message["body"], message["content"], message["bodyPreview"], message["body_preview"], message["html"])),
			}
			if code := domainMailMessageCode(message); code != "" {
				item["verificationCode"] = code
			}
			filtered = append(filtered, messageWithTime{item: item, at: now})
			continue
		}
		if parsedAt.Before(cutoff) || parsedAt.After(now.Add(5*time.Minute)) {
			continue
		}
		bodyPreview := domainMailPlainText(firstText(message["text"], message["body"], message["content"], message["bodyPreview"], message["body_preview"], message["html"]))
		item := map[string]any{
			"id":          firstDomainMailValue(message["id"], message["emailId"], message["messageId"]),
			"sender":      firstText(message["sender"], message["sendEmail"], message["from"]),
			"recipient":   firstText(message["recipient"], message["toEmail"], message["to"], email),
			"receivedAt":  receivedAt,
			"subject":     text(message["subject"]),
			"bodyPreview": bodyPreview,
		}
		if code := domainMailMessageCode(message); code != "" {
			item["verificationCode"] = code
		}
		filtered = append(filtered, messageWithTime{item: item, at: parsedAt})
	}
	sort.SliceStable(filtered, func(i, j int) bool { return filtered[i].at.After(filtered[j].at) })
	if len(filtered) > 10 {
		filtered = filtered[:10]
	}
	items := make([]map[string]any, 0, len(filtered))
	for _, message := range filtered {
		items = append(items, message.item)
	}
	return items
}

func randomDomainSecret(length int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	if length < 12 {
		length = 12
	}
	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		return randomID("domain")
	}
	for index := range buf {
		buf[index] = alphabet[int(buf[index])%len(alphabet)]
	}
	return string(buf)
}

func randomDomainEmail(domain string, length int) string {
	if length < 6 {
		length = 6
	}
	if length > 32 {
		length = 32
	}
	return strings.ToLower(randomDomainSecret(length)) + "@" + strings.ToLower(strings.TrimSpace(domain))
}

func domainMailboxCredential(baseURL, token string) string {
	return dumpJSON(map[string]string{"base_url": strings.TrimRight(strings.TrimSpace(baseURL), "/"), "auth_token": strings.TrimSpace(token)})
}

func randomDomainPickupToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("生成邮箱取件 Token 失败：%w", err)
	}
	return "dmsk_" + base64.RawURLEncoding.EncodeToString(raw), nil
}

func domainMailboxPickupTokenHash(token string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(token)))
	return fmt.Sprintf("%x", sum[:])
}

func domainMailboxPickupBaseURL(cfg map[string]any) (string, error) {
	base := strings.TrimRight(strings.TrimSpace(firstText(cfg["pickup_base_url"], os.Getenv("SUNNY_PUBLIC_ORIGIN"))), "/")
	parsed, err := url.Parse(base)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return "", fmt.Errorf("请填写可公网访问的 SunnyRegister 取件 API 地址")
	}
	return base, nil
}

func domainMailboxPickupCredential(baseURL, email, token string) (string, error) {
	base, err := url.Parse(strings.TrimRight(strings.TrimSpace(baseURL), "/") + "/api/sunny/domain-mail/pickup")
	if err != nil || (base.Scheme != "http" && base.Scheme != "https") || base.Host == "" {
		return "", fmt.Errorf("SunnyRegister 取件 API 地址无效")
	}
	query := base.Query()
	query.Set("email", strings.ToLower(strings.TrimSpace(email)))
	query.Set("token", strings.TrimSpace(token))
	base.RawQuery = query.Encode()
	return base.String(), nil
}

func parseDomainMailboxPickupCredential(value string) (string, string, error) {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return "", "", fmt.Errorf("自建域名邮箱取件 URL 无效")
	}
	email := strings.ToLower(strings.TrimSpace(parsed.Query().Get("email")))
	token := strings.TrimSpace(parsed.Query().Get("token"))
	if email == "" || !strings.Contains(email, "@") || token == "" {
		return "", "", fmt.Errorf("自建域名邮箱取件 URL 缺少邮箱或 Token")
	}
	return email, token, nil
}

func validateDomainMailboxAccessKey(value, email string) error {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://") {
		credentialEmail, _, err := parseDomainMailboxPickupCredential(value)
		if err != nil {
			return err
		}
		if sunnyEmailKey(credentialEmail) != sunnyEmailKey(email) {
			return fmt.Errorf("自建域名邮箱取件 URL 与邮箱名不匹配")
		}
		return nil
	}
	_, _, err := parseDomainMailboxCredential(value)
	return err
}

func domainMailboxTokenHashFromCredential(value, email string) string {
	credentialEmail, token, err := parseDomainMailboxPickupCredential(value)
	if err != nil || sunnyEmailKey(credentialEmail) != sunnyEmailKey(email) {
		return ""
	}
	return domainMailboxPickupTokenHash(token)
}

func parseDomainMailboxCredential(value string) (string, string, error) {
	var payload map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(value)), &payload); err != nil {
		return "", "", fmt.Errorf("自建域名邮箱凭证格式无效")
	}
	base := strings.TrimRight(strings.TrimSpace(text(payload["base_url"])), "/")
	token := strings.TrimSpace(text(payload["auth_token"]))
	if base == "" || token == "" {
		return "", "", fmt.Errorf("自建域名邮箱凭证缺少 API 地址或 Authorization Token")
	}
	return base, token, nil
}

func domainMailPayload(messages []map[string]any, email string, limit int) map[string]any {
	items := domainMailItems(messages, email)
	if limit < 1 || limit > 50 {
		limit = 5
	}
	if len(items) > limit {
		items = items[:limit]
	}
	return map[string]any{
		"email": email, "mailbox_type": "domain", "mailbox_channel": "domain_api", "mail_protocol": "domain_api",
		"items": items, "count": len(items), "limit": limit,
	}
}

func domainMailPublicPayload(messages []map[string]any, email string) map[string]any {
	return map[string]any{"items": domainMailPublicItems(messages, email, time.Now())}
}

func (s *Server) domainMailboxMessagesForToken(ctx context.Context, email, token string) ([]map[string]any, error) {
	var mailbox SunnyMailbox
	requestedEmail := strings.TrimSpace(email)
	if err := s.db.Where("LOWER(email) = ? OR LOWER(rebind_email) = ?", sunnyEmailKey(requestedEmail), sunnyEmailKey(requestedEmail)).First(&mailbox).Error; err != nil {
		return nil, fmt.Errorf("邮箱或取件 Token 无效")
	}
	effectiveEmail := strings.TrimSpace(mailbox.Email)
	if strings.TrimSpace(mailbox.RebindEmail) != "" {
		effectiveEmail = strings.TrimSpace(mailbox.RebindEmail)
	}
	if sunnyEmailKey(requestedEmail) != sunnyEmailKey(effectiveEmail) {
		return nil, fmt.Errorf("邮箱或取件 Token 无效")
	}
	expectedHash := strings.TrimSpace(mailbox.PickupTokenHash)
	actualHash := domainMailboxPickupTokenHash(token)
	if expectedHash == "" || subtle.ConstantTimeCompare([]byte(expectedHash), []byte(actualHash)) != 1 {
		return nil, fmt.Errorf("邮箱或取件 Token 无效")
	}
	hasRebindCredential := strings.TrimSpace(mailbox.RebindEmail) != "" && strings.TrimSpace(mailbox.RebindMailboxAPI) != ""
	if !hasRebindCredential && (normalizeSunnyMailboxType(mailbox.MailboxType) != "domain" || normalizeSunnyMailboxChannel(mailbox.MailboxType, mailbox.MailboxChannel) != "domain_api") {
		return nil, fmt.Errorf("邮箱或取件 Token 无效")
	}
	if !mailbox.Enabled {
		return nil, fmt.Errorf("该邮箱已停用")
	}
	cfg := mergeConfig(defaultDomainMailboxConfig(), s.sunnyGetConfig(sunnyCfgDomainMailbox, defaultDomainMailboxConfig()))
	if !boolValue(cfg["enabled"], true) {
		return nil, fmt.Errorf("自建域名邮箱池已关闭")
	}
	client, err := newDomainMailClient(cfg)
	if err != nil {
		return nil, err
	}
	return client.listMessages(ctx, effectiveEmail)
}

func (s *Server) domainMailLatestMail(accessKey, email string, limit int) (map[string]any, error) {
	var messages []map[string]any
	var err error
	trimmed := strings.TrimSpace(accessKey)
	if strings.HasPrefix(trimmed, "http://") || strings.HasPrefix(trimmed, "https://") {
		credentialEmail, token, parseErr := parseDomainMailboxPickupCredential(trimmed)
		if parseErr != nil {
			return nil, parseErr
		}
		if sunnyEmailKey(credentialEmail) != sunnyEmailKey(email) {
			return nil, fmt.Errorf("自建域名邮箱取件 URL 与邮箱名不匹配")
		}
		messages, err = s.domainMailboxMessagesForToken(context.Background(), email, token)
	} else {
		base, token, parseErr := parseDomainMailboxCredential(trimmed)
		if parseErr != nil {
			return nil, parseErr
		}
		cfg := mergeConfig(defaultDomainMailboxConfig(), s.sunnyGetConfig(sunnyCfgDomainMailbox, defaultDomainMailboxConfig()))
		client := &domainMailClient{baseURL: base, token: token, sitePassword: strings.TrimSpace(text(cfg["site_password"])), client: &http.Client{Timeout: 30 * time.Second}}
		messages, err = client.listMessages(context.Background(), email)
	}
	if err != nil {
		return nil, err
	}
	return domainMailPayload(messages, email, limit), nil
}

func (s *Server) domainMailboxPickupHandler(w http.ResponseWriter, r *http.Request) {
	email := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("email")))
	token := strings.TrimSpace(r.URL.Query().Get("token"))
	if email == "" || token == "" {
		writeError(w, http.StatusBadRequest, "缺少邮箱或取件 Token")
		return
	}
	messages, err := s.domainMailboxMessagesForToken(r.Context(), email, token)
	if err != nil {
		if strings.Contains(err.Error(), "自建域名邮箱请求失败") {
			// 上游 CloudMail 请求/网络失败是瞬时的，返回 502 让 Python 侧有限重试；
			// 只有本地校验类错误（凭证无效/邮箱停用/池关闭）才返回 403 终止。
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, domainMailPublicPayload(messages, email))
}

func (s *Server) createDomainMailbox(ctx context.Context, cfg map[string]any, client *domainMailClient, groupID uint) (SunnyMailbox, error) {
	pickupBaseURL, err := domainMailboxPickupBaseURL(cfg)
	if err != nil {
		return SunnyMailbox{}, err
	}
	length := intValue(cfg["random_local_length"], 12)
	var lastErr error
	for attempt := 0; attempt < 5; attempt++ {
		domain, domainErr := nextDomainMailboxDomain(cfg)
		if domainErr != nil {
			return SunnyMailbox{}, domainErr
		}
		email := randomDomainEmail(domain, length)
		var existing SunnyMailbox
		if s.db.Where("LOWER(email) = ?", sunnyEmailKey(email)).First(&existing).Error == nil {
			continue
		}
		pickupToken, tokenErr := randomDomainPickupToken()
		if tokenErr != nil {
			return SunnyMailbox{}, tokenErr
		}
		credential, credentialErr := domainMailboxPickupCredential(pickupBaseURL, email, pickupToken)
		if credentialErr != nil {
			return SunnyMailbox{}, credentialErr
		}
		if boolValue(cfg["auto_add_user"], true) {
			if lastErr = client.addUser(ctx, email); lastErr != nil {
				continue
			}
		}
		mailbox := SunnyMailbox{
			GroupID: groupID, Email: email, MailboxType: "domain", MailboxChannel: "domain_api",
			AccessKey: credential, PickupTokenHash: domainMailboxPickupTokenHash(pickupToken),
			Raw: sunnyURLAPIRaw(email, credential), AccountType: "free", Status: "未注册", Enabled: true, LatestMailJSON: "{}",
		}
		if lastErr = s.db.Create(&mailbox).Error; lastErr == nil {
			return mailbox, nil
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("生成邮箱失败")
	}
	return SunnyMailbox{}, lastErr
}

func (s *Server) migrateLegacyDomainMailboxCredentials(cfg map[string]any) (int, error) {
	pickupBaseURL, err := domainMailboxPickupBaseURL(cfg)
	if err != nil {
		return 0, err
	}
	var mailboxes []SunnyMailbox
	if err := s.db.Where("mailbox_type = ?", "domain").Find(&mailboxes).Error; err != nil {
		return 0, err
	}
	migrated := 0
	err = s.db.Transaction(func(tx *gorm.DB) error {
		for _, mailbox := range mailboxes {
			if normalizeSunnyMailboxChannel(mailbox.MailboxType, mailbox.MailboxChannel) != "domain_api" {
				continue
			}
			accessKey := strings.TrimSpace(mailbox.AccessKey)
			if credentialEmail, pickupToken, parseErr := parseDomainMailboxPickupCredential(accessKey); parseErr == nil && sunnyEmailKey(credentialEmail) == sunnyEmailKey(mailbox.Email) {
				hash := domainMailboxPickupTokenHash(pickupToken)
				expectedCredential, credentialErr := domainMailboxPickupCredential(pickupBaseURL, mailbox.Email, pickupToken)
				if credentialErr != nil {
					return credentialErr
				}
				if mailbox.PickupTokenHash == hash && accessKey == expectedCredential {
					continue
				}
				if err := tx.Model(&SunnyMailbox{}).Where("id = ?", mailbox.ID).Updates(map[string]any{
					"access_key": expectedCredential, "pickup_token_hash": hash,
					"raw": sunnyURLAPIRaw(mailbox.Email, expectedCredential), "updated_at": time.Now(),
				}).Error; err != nil {
					return err
				}
				migrated++
				continue
			}
			if _, _, parseErr := parseDomainMailboxCredential(accessKey); parseErr != nil {
				continue
			}
			pickupToken, tokenErr := randomDomainPickupToken()
			if tokenErr != nil {
				return tokenErr
			}
			credential, credentialErr := domainMailboxPickupCredential(pickupBaseURL, mailbox.Email, pickupToken)
			if credentialErr != nil {
				return credentialErr
			}
			if err := tx.Model(&SunnyMailbox{}).Where("id = ?", mailbox.ID).Updates(map[string]any{
				"access_key": credential, "pickup_token_hash": domainMailboxPickupTokenHash(pickupToken),
				"raw": sunnyURLAPIRaw(mailbox.Email, credential), "updated_at": time.Now(),
			}).Error; err != nil {
				return err
			}
			migrated++
		}
		return nil
	})
	return migrated, err
}

func (s *Server) domainMailboxConfigHandler(w http.ResponseWriter, r *http.Request, parts []string) {
	if len(parts) == 1 && parts[0] == "config" && r.Method == http.MethodGet {
		cfg := mergeConfig(defaultDomainMailboxConfig(), s.sunnyGetConfig(sunnyCfgDomainMailbox, defaultDomainMailboxConfig()))
		if domains, err := domainMailboxDomains(cfg); err == nil {
			cfg["domains"] = domains
			cfg["domain"] = domains[0]
		}
		cfg["auth_token_configured"] = strings.TrimSpace(text(cfg["auth_token"])) != ""
		cfg["site_password_configured"] = strings.TrimSpace(text(cfg["site_password"])) != ""
		cfg["auth_token"] = ""
		cfg["site_password"] = ""
		writeJSON(w, http.StatusOK, cfg)
		return
	}
	if len(parts) == 1 && parts[0] == "config" && r.Method == http.MethodPut {
		body, _ := parseBody(r)
		if strings.TrimSpace(text(body["auth_token"])) == "" {
			current := mergeConfig(defaultDomainMailboxConfig(), s.sunnyGetConfig(sunnyCfgDomainMailbox, defaultDomainMailboxConfig()))
			body["auth_token"] = text(current["auth_token"])
		}
		if strings.TrimSpace(text(body["site_password"])) == "" {
			current := mergeConfig(defaultDomainMailboxConfig(), s.sunnyGetConfig(sunnyCfgDomainMailbox, defaultDomainMailboxConfig()))
			body["site_password"] = text(current["site_password"])
		}
		cfg := mergeConfig(defaultDomainMailboxConfig(), body)
		domains, domainErr := domainMailboxDomains(cfg)
		if domainErr != nil {
			writeError(w, http.StatusBadRequest, domainErr.Error())
			return
		}
		cfg["domains"] = domains
		cfg["domain"] = domains[0]
		s.sunnySaveConfig(sunnyCfgDomainMailbox, cfg)
		migrated := 0
		if _, pickupErr := domainMailboxPickupBaseURL(cfg); pickupErr == nil {
			var migrationErr error
			migrated, migrationErr = s.migrateLegacyDomainMailboxCredentials(cfg)
			if migrationErr != nil {
				writeError(w, http.StatusInternalServerError, "迁移旧域名邮箱取件凭证失败："+migrationErr.Error())
				return
			}
		}
		cfg["auth_token_configured"] = strings.TrimSpace(text(cfg["auth_token"])) != ""
		cfg["site_password_configured"] = strings.TrimSpace(text(cfg["site_password"])) != ""
		cfg["auth_token"] = ""
		cfg["site_password"] = ""
		cfg["migrated_mailboxes"] = migrated
		writeJSON(w, http.StatusOK, cfg)
		return
	}
	if len(parts) != 1 || r.Method != http.MethodPost {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	cfg := mergeConfig(defaultDomainMailboxConfig(), s.sunnyGetConfig(sunnyCfgDomainMailbox, defaultDomainMailboxConfig()))
	if body, _ := parseBody(r); body != nil {
		enabled := cfg["enabled"]
		if strings.TrimSpace(text(body["auth_token"])) == "" {
			body["auth_token"] = text(cfg["auth_token"])
		}
		if strings.TrimSpace(text(body["site_password"])) == "" {
			body["site_password"] = text(cfg["site_password"])
		}
		cfg = mergeConfig(cfg, body)
		// Operational requests may test unsaved connection fields, but the
		// persisted master switch cannot be bypassed through request payloads.
		cfg["enabled"] = enabled
	}
	client, err := newDomainMailClient(cfg)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	switch parts[0] {
	case "check":
		_, err = client.listMessages(ctx, "healthcheck@"+strings.TrimSpace(text(cfg["domain"])))
		if err == nil {
			writeJSON(w, http.StatusOK, map[string]any{"ok": true, "domain": text(cfg["domain"]), "domains": cfg["domains"]})
			return
		}
	case "generate":
		if !boolValue(cfg["enabled"], true) {
			writeError(w, http.StatusBadRequest, "自建域名邮箱池已关闭，请先在邮箱配置中启用")
			return
		}
		var mailbox SunnyMailbox
		mailbox, err = s.createDomainMailbox(ctx, cfg, client, s.sunnyEnsureDefaultGroup())
		if err == nil {
			writeJSON(w, http.StatusOK, map[string]any{"id": mailbox.ID, "email": mailbox.Email, "mailbox_type": mailbox.MailboxType, "mailbox_channel": mailbox.MailboxChannel})
			return
		}
	default:
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeError(w, http.StatusBadRequest, "自建域名邮箱操作失败")
}

func (s *Server) validateDomainMailboxRegistration(body map[string]any) error {
	cfg := mergeConfig(defaultDomainMailboxConfig(), s.sunnyGetConfig(sunnyCfgDomainMailbox, defaultDomainMailboxConfig()))
	if !boolValue(cfg["enabled"], true) {
		return fmt.Errorf("自建域名邮箱池已关闭，请先在邮箱配置中启用")
	}
	if !boolValue(cfg["enabled_for_registration"], false) {
		return fmt.Errorf("自建域名邮箱未启用账户注册，请先在邮箱配置中启用")
	}
	if _, err := newDomainMailClient(cfg); err != nil {
		return err
	}
	if _, err := domainMailboxPickupBaseURL(cfg); err != nil {
		return err
	}
	count := intValue(body["count"], 1)
	if count < 1 || count > 200 {
		return fmt.Errorf("自建域名邮箱本次生成数量必须在 1 到 200 之间")
	}
	return nil
}

func (s *Server) prepareDomainMailboxRegistration(body map[string]any) error {
	if err := s.validateDomainMailboxRegistration(body); err != nil {
		return err
	}
	cfg := s.sunnyGetConfig(sunnyCfgDomainMailbox, defaultDomainMailboxConfig())
	client, err := newDomainMailClient(cfg)
	if err != nil {
		return err
	}
	count := intValue(body["count"], 1)
	groupName := "domain-api-" + time.Now().Format("01-02")
	var group SunnyMailboxGroup
	if err := s.db.Where("name = ?", groupName).First(&group).Error; err != nil {
		group = SunnyMailboxGroup{Name: groupName, Description: "自建域名邮箱 API 自动生成"}
		if err := s.db.Create(&group).Error; err != nil {
			return fmt.Errorf("创建自建域名邮箱分组失败：%w", err)
		}
	}
	ids := make([]uint, 0, count)
	created := make([]uint, 0, count)
	for index := 0; index < count; index++ {
		mailbox, createErr := s.createDomainMailbox(context.Background(), cfg, client, group.ID)
		if createErr != nil || mailbox.ID == 0 {
			cleanupErrors := make([]string, 0)
			for _, id := range created {
				var generated SunnyMailbox
				if s.db.First(&generated, id).Error != nil {
					continue
				}
				if boolValue(cfg["retain_failed_mailboxes"], true) {
					s.db.Model(&SunnyMailbox{}).Where("id = ?", id).Updates(map[string]any{"status": "失败", "last_error": "批量生成域名邮箱未完成"})
					continue
				}
				if deleteErr := client.deleteUser(context.Background(), generated.Email); deleteErr != nil {
					cleanupErrors = append(cleanupErrors, generated.Email+" CloudMail 删除失败："+deleteErr.Error())
				}
				if localErr := s.db.Delete(&SunnyMailbox{}, id).Error; localErr != nil {
					cleanupErrors = append(cleanupErrors, generated.Email+" 本地记录删除失败："+localErr.Error())
				}
			}
			if createErr == nil {
				createErr = fmt.Errorf("生成邮箱失败")
			}
			if len(cleanupErrors) > 0 {
				return fmt.Errorf("自建域名邮箱第 %d 个生成失败：%w；失败邮箱清理未完全完成：%s", index+1, createErr, strings.Join(cleanupErrors, "；"))
			}
			return fmt.Errorf("自建域名邮箱第 %d 个生成失败：%w", index+1, createErr)
		}
		created = append(created, mailbox.ID)
		ids = append(ids, mailbox.ID)
	}
	body["mailbox_ids"] = ids
	return nil
}
