package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var (
	icmeigoAPIBaseURL  = "https://ic.meiguo.lol"
	icmeigoOTPPattern  = regexp.MustCompile(`(?m)(?:^|\D)(\d{6})(?:\D|$)`)
	icmeigoOpenAIPattern = regexp.MustCompile(`(?i)openai|chatgpt`)
)

func icmeigoHTTPClient(proxyURL string) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if strings.TrimSpace(proxyURL) != "" {
		if parsed, err := url.Parse(proxyURL); err == nil {
			transport.Proxy = http.ProxyURL(parsed)
		}
	}
	return &http.Client{Timeout: 30 * time.Second, Transport: transport}
}

// icmeigoBearerJSON performs a POST with an Authorization: Bearer header and a JSON body.
func icmeigoBearerPOST(client *http.Client, accessKey, endpoint string, bodyValue map[string]any) (int, map[string]any, error) {
	raw, _ := json.Marshal(bodyValue)
	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(icmeigoAPIBaseURL, "/")+endpoint, bytes.NewReader(raw))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessKey)
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	payload := map[string]any{}
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if len(bodyBytes) > 0 {
		_ = json.Unmarshal(bodyBytes, &payload)
	}
	return resp.StatusCode, payload, nil
}

// icmeigoBearerGET performs a GET with an Authorization: Bearer header (used by the quota endpoint).
func icmeigoBearerGET(client *http.Client, accessKey, endpoint string) (int, map[string]any, error) {
	req, err := http.NewRequest(http.MethodGet, strings.TrimRight(icmeigoAPIBaseURL, "/")+endpoint, nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessKey)
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	payload := map[string]any{}
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if len(bodyBytes) > 0 {
		_ = json.Unmarshal(bodyBytes, &payload)
	}
	return resp.StatusCode, payload, nil
}

// icmeigoQuota reads a redeem code's quota. If the code is invalid, a terminal error is returned.
func icmeigoQuota(client *http.Client, accessKey string) (map[string]any, error) {
	status, payload, err := icmeigoBearerGET(client, accessKey, "/api/hme/quota")
	if err != nil {
		return nil, &outlookMailError{Code: "mailbox_network_error", Category: "network", HTTPStatus: http.StatusServiceUnavailable, UserMessage: "iCloud 邮箱渠道网络连接失败，请检查服务器出网", Detail: err.Error()}
	}
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		return nil, &outlookMailError{Code: "mailbox_credential_invalid", Category: "credential", HTTPStatus: http.StatusUnprocessableEntity, UserMessage: "iCloud 邮箱查询 Key 无效，请检查 ic.meigo.lol 卡密", Detail: fmt.Sprintf("HTTP %d", status), Terminal: true}
	}
	if status < 200 || status >= 300 {
		return nil, &outlookMailError{Code: "mailbox_provider_failed", Category: "service", HTTPStatus: http.StatusBadGateway, UserMessage: "iCloud 邮箱渠道请求失败，请稍后重试", Detail: fmt.Sprintf("HTTP %d", status)}
	}
	data, _ := payload["data"].(map[string]any)
	return data, nil
}

// icmeigoGenerate creates one hidden mailbox for a redeem code and returns its address.
func icmeigoGenerate(client *http.Client, accessKey string) (string, error) {
	status, payload, err := icmeigoBearerPOST(client, accessKey, "/api/hme/generate", map[string]any{})
	if err != nil {
		return "", &outlookMailError{Code: "mailbox_network_error", Category: "network", HTTPStatus: http.StatusServiceUnavailable, UserMessage: "iCloud 邮箱渠道网络连接失败，请检查服务器出网", Detail: err.Error()}
	}
	detail := firstText(payload["error"], payload["message"], fmt.Sprintf("HTTP %d", status))
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		return "", &outlookMailError{Code: "mailbox_credential_invalid", Category: "credential", HTTPStatus: http.StatusUnprocessableEntity, UserMessage: "iCloud 邮箱查询 Key 无效，请检查 ic.meigo.lol 卡密", Detail: detail, Terminal: true}
	}
	upstreamCode := strings.ToUpper(strings.TrimSpace(text(payload["code"])))
	detailLower := strings.ToLower(detail)
	if upstreamCode != "" || status == http.StatusTooManyRequests || strings.Contains(detailLower, "quota") || strings.Contains(detailLower, "concurrency") || strings.Contains(detail, "并发") || strings.Contains(detail, "额度") {
		// 并发已满与额度用完是两种状态：并发满时该卡名下完成密码+2FA 的邮箱
		// 释放并发槽后还能继续生成；额度用完则只能停止。
		if upstreamCode == "API_CONCURRENCY_LIMIT" || strings.Contains(detail, "并发") {
			return "", &outlookMailError{Code: "mailbox_concurrency_limit", Category: "service", HTTPStatus: http.StatusServiceUnavailable, UserMessage: "卡密并发已满，请释放邮箱后再生成", Detail: detail}
		}
		return "", &outlookMailError{Code: "mailbox_provider_busy", Category: "service", HTTPStatus: http.StatusServiceUnavailable, UserMessage: "该兑换码额度已用完", Detail: detail}
	}
	if status < 200 || status >= 300 {
		return "", &outlookMailError{Code: "mailbox_provider_failed", Category: "service", HTTPStatus: http.StatusBadGateway, UserMessage: "iCloud 邮箱渠道请求失败，请稍后重试", Detail: fmt.Sprintf("HTTP %d", status)}
	}
	data, _ := payload["data"].(map[string]any)
	email := strings.TrimSpace(text(data["email"]))
	if email == "" || !strings.Contains(email, "@") {
		return "", &outlookMailError{Code: "mailbox_service_response_invalid", Category: "service", HTTPStatus: http.StatusBadGateway, UserMessage: "iCloud 邮箱渠道返回了无法解析的邮箱地址，请稍后重试"}
	}
	return email, nil
}

// icmeigoReleaseMailbox frees the concurrency slot held by a generated mailbox.
// ic.meigo.lol grants each redeem code a tiny concurrency budget (often 1);
// generate() occupies one slot per mailbox and the API only frees it via
// /api/hme/release-all. Releasing right after generation lets one card expand
// to its full remaining quota in a single import instead of stopping after the
// first mailbox. Releasing does not refund the quota, and the mailbox keeps
// receiving mail, so the registration flow is unaffected.
func icmeigoReleaseMailbox(client *http.Client, accessKey, email string) error {
	status, payload, err := icmeigoBearerPOST(client, accessKey, "/api/hme/release-all", map[string]any{"email": email})
	if err != nil {
		return &outlookMailError{Code: "mailbox_network_error", Category: "network", HTTPStatus: http.StatusServiceUnavailable, UserMessage: "iCloud 邮箱渠道网络连接失败", Detail: err.Error()}
	}
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		return &outlookMailError{Code: "mailbox_credential_invalid", Category: "credential", HTTPStatus: http.StatusUnprocessableEntity, UserMessage: "iCloud 邮箱查询 Key 无效，请检查 ic.meigo.lol 卡密", Detail: fmt.Sprintf("HTTP %d", status), Terminal: true}
	}
	if status < 200 || status >= 300 {
		detail := firstText(payload["error"], payload["message"], fmt.Sprintf("HTTP %d", status))
		return &outlookMailError{Code: "mailbox_provider_failed", Category: "service", HTTPStatus: http.StatusBadGateway, UserMessage: "iCloud 邮箱渠道释放邮箱失败", Detail: detail}
	}
	data, _ := payload["data"].(map[string]any)
	if intValue(data["success"], 1) < 1 {
		return &outlookMailError{Code: "mailbox_provider_failed", Category: "service", HTTPStatus: http.StatusBadGateway, UserMessage: "iCloud 邮箱渠道释放邮箱未成功", Detail: dumpJSON(data)}
	}
	return nil
}

func fetchIcMeiGoJSON(client *http.Client, accessKey, email string) (map[string]any, error) {
	body, _ := json.Marshal(map[string]any{"email": email, "format": "text"})
	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(icmeigoAPIBaseURL, "/")+"/api/hme/mail", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessKey)
	resp, err := client.Do(req)
	if err != nil {
		return nil, &outlookMailError{Code: "mailbox_network_error", Category: "network", HTTPStatus: http.StatusServiceUnavailable, UserMessage: "iCloud 邮箱渠道网络连接失败，请检查服务器出网与代理配置", Detail: err.Error()}
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode == http.StatusNotFound {
		// No mail has arrived for this hidden mailbox yet.
		return map[string]any{"empty": true}, nil
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, &outlookMailError{Code: "mailbox_service_response_invalid", Category: "service", HTTPStatus: http.StatusBadGateway, UserMessage: "iCloud 邮箱渠道返回了无法解析的响应，请稍后重试", Detail: fmt.Sprintf("HTTP %d", resp.StatusCode)}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		detail := firstText(payload["error"], payload["message"], fmt.Sprintf("HTTP %d", resp.StatusCode))
		code, category, status2, message, terminal := "mailbox_provider_failed", "service", http.StatusBadGateway, "iCloud 邮箱渠道请求失败，请稍后重试", false
		upstreamCode := strings.ToUpper(strings.TrimSpace(text(payload["code"])))
		if resp.StatusCode == http.StatusForbidden && upstreamCode == "HISTORY_ACCESS_DISABLED" {
			// 邮箱已释放：ic.meigo 关闭了已释放邮箱的查询能力，邮箱无法再收信，
			// 但卡密 Key 仍然有效，不能按凭证失效处理。
			code, category, status2, message = "mailbox_history_disabled", "service", http.StatusForbidden, "ic.meigo 邮箱已释放，无法再收取新邮件"
		} else if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden || strings.Contains(strings.ToLower(detail), "key") || strings.Contains(detail, "密钥") || strings.Contains(detail, "无效") {
			code, category, status2, message, terminal = "mailbox_credential_invalid", "credential", http.StatusUnprocessableEntity, "iCloud 邮箱查询 Key 无效，请检查 ic.meigo.lol 卡密", true
		}
		return nil, &outlookMailError{Code: code, Category: category, HTTPStatus: status2, UserMessage: message, Detail: detail, Terminal: terminal}
	}
	return payload, nil
}

func fetchIcMeiGoLatestMail(email, accessKey string, limit int, proxyURL string) (map[string]any, error) {
	email = strings.TrimSpace(email)
	accessKey = strings.TrimSpace(accessKey)
	if email == "" || !strings.Contains(email, "@") || accessKey == "" {
		return nil, &outlookMailError{Code: "mailbox_format_error", Category: "format", HTTPStatus: http.StatusUnprocessableEntity, UserMessage: "苹果邮箱凭证格式错误，应为 icloud email----key", Terminal: true}
	}
	if limit < 1 {
		limit = 5
	}
	if limit > 50 {
		limit = 50
	}
	payload, err := fetchIcMeiGoJSON(icmeigoHTTPClient(proxyURL), accessKey, email)
	if err != nil {
		return nil, err
	}
	if boolValue(payload["empty"], false) {
		return map[string]any{"email": email, "mailbox_type": "apple", "mailbox_channel": "icmeigo", "mail_protocol": "icmeigo_api", "items": []map[string]any{}, "count": 0, "limit": limit}, nil
	}
	data, _ := payload["data"].(map[string]any)
	content := firstText(data["content"], data["html_content"])
	plain := urlAPIText(content)
	otp := ""
	if matched := icmeigoOTPPattern.FindStringSubmatch(plain); len(matched) > 1 {
		otp = matched[1]
	}
	subject := text(data["subject"])
	item := map[string]any{
		"id": text(data["id"]), "email": email, "folder": "iCloud", "subject": subject,
		"from": text(data["from"]), "to": email, "date": text(data["received_at"]),
		"body": plain, "body_preview": strings.TrimSpace(plain),
		"raw_html": content, "otp": otp, "source": "icmeigo",
	}
	if subject == "" && icmeigoOpenAIPattern.MatchString(plain) {
		item["subject"] = "ChatGPT"
	}
	return map[string]any{"email": email, "mailbox_type": "apple", "mailbox_channel": "icmeigo", "mail_protocol": "icmeigo_api", "items": []map[string]any{item}, "count": 1, "limit": limit}, nil
}