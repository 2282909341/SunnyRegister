package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

var (
	xbovoAPIBaseURL = "https://icloud.xbovo.online"
	xbovoOTPPattern = regexp.MustCompile(`(?m)(?:^|\D)(\d{6})(?:\D|$)`)
)

func xbovoHTTPClient(proxyURL string) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if strings.TrimSpace(proxyURL) != "" {
		if parsed, err := url.Parse(proxyURL); err == nil {
			transport.Proxy = http.ProxyURL(parsed)
		}
	}
	return &http.Client{Timeout: 30 * time.Second, Transport: transport}
}

func fetchXbovoJSON(client *http.Client, endpoint, accessKey string, query url.Values) (map[string]any, error) {
	if query == nil {
		query = url.Values{}
	}
	req, err := http.NewRequest(http.MethodGet, strings.TrimRight(xbovoAPIBaseURL, "/")+endpoint+"?"+query.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-API-Key", accessKey)
	resp, err := client.Do(req)
	if err != nil {
		return nil, &outlookMailError{Code: "mailbox_network_error", Category: "network", HTTPStatus: http.StatusServiceUnavailable, UserMessage: "iCloud 邮箱渠道网络连接失败，请检查服务器出网与代理配置", Detail: err.Error()}
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, &outlookMailError{Code: "mailbox_service_response_invalid", Category: "service", HTTPStatus: http.StatusBadGateway, UserMessage: "iCloud 邮箱渠道返回了无法解析的响应，请稍后重试", Detail: fmt.Sprintf("HTTP %d", resp.StatusCode)}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || !boolValue(payload["ok"], false) {
		detail := firstText(payload["error"], payload["message"], fmt.Sprintf("HTTP %d", resp.StatusCode))
		lower := strings.ToLower(detail)
		code, category, status, message, terminal := "mailbox_provider_failed", "service", http.StatusBadGateway, "iCloud 邮箱渠道请求失败，请稍后重试", false
		if strings.Contains(lower, "key") || strings.Contains(detail, "密钥") || strings.Contains(detail, "不正确") || strings.Contains(detail, "无效") {
			code, category, status, message, terminal = "mailbox_credential_invalid", "credential", http.StatusUnprocessableEntity, "iCloud 邮箱查询 Key 无效，请检查 xbovo 邮箱凭证", true
		}
		return nil, &outlookMailError{Code: code, Category: category, HTTPStatus: status, UserMessage: message, Detail: detail, Terminal: terminal}
	}
	return payload, nil
}

func fetchXbovoLatestMail(email, accessKey string, limit int, proxyURL string) (map[string]any, error) {
	email = strings.TrimSpace(email)
	accessKey = strings.TrimSpace(accessKey)
	if email == "" || !strings.Contains(email, "@") || accessKey == "" {
		return nil, &outlookMailError{Code: "mailbox_format_error", Category: "format", HTTPStatus: http.StatusUnprocessableEntity, UserMessage: "苹果邮箱凭证格式错误，应为 icloud_email----key", Terminal: true}
	}
	if limit < 1 {
		limit = 5
	}
	if limit > 50 {
		limit = 50
	}
	client := xbovoHTTPClient(proxyURL)
	payload, err := fetchXbovoJSON(client, "/api/v1/messages", accessKey, url.Values{"email": {email}, "limit": {fmt.Sprintf("%d", limit)}})
	if err != nil {
		return nil, err
	}
	rawItems, _ := payload["messages"].([]any)
	items := make([]map[string]any, 0, len(rawItems))
	fetchRaw := !strings.EqualFold(strings.TrimSpace(os.Getenv("XBOVO_FETCH_RAW_MAIL")), "false")
	for _, rawItem := range rawItems {
		message, ok := rawItem.(map[string]any)
		if !ok {
			continue
		}
		id := text(message["id"])
		preview := firstText(message["preview"], message["body_preview"], message["body"])
		otp := strings.TrimSpace(text(message["code"]))
		if matched := xbovoOTPPattern.FindStringSubmatch(otp + "\n" + preview); len(matched) > 1 {
			otp = matched[1]
		} else {
			otp = ""
		}
		item := map[string]any{
			"id": id, "email": email, "folder": "iCloud", "subject": text(message["subject"]),
			"from": text(message["from"]), "to": firstText(message["to"], message["alias_email"], email),
			"date": firstText(message["received_at"], message["date"]), "body": preview, "body_preview": preview,
			"otp": otp, "source": "xbovo",
		}
		// Some xbovo credentials expose only list previews. Raw mail is optional,
		// so a raw-mail permission failure must not fail the mailbox query.
		if id != "" && fetchRaw {
			if rawPayload, rawErr := fetchXbovoJSON(client, "/api/v1/message/raw", accessKey, url.Values{"id": {id}}); rawErr == nil {
				body := firstText(rawPayload["text"], rawPayload["body"], preview)
				htmlBody := firstText(rawPayload["html"], rawPayload["raw_html"])
				item["body"] = body
				item["body_preview"] = firstText(preview, body)
				item["raw_html"] = htmlBody
			} else {
				fetchRaw = false
			}
		}
		items = append(items, item)
	}
	return map[string]any{"email": email, "mailbox_type": "apple", "mailbox_channel": "xbovo", "mail_protocol": "xbovo_api", "items": items, "count": len(items), "limit": limit}, nil
}

func fetchXbovoMailSubjects(email, accessKey string, limit int, proxyURL string) ([]string, error) {
	return fetchXbovoMailSummaries(email, accessKey, limit, proxyURL, false)
}

func fetchXbovoHealthMailEvidence(email, accessKey string, limit int, proxyURL string) ([]string, error) {
	return fetchXbovoMailSummaries(email, accessKey, limit, proxyURL, true)
}

func fetchXbovoMailSummaries(email, accessKey string, limit int, proxyURL string, includePreview bool) ([]string, error) {
	email = strings.TrimSpace(email)
	accessKey = strings.TrimSpace(accessKey)
	if email == "" || !strings.Contains(email, "@") || accessKey == "" {
		return nil, &outlookMailError{Code: "mailbox_format_error", Category: "format", HTTPStatus: http.StatusUnprocessableEntity, UserMessage: "苹果邮箱凭证格式错误，应为 icloud_email----key", Terminal: true}
	}
	if limit < 1 {
		limit = 5
	}
	if limit > 50 {
		limit = 50
	}
	payload, err := fetchXbovoJSON(xbovoHTTPClient(proxyURL), "/api/v1/messages", accessKey, url.Values{"email": {email}, "limit": {fmt.Sprintf("%d", limit)}})
	if err != nil {
		return nil, err
	}
	rawItems, _ := payload["messages"].([]any)
	subjects := make([]string, 0, len(rawItems))
	for _, raw := range rawItems {
		item, _ := raw.(map[string]any)
		subject := strings.TrimSpace(text(item["subject"]))
		body := ""
		if includePreview {
			body = strings.TrimSpace(firstText(item["text"], item["body"], item["body_preview"], item["preview"]))
		}
		if evidence := strings.TrimSpace(subject + "\n" + body); evidence != "" {
			subjects = append(subjects, evidence)
		}
	}
	return subjects, nil
}
