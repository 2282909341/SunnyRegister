package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

const sunnyCfgMailCom = "mail_com_code"

func defaultMailComConfig() map[string]any {
	return map[string]any{
		"enabled":               false,
		"enabled_for_rebinding": false,
		"base_url":              "",
		"accounts":              []map[string]any{},
		"shared_token":          "",
	}
}

// mailComAccount is a stored mail.com master account. Passwords stay on the
// server side (sunny_configs) and are never echoed back to the frontend.
type mailComAccount struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Status   string `json:"status,omitempty"`
	Error    string `json:"error,omitempty"`
}

func mailComBaseURL(cfg map[string]any) string {
	return strings.TrimRight(strings.TrimSpace(text(cfg["base_url"])), "/")
}

// mailComCfgWithBody overlays operational fields carried by a request body
// onto the stored config, so actions like check/split/import work even when
// the user has not persisted the config yet.
func mailComCfgWithBody(cfg map[string]any, body map[string]any) map[string]any {
	if body == nil {
		return cfg
	}
	next := make(map[string]any, len(cfg)+4)
	for key, value := range cfg {
		next[key] = value
	}
	if rawBase := strings.TrimSpace(text(body["base_url"])); rawBase != "" {
		next["base_url"] = strings.TrimRight(rawBase, "/")
	}
	if rawAccounts, ok := body["accounts"]; ok {
		next["accounts"] = rawAccounts
	}
	for _, key := range []string{"enabled", "enabled_for_rebinding"} {
		if value, ok := body[key]; ok {
			next[key] = value
		}
	}
	return next
}

func mailComAccounts(cfg map[string]any) []mailComAccount {
	raw := cfg["accounts"]
	var out []mailComAccount
	switch value := raw.(type) {
	case []map[string]any:
		for _, item := range value {
			out = append(out, mailComAccount{
				Email:    strings.ToLower(strings.TrimSpace(text(item["email"]))),
				Password: text(item["password"]),
			})
		}
	case []any:
		for _, item := range value {
			if obj, ok := item.(map[string]any); ok {
				out = append(out, mailComAccount{
					Email:    strings.ToLower(strings.TrimSpace(text(obj["email"]))),
					Password: text(obj["password"]),
				})
			}
		}
	case string:
		for _, line := range strings.Split(value, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.SplitN(line, "----", 2)
			if len(parts) != 2 {
				continue
			}
			out = append(out, mailComAccount{
				Email:    strings.ToLower(strings.TrimSpace(parts[0])),
				Password: strings.TrimSpace(parts[1]),
			})
		}
	}
	filtered := out[:0]
	for _, account := range out {
		if account.Email != "" && account.Password != "" {
			filtered = append(filtered, account)
		}
	}
	return filtered
}

type mailComClient struct {
	baseURL string
	client  *http.Client
}

func newMailComClient(cfg map[string]any) (*mailComClient, error) {
	base := mailComBaseURL(cfg)
	if base == "" {
		return nil, fmt.Errorf("Mail.com 服务地址未配置")
	}
	return &mailComClient{
		baseURL: base,
		client: &http.Client{
			Timeout: 35 * time.Second,
		},
	}, nil
}

func (c *mailComClient) request(ctx context.Context, method, path string, body any) ([]byte, int, error) {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, 0, err
		}
		reader = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "SunnyRegister/1.0")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("Mail.com 服务请求失败：%w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return raw, resp.StatusCode, nil
}

// mailComSplitResponse mirrors POST /aliases/split on the code API.
type mailComSplitResponse struct {
	Email    string               `json:"email"`
	Domain   string               `json:"domain"`
	Created  int                  `json:"created"`
	Routes   []mailComSplitRoute  `json:"routes"`
	Error    string               `json:"error"`
	Detail   string               `json:"detail"`
}

type mailComSplitRoute struct {
	Address string `json:"address"`
	URL     string `json:"url"`
}

func (s *Server) sunnyMailComHandler(w http.ResponseWriter, r *http.Request, parts []string) {
	if len(parts) == 0 {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	cfg := mergeConfig(defaultMailComConfig(), s.sunnyGetConfig(sunnyCfgMailCom, defaultMailComConfig()))
	switch parts[0] {
	case "config":
		s.mailComConfigHandler(w, r, parts[1:])
		return
	case "check":
		if r.Method != http.MethodPost {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		s.mailComCheckHandler(w, r, cfg)
		return
	case "split":
		if r.Method != http.MethodPost {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		s.mailComSplitHandler(w, r, cfg)
		return
	case "import":
		if r.Method != http.MethodPost {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		s.mailComImportHandler(w, r, cfg)
		return
	case "aliases":
		if r.Method != http.MethodGet {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		s.mailComAliasesHandler(w, r)
		return
	case "fetch-code":
		if r.Method != http.MethodPost {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		s.mailComFetchCodeHandler(w, r)
		return
	case "delete":
		if r.Method != http.MethodPost {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		s.mailComDeleteHandler(w, r)
		return
	}
	writeError(w, http.StatusNotFound, "not found")
}

// ---- config ----

func (s *Server) mailComConfigHandler(w http.ResponseWriter, r *http.Request, parts []string) {
	if len(parts) == 0 && r.Method == http.MethodGet {
		cfg := mergeConfig(defaultMailComConfig(), s.sunnyGetConfig(sunnyCfgMailCom, defaultMailComConfig()))
		accounts := mailComAccounts(cfg)
		out := map[string]any{
			"enabled":               boolValue(cfg["enabled"], false),
			"enabled_for_rebinding": boolValue(cfg["enabled_for_rebinding"], false),
			"base_url":              mailComBaseURL(cfg),
			"accounts_configured":   len(accounts),
			"accounts":              []string{},
		}
		for _, account := range accounts {
			out["accounts"] = append(out["accounts"].([]string), account.Email)
		}
		writeJSON(w, http.StatusOK, out)
		return
	}
	if len(parts) == 0 && r.Method == http.MethodPut {
		body, err := parseBody(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		current := mergeConfig(defaultMailComConfig(), s.sunnyGetConfig(sunnyCfgMailCom, defaultMailComConfig()))
		next := mergeConfig(current, body)

		// Accounts: frontend sends either a textarea string (email----password
		// per line) or an array of {"email","password"} objects. Blank
		// passwords keep the stored password for that email.
		existing := map[string]string{}
		for _, account := range mailComAccounts(current) {
			existing[account.Email] = account.Password
		}
		merged := map[string]mailComAccount{}
		rawAccounts, hasAccounts := body["accounts"]
		if hasAccounts {
			switch value := rawAccounts.(type) {
			case string:
				for _, account := range mailComAccounts(map[string]any{"accounts": value}) {
					merged[account.Email] = account
				}
			case []any:
				for _, item := range value {
					if obj, ok := item.(map[string]any); ok {
						email := strings.ToLower(strings.TrimSpace(text(obj["email"])))
						password := strings.TrimSpace(text(obj["password"]))
						if password == "" {
							password = existing[email]
						}
						if email != "" && password != "" {
							merged[email] = mailComAccount{Email: email, Password: password}
						}
					}
				}
			}
		} else {
			// Not provided: keep existing accounts untouched.
			for email, password := range existing {
				merged[email] = mailComAccount{Email: email, Password: password}
			}
		}
		accountList := make([]map[string]any, 0, len(merged))
		emails := make([]string, 0, len(merged))
		for email, account := range merged {
			accountList = append(accountList, map[string]any{"email": account.Email, "password": account.Password})
			emails = append(emails, email)
		}
		next["accounts"] = accountList

		if strings.TrimSpace(text(body["base_url"])) != "" {
			next["base_url"] = strings.TrimRight(strings.TrimSpace(text(body["base_url"])), "/")
		}
		s.sunnySaveConfig(sunnyCfgMailCom, next)

		out := map[string]any{
			"enabled":               boolValue(next["enabled"], false),
			"enabled_for_rebinding": boolValue(next["enabled_for_rebinding"], false),
			"base_url":              mailComBaseURL(next),
			"accounts_configured":   len(emails),
			"accounts":              emails,
		}
		writeJSON(w, http.StatusOK, out)
		return
	}
	writeError(w, http.StatusNotFound, "not found")
}

// ---- check ----

func (s *Server) mailComCheckHandler(w http.ResponseWriter, r *http.Request, cfg map[string]any) {
	body, _ := parseBody(r)
	cfg = mailComCfgWithBody(cfg, body)
	accounts := mailComAccounts(cfg)
	if len(accounts) == 0 {
		writeError(w, http.StatusBadRequest, "请先配置 Mail.com 主账号")
		return
	}
	client, err := newMailComClient(cfg)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 35*time.Second)
	defer cancel()
	account := accounts[0]
	raw, status, err := client.request(ctx, http.MethodPost, "/aliases/split", map[string]any{
		"email": account.Email, "password": account.Password, "count": 1,
	})
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	if status < 200 || status >= 300 {
		summary := mailComResponseSummary(raw)
		writeError(w, http.StatusBadGateway, fmt.Sprintf("Mail.com 服务返回 HTTP %d：%s", status, summary))
		return
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		writeError(w, http.StatusBadGateway, "Mail.com 服务返回内容不是有效 JSON")
		return
	}
	// The probe split creates one alias; report its address and leave the
	// alias on the service so it can be picked up by the pool table.
	routeCount := 0
	var address, codeURL string
	if routes, ok := payload["routes"].([]any); ok && len(routes) > 0 {
		if first, ok := routes[0].(map[string]any); ok {
			routeCount = len(routes)
			address = text(first["address"])
			codeURL = text(first["url"])
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "email": account.Email, "routes": routeCount,
		"address": address, "url": codeURL,
	})
}

func mailComResponseSummary(raw []byte) string {
	value := strings.Join(strings.Fields(strings.TrimSpace(string(raw))), " ")
	if len([]rune(value)) > 300 {
		value = string([]rune(value)[:300]) + "..."
	}
	return value
}

// ---- split ----

func (s *Server) mailComSplitHandler(w http.ResponseWriter, r *http.Request, cfg map[string]any) {
	body, err := parseBody(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	cfg = mailComCfgWithBody(cfg, body)
	client, err := newMailComClient(cfg)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	accountEmail := strings.ToLower(strings.TrimSpace(text(body["email"])))
	accounts := mailComAccounts(cfg)
	var selected *mailComAccount
	if accountEmail != "" {
		for index := range accounts {
			if accounts[index].Email == accountEmail {
				selected = &accounts[index]
				break
			}
		}
		if selected == nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("未找到主账号 %s，请先导入", accountEmail))
			return
		}
	} else if len(accounts) > 0 {
		selected = &accounts[0]
	} else {
		writeError(w, http.StatusBadRequest, "请先配置 Mail.com 主账号")
		return
	}
	count := intValue(body["count"], 1)
	if count < 1 || count > 9 {
		writeError(w, http.StatusBadRequest, "分裂数量必须在 1 到 9 之间")
		return
	}
	payload := map[string]any{"email": selected.Email, "password": selected.Password, "count": count}
	if domain := strings.TrimSpace(text(body["domain"])); domain != "" {
		payload["domain"] = strings.TrimPrefix(strings.ToLower(domain), "@")
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	raw, status, err := client.request(ctx, http.MethodPost, "/aliases/split", payload)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	if status < 200 || status >= 300 {
		summary := mailComResponseSummary(raw)
		var payload map[string]any
		detail := ""
		if json.Unmarshal(raw, &payload) == nil {
			detail = firstText(text(payload["detail"]), text(payload["error"]))
		}
		if detail == "" {
			detail = summary
		}
		writeError(w, http.StatusBadGateway, fmt.Sprintf("分裂别名失败：HTTP %d：%s", status, detail))
		return
	}
	var result mailComSplitResponse
	if err := json.Unmarshal(raw, &result); err != nil {
		writeError(w, http.StatusBadGateway, "Mail.com 服务返回内容不是有效 JSON")
		return
	}
	// Persist each alias into the mailbox pool so the UI table and the rebind
	// channel can consume them.
	saved := make([]map[string]any, 0, len(result.Routes))
	for _, route := range result.Routes {
		if route.Address == "" || route.URL == "" {
			continue
		}
		mailbox, persistErr := s.persistMailComAlias(selected.Email, route.Address, route.URL)
		if persistErr != nil {
			log.Printf("persist mailcom alias %s: %v", route.Address, persistErr)
		}
		saved = append(saved, map[string]any{
			"email":        route.Address,
			"url":          route.URL,
			"master_email": selected.Email,
			"id":           mailbox.ID,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "email": selected.Email, "created": len(saved), "routes": saved,
	})
}

// persistMailComAlias writes a split alias into sunny_mailboxes so the pool
// table and rebind candidates can find it. Returns the mailbox row.
func (s *Server) persistMailComAlias(masterEmail, address, codeURL string) (SunnyMailbox, error) {
	var mailbox SunnyMailbox
	if err := s.db.Where("LOWER(email) = ?", strings.ToLower(address)).First(&mailbox).Error; err == nil {
		mailbox.RebindMailboxAPI = codeURL
		mailbox.Raw = address + "----" + codeURL
		s.db.Save(&mailbox)
		return mailbox, nil
	}
	groupName := "mailcom-" + time.Now().Format("01-02")
	var group SunnyMailboxGroup
	if err := s.db.Where("name = ?", groupName).First(&group).Error; err != nil {
		group = SunnyMailboxGroup{Name: groupName, Description: "Mail.com 分裂邮箱"}
		s.db.Create(&group)
	}
	mailbox = SunnyMailbox{
		GroupID:          group.ID,
		Email:            strings.ToLower(address),
		MailboxType:      "mailcom",
		MailboxChannel:   "mailcom_code",
		AccessKey:        codeURL,
		RebindMailboxAPI: codeURL,
		Raw:              address + "----" + codeURL,
		Status:           "未注册",
		Enabled:          true,
		Password:         "",
	}
	if err := s.db.Create(&mailbox).Error; err != nil {
		return mailbox, err
	}
	return mailbox, nil
}

// ---- import ----

func (s *Server) mailComImportHandler(w http.ResponseWriter, r *http.Request, cfg map[string]any) {
	body, _ := parseBody(r)
	client, err := newMailComClient(cfg)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	rawAccounts, hasAccounts := body["accounts"]
	accounts := mailComAccounts(cfg)
	if hasAccounts {
		parsed := mailComAccounts(map[string]any{"accounts": rawAccounts})
		if len(parsed) > 0 {
			accounts = parsed
		}
	}
	if len(accounts) == 0 {
		writeError(w, http.StatusBadRequest, "请先配置或提供 Mail.com 主账号")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()
	// Forward the full account list to /admin/import with verify so the code
	// API validates logins in the background and returns per-account results.
	adminToken := strings.TrimSpace(text(body["admin_token"]))
	verify := boolValue(body["verify"], true)
	importBody := map[string]any{"accounts": []map[string]any{}}
	for _, account := range accounts {
		importBody["accounts"] = append(importBody["accounts"].([]map[string]any), map[string]any{
			"email": account.Email, "password": account.Password,
		})
	}
	query := ""
	if verify {
		query = "?verify=true"
	}
	raw, status, err := client.request(ctx, http.MethodPost, "/admin/import"+query, importBody)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	if adminToken != "" {
		_ = adminToken // reserved for future shared-token auth
	}
	_ = raw
	_ = status
	// Save/update accounts locally regardless of upstream verify outcome.
	current := mergeConfig(defaultMailComConfig(), s.sunnyGetConfig(sunnyCfgMailCom, defaultMailComConfig()))
	// Honor operational fields carried by the import request (the frontend
	// sends the whole config), so base_url/enabled survive an import-first
	// workflow instead of being silently dropped.
	if rawBase := strings.TrimSpace(text(body["base_url"])); rawBase != "" {
		current["base_url"] = strings.TrimRight(rawBase, "/")
	}
	if _, hasEnabled := body["enabled"]; hasEnabled {
		current["enabled"] = boolValue(body["enabled"], boolValue(current["enabled"], false))
	}
	if _, hasRebind := body["enabled_for_rebinding"]; hasRebind {
		current["enabled_for_rebinding"] = boolValue(body["enabled_for_rebinding"], boolValue(current["enabled_for_rebinding"], false))
	}
	existing := map[string]string{}
	for _, account := range mailComAccounts(current) {
		existing[account.Email] = account.Password
	}
	merged := map[string]mailComAccount{}
	for email, password := range existing {
		merged[email] = mailComAccount{Email: email, Password: password}
	}
	for _, account := range accounts {
		merged[account.Email] = mailComAccount{Email: account.Email, Password: account.Password}
	}
	accountList := make([]map[string]any, 0, len(merged))
	for _, account := range merged {
		accountList = append(accountList, map[string]any{"email": account.Email, "password": account.Password})
	}
	current["accounts"] = accountList
	s.sunnySaveConfig(sunnyCfgMailCom, current)

	if status < 200 || status >= 300 {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok": true, "imported": len(accounts), "warning": fmt.Sprintf("上游返回 HTTP %d：%s", status, mailComResponseSummary(raw)),
		})
		return
	}
	var result map[string]any
	_ = json.Unmarshal(raw, &result)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "imported": len(accounts), "upstream": result,
	})
}

// ---- aliases (pool table) ----

func (s *Server) mailComAliasesHandler(w http.ResponseWriter, r *http.Request) {
	var rows []SunnyMailbox
	s.db.Where("mailbox_type = ?", "mailcom").Order("updated_at desc").Find(&rows)
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		out = append(out, map[string]any{
			"id":             row.ID,
			"email":          row.Email,
			"url":            row.RebindMailboxAPI,
			"status":         row.Status,
			"enabled":        row.Enabled,
			"last_error":     row.LastError,
			"last_mail_at":   row.LastMailAt,
			"updated_at":     row.UpdatedAt,
			"created_at":     row.CreatedAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

// ---- fetch-code ----

func (s *Server) mailComFetchCodeHandler(w http.ResponseWriter, r *http.Request) {
	body, err := parseBody(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	codeURL := strings.TrimSpace(text(body["url"]))
	if codeURL == "" {
		writeError(w, http.StatusBadRequest, "缺少取码 URL")
		return
	}
	if !strings.HasPrefix(codeURL, "http://") && !strings.HasPrefix(codeURL, "https://") {
		writeError(w, http.StatusBadRequest, "取码 URL 格式无效")
		return
	}
	wait := intValue(body["wait"], 10)
	if wait < 0 || wait > 60 {
		wait = 10
	}
	target := codeURL
	separator := "?"
	if strings.Contains(codeURL, "?") {
		separator = "&"
	}
	target += separator + "wait=" + fmt.Sprintf("%d", wait) + "&max_age=600"
	if sender := strings.TrimSpace(text(body["sender"])); sender != "" {
		target += "&sender=" + sender
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(wait+15)*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "SunnyRegister/1.0")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("取码请求失败：%v", err))
		return
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("读取取码响应失败：%v", err))
		return
	}
	if resp.StatusCode == http.StatusNotFound {
		writeError(w, http.StatusNotFound, "取码 key 不存在或已失效")
		return
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		writeError(w, http.StatusTooManyRequests, "取码请求过于频繁，请稍后再试")
		return
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("取码接口返回 HTTP %d：%s", resp.StatusCode, mailComResponseSummary(raw)))
		return
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		writeError(w, http.StatusBadGateway, "取码接口返回内容不是有效 JSON")
		return
	}
	writeJSON(w, http.StatusOK, payload)
}

// ---- delete ----

func (s *Server) mailComDeleteHandler(w http.ResponseWriter, r *http.Request) {
	body, err := parseBody(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	address := strings.ToLower(strings.TrimSpace(text(body["email"])))
	codeURL := strings.TrimSpace(text(body["url"]))
	if address == "" {
		writeError(w, http.StatusBadRequest, "缺少分裂邮箱地址")
		return
	}
	cfg := mergeConfig(defaultMailComConfig(), s.sunnyGetConfig(sunnyCfgMailCom, defaultMailComConfig()))
	// Try to release the alias upstream when a code URL is known. Failure to
	// reach the code API only warns; the local pool row is still removed.
	if codeURL != "" {
		if client, clientErr := newMailComClient(cfg); clientErr == nil {
			ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
			raw, status, requestErr := client.request(ctx, http.MethodPost, "/mail/aliases/remove", map[string]any{"email": address})
			cancel()
			if requestErr == nil && (status < 200 || status >= 300) {
				_ = raw
			}
		}
	}
	var mailbox SunnyMailbox
	if err := s.db.Where("LOWER(email) = ? AND mailbox_type = ?", address, "mailcom").First(&mailbox).Error; err == nil {
		s.db.Delete(&mailbox)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "removed": address})
}
