package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"
)

const (
	sunnyAccessTokenCheckTaskType = "sunny_access_token_check"
	sunnyCfgMaintenance           = "account_maintenance"
)

const sunnyAccessTokenProbeEndpoint = "https://chatgpt.com/backend-api/models"

var sunnyProbeAccessTokenEndpoint = sunnyAccessTokenProbeEndpoint

func sunnyGoTaskType(taskType string) bool {
	return taskType == sunnyHealthTaskType || taskType == sunnyAccessTokenCheckTaskType || taskType == sunnySubscriptionTaskType || taskType == sunnyTrialTaskType || taskType == sunnyCheckoutProbeTaskType || taskType == sunnyPaymentProbeTaskType || taskType == sunnyCheckoutTaskType
}

type sunnyAccessTokenCandidate struct {
	SessionID   uint
	AccountID   uint
	Email       string
	AccessToken string
}

type sunnyAccessTokenResult struct {
	SessionID uint
	AccountID uint
	Email     string
	Status    string
	Error     string
}

func (s *Server) createSunnyAccessTokenRenewalTask(sourceTask *Task, source string, accountIDs []uint) Task {
	accountIDs = s.filterActiveSunnyRenewalAccounts(accountIDs)
	if len(accountIDs) == 0 {
		return Task{}
	}
	concurrency := s.sunnyATConcurrency()
	refreshPayload := s.sunnyTaskProxySnapshot(map[string]any{
		"account_ids": accountIDs, "automatic": true, "source": source, "source_task_id": sourceTask.ID,
		"execution_mode": "protocol", "protocol_challenge_strategy": "sentinel_protocol", "registration_stage": "register_only", "concurrency": concurrency,
	})
	renewalTask := s.createTask("sunny_refresh_session", "sunny", refreshPayload, len(accountIDs))
	s.appendTaskEvent(sourceTask.ID, fmt.Sprintf("检测到 %d 个无效 AT，已创建续期任务", len(accountIDs)), "log", "warning", map[string]any{"renewal_task_id": renewalTask.ID})
	return renewalTask
}

func (s *Server) filterActiveSunnyRenewalAccounts(accountIDs []uint) []uint {
	requested := make(map[uint]bool, len(accountIDs))
	for _, accountID := range accountIDs {
		if accountID != 0 {
			requested[accountID] = true
		}
	}
	if len(requested) == 0 {
		return nil
	}
	var tasks []Task
	if err := s.db.Where("type = ? AND status NOT IN ?", "sunny_refresh_session", []string{TaskSucceeded, TaskFailed, TaskInterrupted, TaskCancelled}).Find(&tasks).Error; err != nil {
		return accountIDs
	}
	active := make(map[uint]bool)
	for _, task := range tasks {
		for _, accountID := range uintSlice(jsonMap(task.PayloadJSON)["account_ids"]) {
			active[accountID] = true
		}
	}
	filtered := make([]uint, 0, len(requested))
	seen := make(map[uint]bool)
	for _, accountID := range accountIDs {
		if accountID != 0 && !active[accountID] && !seen[accountID] {
			filtered = append(filtered, accountID)
			seen[accountID] = true
		}
	}
	return filtered
}

type sunnyConcurrencyConfigSpec struct {
	Key    string
	EnvKey string
	Max    int
}

var sunnyConcurrencyConfigSpecs = []sunnyConcurrencyConfigSpec{
	{Key: "rebind_concurrency", Max: 6},
	{Key: "sub2_import_concurrency", Max: 6},
	{Key: "trial_concurrency", EnvKey: "SUNNY_TRIAL_CONCURRENCY", Max: 16},
	{Key: "checkout_probe_concurrency", EnvKey: "SUNNY_CHECKOUT_PROBE_CONCURRENCY", Max: 16},
	{Key: "payment_probe_concurrency", EnvKey: "SUNNY_PAYMENT_PROBE_CONCURRENCY", Max: 8},
	{Key: "payment_country_concurrency", EnvKey: "SUNNY_PAYMENT_PROBE_COUNTRY_CONCURRENCY", Max: 8},
	{Key: "add_ls_concurrency", Max: 6},
	{Key: "at_concurrency", EnvKey: "SUNNY_AT_RENEWAL_CONCURRENCY", Max: 6},
	{Key: "health_concurrency", EnvKey: "SUNNY_HEALTHCHECK_CONCURRENCY", Max: 16},
	{Key: "subscription_concurrency", EnvKey: "SUNNY_SUBSCRIPTION_CONCURRENCY", Max: 12},
}

func sunnyScaledConcurrency(cpu, numerator, denominator, maximum int) int {
	if cpu < 1 {
		cpu = 1
	}
	value := (cpu*numerator + denominator - 1) / denominator
	if value < 1 {
		value = 1
	}
	if maximum > 0 && value > maximum {
		value = maximum
	}
	return value
}

func defaultSunnyMaintenanceConfigForCPU(cpu int) map[string]any {
	return map[string]any{
		"health_enabled":              true,
		"health_time":                 "06:00",
		"health_frequency_hours":      24,
		"at_enabled":                  true,
		"at_time":                     "06:30",
		"at_frequency_hours":          24,
		"rebind_concurrency":          sunnyScaledConcurrency(cpu, 3, 4, 6),
		"sub2_import_concurrency":     sunnyScaledConcurrency(cpu, 1, 1, 6),
		"trial_concurrency":           sunnyScaledConcurrency(cpu, 1, 1, 16),
		"checkout_probe_concurrency":  sunnyScaledConcurrency(cpu, 1, 1, 16),
		"payment_probe_concurrency":   sunnyScaledConcurrency(cpu, 1, 2, 8),
		"payment_country_concurrency": sunnyScaledConcurrency(cpu, 1, 2, 8),
		"add_ls_concurrency":          sunnyScaledConcurrency(cpu, 3, 4, 6),
		"at_concurrency":              sunnyScaledConcurrency(cpu, 1, 2, 6),
		"health_concurrency":          sunnyScaledConcurrency(cpu, 1, 1, 16),
		"subscription_concurrency":    sunnyScaledConcurrency(cpu, 3, 4, 12),
	}
}

func defaultSunnyMaintenanceConfig() map[string]any {
	return defaultSunnyMaintenanceConfigForCPU(runtime.NumCPU())
}

func normalizeSunnyMaintenanceConfig(value map[string]any) (map[string]any, error) {
	config := mergeConfig(defaultSunnyMaintenanceConfig(), value)
	for _, key := range []string{"health_time", "at_time"} {
		textValue := strings.TrimSpace(text(config[key]))
		if _, err := time.Parse("15:04", textValue); err != nil {
			return nil, fmt.Errorf("%s 必须使用 HH:mm 格式", key)
		}
		config[key] = textValue
	}
	for _, key := range []string{"health_frequency_hours", "at_frequency_hours"} {
		value := intValue(config[key], 24)
		if value < 1 || value > 24*30 {
			return nil, fmt.Errorf("%s 必须在 1 到 720 小时之间", key)
		}
		config[key] = value
	}
	config["health_enabled"] = boolValue(config["health_enabled"], true)
	config["at_enabled"] = boolValue(config["at_enabled"], true)
	for _, spec := range sunnyConcurrencyConfigSpecs {
		concurrency := intValue(config[spec.Key], intValue(defaultSunnyMaintenanceConfig()[spec.Key], 1))
		if concurrency < 1 || concurrency > spec.Max {
			return nil, fmt.Errorf("%s 必须在 1 到 %d 之间", spec.Key, spec.Max)
		}
		config[spec.Key] = concurrency
	}
	return config, nil
}

func (s *Server) loadSunnyMaintenanceConfig() map[string]any {
	config, err := normalizeSunnyMaintenanceConfig(s.sunnyGetConfig(sunnyCfgMaintenance, defaultSunnyMaintenanceConfig()))
	if err != nil {
		log.Printf("invalid account maintenance config, using defaults: %v", err)
		return defaultSunnyMaintenanceConfig()
	}
	return config
}

func (s *Server) sunnyMaintenanceSnapshot() map[string]any {
	s.maintenanceMu.RLock()
	defer s.maintenanceMu.RUnlock()
	return mergeConfig(defaultSunnyMaintenanceConfig(), s.maintenance)
}

func (s *Server) sunnyConfiguredConcurrency(key, envKey string, maximum int) int {
	s.maintenanceMu.RLock()
	raw, configured := s.maintenance[key]
	s.maintenanceMu.RUnlock()
	if configured {
		return max(1, min(intValue(raw, 1), maximum))
	}
	if envKey != "" {
		if rawEnv := strings.TrimSpace(os.Getenv(envKey)); rawEnv != "" {
			return max(1, min(intValue(rawEnv, 1), maximum))
		}
	}
	return max(1, min(intValue(defaultSunnyMaintenanceConfig()[key], 1), maximum))
}

func (s *Server) sunnyATConcurrency() int {
	return s.sunnyConfiguredConcurrency("at_concurrency", "SUNNY_AT_RENEWAL_CONCURRENCY", 6)
}

func (s *Server) sunnyAddLSConcurrency() int {
	return s.sunnyConfiguredConcurrency("add_ls_concurrency", "", 6)
}

func (s *Server) sunnyRebindConcurrency() int {
	return s.sunnyConfiguredConcurrency("rebind_concurrency", "", 6)
}

func (s *Server) sunnySub2ImportConcurrency() int {
	return s.sunnyConfiguredConcurrency("sub2_import_concurrency", "", 6)
}

func (s *Server) sunnyMaintenanceConfigHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		config, err := normalizeSunnyMaintenanceConfig(s.sunnyGetConfig(sunnyCfgMaintenance, defaultSunnyMaintenanceConfig()))
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, config)
	case http.MethodPut:
		body, err := parseBody(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		config, err := normalizeSunnyMaintenanceConfig(body)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.sunnySaveConfig(sunnyCfgMaintenance, config)
		s.maintenanceMu.Lock()
		s.maintenance = mergeConfig(defaultSunnyMaintenanceConfig(), config)
		s.maintenanceMu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"config": config, "restart_required": false, "effective_immediately": true})
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func sunnyProbeAccessToken(accessToken, proxyURL string, meters ...*sunnyTrafficMeter) (string, error) {
	return sunnyProbeAccessTokenContext(context.Background(), accessToken, proxyURL, meters...)
}

func sunnyProbeAccessTokenContext(ctx context.Context, accessToken, proxyURL string, meters ...*sunnyTrafficMeter) (string, error) {
	if strings.TrimSpace(accessToken) == "" {
		return "invalid", fmt.Errorf("账户没有可用的 Access Token")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if strings.TrimSpace(proxyURL) != "" {
		proxy, err := url.Parse(proxyURL)
		if err != nil {
			return "probe_failed", fmt.Errorf("AT 检测代理配置无效: %w", err)
		}
		transport.Proxy = http.ProxyURL(proxy)
	}
	client := &http.Client{
		Timeout:       12 * time.Second,
		Transport:     transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}
	if len(meters) > 0 && meters[0] != nil && strings.TrimSpace(proxyURL) != "" {
		client.Transport = &sunnyTrafficTransport{base: transport, meter: meters[0]}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sunnyProbeAccessTokenEndpoint, nil)
	if err != nil {
		return "probe_failed", err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(accessToken))
	req.Header.Set("Origin", "https://chatgpt.com")
	req.Header.Set("Referer", "https://chatgpt.com/")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/134.0.0.0 Safari/537.36")
	resp, err := client.Do(req)
	if err != nil {
		return "probe_failed", fmt.Errorf("AT 官方接口检测失败: %w", err)
	}
	defer resp.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if readErr != nil {
		return "probe_failed", fmt.Errorf("AT 检测响应读取失败: %w", readErr)
	}
	var payload map[string]any
	jsonErr := json.Unmarshal(body, &payload)
	detail := compactATProbeDetail(resp.StatusCode, payload, body)

	if resp.StatusCode == http.StatusUnauthorized {
		return "invalid", fmt.Errorf("AT 已失效: %s", detail)
	}
	if resp.StatusCode == http.StatusForbidden {
		if jsonErr == nil && atProbeAuthenticationError(payload) {
			return "invalid", fmt.Errorf("AT 已失效: %s", detail)
		}
		return "blocked", fmt.Errorf("AT 检测被上游边缘拦截，未确认令牌失效: %s", detail)
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		return "valid", nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "probe_failed", fmt.Errorf("AT 检测上游响应异常: %s", detail)
	}
	if jsonErr != nil {
		return "probe_failed", fmt.Errorf("AT 检测接口返回非 JSON 内容 (HTTP %d)", resp.StatusCode)
	}
	if _, ok := payload["models"]; !ok {
		return "probe_failed", fmt.Errorf("AT 检测响应缺少 models 字段")
	}
	return "valid", nil
}

func (s *Server) sunnyProbeAccessToken(accessToken, proxyURL string, meters ...*sunnyTrafficMeter) (string, error) {
	return s.sunnyProbeAccessTokenContext(context.Background(), accessToken, proxyURL, meters...)
}

func (s *Server) sunnyProbeAccessTokenContext(ctx context.Context, accessToken, proxyURL string, meters ...*sunnyTrafficMeter) (string, error) {
	if status, err, handled := s.sunnyProbeAccessTokenViaWorkerContext(ctx, accessToken, proxyURL, meters...); handled {
		return status, err
	}
	if ctx.Err() != nil {
		return "probe_failed", ctx.Err()
	}
	directStatus, directErr := sunnyProbeAccessTokenContext(ctx, accessToken, "", meters...)
	if directStatus == "valid" || directStatus == "invalid" || strings.TrimSpace(proxyURL) == "" {
		return directStatus, directErr
	}
	proxyStatus, proxyErr := sunnyProbeAccessTokenContext(ctx, accessToken, proxyURL, meters...)
	if proxyStatus == "valid" || proxyStatus == "invalid" {
		return proxyStatus, proxyErr
	}
	if directStatus == "blocked" && proxyStatus == "blocked" {
		return "blocked", fmt.Errorf("AT 检测直连与代理链路均被上游边缘拦截，未确认令牌失效: 直连=%v; 代理=%v", directErr, proxyErr)
	}
	return "probe_failed", fmt.Errorf("AT 检测直连与代理链路均未得到有效 API 响应: 直连=%v; 代理=%v", directErr, proxyErr)
}

func (s *Server) sunnyProbeAccessTokenViaWorker(accessToken, proxyURL string, meters ...*sunnyTrafficMeter) (string, error, bool) {
	return s.sunnyProbeAccessTokenViaWorkerContext(context.Background(), accessToken, proxyURL, meters...)
}

func (s *Server) sunnyProbeAccessTokenViaWorkerContext(ctx context.Context, accessToken, proxyURL string, meters ...*sunnyTrafficMeter) (string, error, bool) {
	workerURL := strings.TrimRight(strings.TrimSpace(os.Getenv("PYTHON_WORKER_URL")), "/")
	if workerURL == "" {
		workerURL = "http://127.0.0.1:8765"
	}
	body, _ := json.Marshal(map[string]any{"access_token": accessToken, "proxy_url": proxyURL})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, workerURL+"/probe-access-token", bytes.NewReader(body))
	if err != nil {
		return "", nil, false
	}
	req.Header.Set("Content-Type", "application/json")
	if token := secretValue("PYTHON_WORKER_TOKEN", "PYTHON_WORKER_TOKEN_FILE"); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := (&http.Client{Timeout: 45 * time.Second}).Do(req)
	if err != nil {
		return "", nil, false
	}
	defer resp.Body.Close()
	responseBody, readErr := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if readErr != nil || resp.StatusCode == http.StatusNotFound {
		return "", nil, false
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", nil, false
	}
	var payload map[string]any
	if json.Unmarshal(responseBody, &payload) != nil {
		return "", nil, false
	}
	status := strings.TrimSpace(text(payload["status"]))
	if status != "valid" && status != "invalid" && status != "blocked" && status != "probe_failed" {
		return "", nil, false
	}
	if len(meters) > 0 && meters[0] != nil {
		traffic, _ := payload["traffic"].(map[string]any)
		meters[0].addExternal(int64(intValue(traffic["total_bytes"], 0)))
	}
	message := strings.TrimSpace(text(payload["error"]))
	if message != "" {
		return status, fmt.Errorf("%s", message), true
	}
	return status, nil, true
}

func atProbeAuthenticationError(payload map[string]any) bool {
	if message, ok := payload["error"].(string); ok {
		combined := strings.ToLower(message)
		return strings.Contains(combined, "token") || strings.Contains(combined, "auth") || strings.Contains(combined, "expired") || strings.Contains(combined, "invalid")
	}
	errorValue, _ := payload["error"].(map[string]any)
	combined := strings.ToLower(strings.Join([]string{text(errorValue["code"]), text(errorValue["type"]), text(errorValue["message"])}, " "))
	return strings.Contains(combined, "token") || strings.Contains(combined, "auth") || strings.Contains(combined, "expired") || strings.Contains(combined, "invalidated")
}

func compactATProbeDetail(status int, payload map[string]any, body []byte) string {
	if errorValue, ok := payload["error"].(map[string]any); ok {
		parts := []string{}
		for _, key := range []string{"code", "type", "message"} {
			if value := strings.TrimSpace(text(errorValue[key])); value != "" {
				parts = append(parts, key+"="+value)
			}
		}
		if len(parts) > 0 {
			return fmt.Sprintf("HTTP %d, %s", status, strings.Join(parts, ", "))
		}
	}
	preview := strings.TrimSpace(string(body))
	if len(preview) > 300 {
		preview = preview[:300] + "..."
	}
	if preview == "" {
		preview = "empty response"
	}
	return fmt.Sprintf("HTTP %d, %s", status, preview)
}

func (s *Server) sunnyAccessTokenCheckConcurrency() int {
	return s.sunnyConfiguredConcurrency("at_concurrency", "SUNNY_ATCHECK_CONCURRENCY", 6)
}

func (s *Server) sunnyAccessTokenCandidates(ids []uint, scheduled bool) ([]sunnyAccessTokenCandidate, int, error) {
	var sessions []SunnySession
	query := s.db.Model(&SunnySession{}).Select("id", "account_id", "email", "access_token", "session_json", "health_check_status")
	query = sunnyUniqueSessionIdentityScope(query)
	if len(ids) > 0 {
		query = query.Where("id IN ?", ids)
	} else if !scheduled {
		return nil, 0, fmt.Errorf("请选择需要检测 AT 的账户")
	}
	if scheduled {
		query = query.Where("health_check_status = ?", "alive")
	}
	if err := query.Order("id asc").Find(&sessions).Error; err != nil {
		return nil, 0, err
	}
	emails := make([]string, 0, len(sessions))
	for _, session := range sessions {
		emails = append(emails, session.Email)
	}
	accounts := map[string]SunnyAccount{}
	mailboxes := map[string]SunnyMailbox{}
	if len(emails) > 0 {
		var accountRows []SunnyAccount
		var mailboxRows []SunnyMailbox
		s.db.Select("id", "email", "status", "access_token").Where("email IN ?", emails).Find(&accountRows)
		s.db.Select("email", "status").Where("email IN ?", emails).Find(&mailboxRows)
		for _, row := range accountRows {
			accounts[sunnyEmailKey(row.Email)] = row
		}
		for _, row := range mailboxRows {
			mailboxes[sunnyEmailKey(row.Email)] = row
		}
	}
	candidates := make([]sunnyAccessTokenCandidate, 0, len(sessions))
	skipped := 0
	for _, session := range sessions {
		key := sunnyEmailKey(session.Email)
		account := accounts[key]
		mailbox := mailboxes[key]
		if !sunnyHealthRegisteredStatus(account.Status) && !sunnyHealthRegisteredStatus(mailbox.Status) {
			skipped++
			continue
		}
		if sunnyHealthBannedStatus(account.Status) || sunnyHealthBannedStatus(mailbox.Status) {
			skipped++
			continue
		}
		accountID := session.AccountID
		if accountID == 0 {
			accountID = account.ID
		}
		accessToken := sunnyPreferredAccessToken(session.AccessToken, sunnyAccessTokenFromSessionJSON(session.SessionJSON), account.AccessToken)
		candidates = append(candidates, sunnyAccessTokenCandidate{SessionID: session.ID, AccountID: accountID, Email: session.Email, AccessToken: accessToken})
	}
	return candidates, skipped, nil
}

func (s *Server) createSunnyAccessTokenCheckTask(body map[string]any) (Task, error) {
	s.atCheckMu.Lock()
	defer s.atCheckMu.Unlock()

	ids := uintSlice(body["session_ids"])
	scheduled := boolValue(body["scheduled"], false)
	if len(ids) == 0 && !scheduled {
		return Task{}, fmt.Errorf("请选择需要检测 AT 的账户")
	}
	var activeTasks []Task
	s.db.Where("type = ? AND status NOT IN ?", sunnyAccessTokenCheckTaskType, []string{TaskSucceeded, TaskFailed, TaskInterrupted, TaskCancelled}).Find(&activeTasks)
	if scheduled && len(activeTasks) > 0 {
		return Task{}, fmt.Errorf("已有 AT 检测任务正在执行，请稍候")
	}
	activeLimit := intValue(strings.TrimSpace(os.Getenv("SUNNY_ATCHECK_ACTIVE_TASKS")), 4)
	if activeLimit < 1 {
		activeLimit = 1
	}
	if activeLimit > 12 {
		activeLimit = 12
	}
	requested := map[uint]bool{}
	for _, id := range ids {
		requested[id] = true
	}
	for _, activeTask := range activeTasks {
		activePayload := jsonMap(activeTask.PayloadJSON)
		if boolValue(activePayload["scheduled"], false) {
			return Task{}, fmt.Errorf("定时 AT 检测任务正在执行，请稍候")
		}
		for _, activeID := range uintSlice(activePayload["session_ids"]) {
			if requested[activeID] {
				return Task{}, fmt.Errorf("选中的账户已有 AT 检测任务正在执行")
			}
		}
	}
	if len(activeTasks) >= activeLimit {
		return Task{}, fmt.Errorf("AT 检测并发任务已达到上限 %d，请稍候", activeLimit)
	}
	candidates, skipped, err := s.sunnyAccessTokenCandidates(ids, scheduled)
	if err != nil {
		return Task{}, err
	}
	payload := map[string]any{"session_ids": ids, "scheduled": scheduled, "skipped": skipped}
	return s.createTask(sunnyAccessTokenCheckTaskType, "sunny", payload, len(candidates)), nil
}

func (s *Server) executeSunnyAccessTokenCheckTask(task *Task, payload map[string]any) {
	task.Status = TaskRunning
	task.StartedAt = sql.NullTime{Time: time.Now(), Valid: true}
	s.db.Save(task)
	ctx, cancel := s.taskCancellationContext(task)
	defer cancel()
	candidates, skipped, err := s.sunnyAccessTokenCandidates(uintSlice(payload["session_ids"]), boolValue(payload["scheduled"], false))
	if err != nil {
		s.failSunnyAccessTokenCheckTask(task, err.Error())
		return
	}
	result := map[string]any{"requested": len(candidates), "valid": 0, "invalid": 0, "failed": 0, "skipped": skipped, "items": []any{}}
	if len(candidates) == 0 {
		s.completeSunnyAccessTokenCheckTask(task, result)
		return
	}
	proxyURL := s.sunnyMailboxProxyURL()
	invalidAccounts := []uint{}
	invalidSessions := []uint{}
	seenAccounts := map[uint]bool{}
	accountBySession := make(map[uint]uint, len(candidates))
	for _, candidate := range candidates {
		accountBySession[candidate.SessionID] = candidate.AccountID
	}
	items := make([]any, 0, len(candidates))
	concurrency := s.sunnyAccessTokenCheckConcurrency()
	results := streamSunnyWorkerPoolContext(ctx, candidates, concurrency, func(candidate sunnyAccessTokenCandidate) sunnyAccessTokenResult {
		meter := &sunnyTrafficMeter{}
		status, probeErr := s.sunnyProbeAccessTokenContext(ctx, candidate.AccessToken, proxyURL, meter)
		message := ""
		if probeErr != nil {
			message = probeErr.Error()
		}
		s.recordSunnyProxyTraffic(candidate.Email, meter.totalBytes())
		return sunnyAccessTokenResult{SessionID: candidate.SessionID, AccountID: candidate.AccountID, Email: candidate.Email, Status: status, Error: message}
	})
	for outcome := range results {
		if ctx.Err() != nil {
			break
		}
		now := time.Now()
		item := map[string]any{"session_id": outcome.SessionID, "email": outcome.Email, "status": outcome.Status}
		if outcome.Error != "" {
			item["error"] = outcome.Error
		}
		switch outcome.Status {
		case "valid":
			result["valid"] = result["valid"].(int) + 1
			s.db.Model(&SunnySession{}).Where("id = ?", outcome.SessionID).Updates(map[string]any{"access_token_status": "valid", "access_token_error": "", "access_token_checked_at": now})
			s.appendAccountTaskEvent(task.ID, outcome.Email, "session", "access_token.valid", fmt.Sprintf("账户 %s：Access Token 有效", outcome.Email), "info", item)
		case "invalid":
			result["invalid"] = result["invalid"].(int) + 1
			s.db.Model(&SunnySession{}).Where("id = ?", outcome.SessionID).Updates(map[string]any{"access_token_status": "invalid", "access_token_error": outcome.Error, "access_token_checked_at": now})
			invalidSessions = append(invalidSessions, outcome.SessionID)
			if outcome.AccountID != 0 && !seenAccounts[outcome.AccountID] {
				seenAccounts[outcome.AccountID] = true
				invalidAccounts = append(invalidAccounts, outcome.AccountID)
			}
			s.appendAccountTaskEvent(task.ID, outcome.Email, "session", "access_token.invalid", fmt.Sprintf("账户 %s：Access Token 无效，%s", outcome.Email, outcome.Error), "warning", item)
		case "blocked":
			result["skipped"] = result["skipped"].(int) + 1
			s.db.Model(&SunnySession{}).Where("id = ?", outcome.SessionID).Updates(map[string]any{"access_token_status": "probe_blocked", "access_token_error": outcome.Error, "access_token_checked_at": now})
			s.appendAccountTaskEvent(task.ID, outcome.Email, "session", "access_token.probe_blocked", fmt.Sprintf("账户 %s：AT 检测被上游边缘拦截，未确认令牌失效", outcome.Email), "warning", item)
		default:
			result["failed"] = result["failed"].(int) + 1
			s.db.Model(&SunnySession{}).Where("id = ?", outcome.SessionID).Updates(map[string]any{"access_token_status": "probe_failed", "access_token_error": outcome.Error, "access_token_checked_at": now})
			s.appendAccountTaskEvent(task.ID, outcome.Email, "session", "access_token.check_failed", fmt.Sprintf("账户 %s：AT 检测失败，%s", outcome.Email, outcome.Error), "warning", item)
		}
		items = append(items, item)
		task.ProgressCurrent++
		s.persistTaskProgress(task, intValue(result["valid"], 0)+intValue(result["invalid"], 0), intValue(result["failed"], 0), now)
	}
	result["items"] = items
	if s.finishCancelledTask(task, result, "用户已停止 AT 检测任务") {
		return
	}
	if len(invalidAccounts) > 0 {
		renewalAccounts := s.filterActiveSunnyRenewalAccounts(invalidAccounts)
		if len(renewalAccounts) > 0 {
			renewalTask := s.createSunnyAccessTokenRenewalTask(task, "access_token_check", renewalAccounts)
			if renewalTask.ID != "" {
				queuedAccounts := make(map[uint]bool, len(renewalAccounts))
				for _, accountID := range renewalAccounts {
					queuedAccounts[accountID] = true
				}
				queuedSessions := make([]uint, 0, len(invalidSessions))
				for _, sessionID := range invalidSessions {
					if queuedAccounts[accountBySession[sessionID]] {
						queuedSessions = append(queuedSessions, sessionID)
					}
				}
				result["renewal_task_id"] = renewalTask.ID
				result["renewal_queued"] = len(renewalAccounts)
				result["invalid_session_ids"] = queuedSessions
			}
		}
	}
	s.completeSunnyAccessTokenCheckTask(task, result)
}

func (s *Server) failSunnyAccessTokenCheckTask(task *Task, message string) {
	task.Status = TaskFailed
	task.Error = message
	task.ErrorCount = task.ProgressTotal
	task.FinishedAt = sql.NullTime{Time: time.Now(), Valid: true}
	task.ResultJSON = dumpJSON(map[string]any{"requested": task.ProgressTotal, "valid": 0, "invalid": 0, "failed": task.ProgressTotal, "skipped": 0})
	s.db.Save(task)
	s.appendTaskEvent(task.ID, message, "log", "error", nil)
}

func (s *Server) completeSunnyAccessTokenCheckTask(task *Task, result map[string]any) {
	task.Status = TaskSucceeded
	task.SuccessCount = intValue(result["valid"], 0) + intValue(result["invalid"], 0)
	task.ErrorCount = intValue(result["failed"], 0)
	task.ResultJSON = dumpJSON(result)
	task.FinishedAt = sql.NullTime{Time: time.Now(), Valid: true}
	s.db.Save(task)
	s.appendTaskEvent(task.ID, "AT 检测任务完成", "log", "info", result)
}

func sunnyScheduledTaskDue(now time.Time, timeText string, frequencyHours int, latest *time.Time) bool {
	configured, err := time.ParseInLocation("15:04", timeText, now.Location())
	if err != nil {
		return false
	}
	anchor := time.Date(now.Year(), now.Month(), now.Day(), configured.Hour(), configured.Minute(), 0, 0, now.Location())
	if latest == nil {
		return !now.Before(anchor)
	}
	return !now.Before(latest.Add(time.Duration(frequencyHours) * time.Hour))
}

func (s *Server) latestScheduledTaskTime(taskType string) *time.Time {
	var tasks []Task
	s.db.Where("type = ?", taskType).Order("created_at desc").Limit(30).Find(&tasks)
	for _, task := range tasks {
		if boolValue(jsonMap(task.PayloadJSON)["scheduled"], false) {
			created := task.CreatedAt.In(applicationLocation())
			return &created
		}
	}
	return nil
}

func (s *Server) sunnyMaybeScheduleAccessTokenCheck() {
	config := s.sunnyMaintenanceSnapshot()
	if !boolValue(config["at_enabled"], true) {
		return
	}
	var healthTasks int64
	s.db.Model(&Task{}).Where("type = ? AND status NOT IN ?", sunnyHealthTaskType, []string{TaskSucceeded, TaskFailed, TaskInterrupted, TaskCancelled}).Count(&healthTasks)
	if healthTasks > 0 {
		return
	}
	now := time.Now().In(applicationLocation())
	if !sunnyScheduledTaskDue(now, text(config["at_time"]), intValue(config["at_frequency_hours"], 24), s.latestScheduledTaskTime(sunnyAccessTokenCheckTaskType)) {
		return
	}
	if _, err := s.createSunnyAccessTokenCheckTask(map[string]any{"scheduled": true}); err != nil && !strings.Contains(err.Error(), "正在执行") {
		log.Printf("scheduled AT check skipped: %v", err)
	}
}
