package main

import (
	"bufio"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"net/mail"
	"net/textproto"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const sunnyHealthTaskType = "sunny_account_health_check"

// The [C-...] value is a trust-and-safety case identifier, not a ban signal.
// Only completed deactivation statements are terminal evidence; warning and
// restriction notices must remain eligible for normal account checks.
var sunnyHealthBanMarker = regexp.MustCompile(`(?i)(?:access|account)(?:\s+\[\s*C-[A-Za-z0-9_-]{6,64}\s*\])?\s+(?:has\s+been\s+|was\s+|is\s+)?(?:deactivated|disabled)|(?:账户|账号)(?:已被|已经被|已|已经|被)(?:封禁|停用|禁用)|(?:アカウント|アクセス)(?:が|は)?(?:無効になりました|無効化されました|停止されました)|(?:계정|액세스)(?:이|가|은|는)?\s*(?:비활성화되었습니다|사용\s*중지되었습니다)`)
var sunnyFetchOutlookMailSubjects = fetchOutlookMailSubjects
var sunnyFetchMailSubjectsViaGraph = fetchMailSubjectsViaGraph
var sunnyFetchMailHeadersViaIMAP = fetchMailHeadersViaIMAP

type sunnyHealthCandidate struct {
	SessionID    uint
	Email        string
	MailboxType  string
	Channel      string
	AccessKey    string
	ClientID     string
	RefreshToken string
	Error        string
}

type sunnyHealthMailHeader struct {
	Subject string
	Date    time.Time
}

type sunnyHealthResult struct {
	SessionID    uint
	Email        string
	Banned       bool
	Checked      bool
	Error        string
	TrafficBytes int64
}

func (s *Server) sunnyHealthCheckConcurrency() int {
	return s.sunnyConfiguredConcurrency("health_concurrency", "SUNNY_HEALTHCHECK_CONCURRENCY", 16)
}

func sunnyHealthStatus(status string) string {
	return normalizeSunnyDisplayStatus(strings.TrimSpace(status))
}

func sunnyHealthRegisteredStatus(status string) bool {
	if strings.TrimSpace(status) == "" {
		return false
	}
	switch sunnyHealthStatus(status) {
	case "已注册", "已接码", "已反代", "PLUS试用中", "需二验", "registered", "phone_bound", "reverse_proxied":
		return true
	default:
		return false
	}
}

func sunnyHealthBannedStatus(status string) bool {
	return sunnyHealthStatus(status) == "已封禁"
}

func (s *Server) sunnyHealthCandidates(ids []uint, all bool) ([]sunnyHealthCandidate, int, error) {
	var sessions []SunnySession
	query := s.db.Model(&SunnySession{}).Select("id", "email")
	if len(ids) > 0 {
		query = query.Where("id IN ?", ids)
	} else if !all {
		return nil, 0, fmt.Errorf("请选择需要测活的账户")
	}
	if err := query.Order("id asc").Find(&sessions).Error; err != nil {
		return nil, 0, err
	}
	emails := make([]string, 0, len(sessions))
	sessionByEmail := map[string]SunnySession{}
	for _, session := range sessions {
		key := sunnyEmailKey(session.Email)
		sessionByEmail[key] = session
		emails = append(emails, session.Email)
	}
	var mailboxes []SunnyMailbox
	mailboxQuery := s.db.Model(&SunnyMailbox{})
	if !all {
		mailboxQuery = mailboxQuery.Where("email IN ?", emails)
	}
	if err := mailboxQuery.Order("id asc").Find(&mailboxes).Error; err != nil {
		return nil, 0, err
	}
	mailboxByEmail := map[string]SunnyMailbox{}
	for _, mailbox := range mailboxes {
		key := sunnyEmailKey(mailbox.Email)
		mailboxByEmail[key] = mailbox
		if all {
			emails = append(emails, mailbox.Email)
		}
	}
	var accounts []SunnyAccount
	accountQuery := s.db.Model(&SunnyAccount{}).Select("id", "email", "status")
	if !all {
		accountQuery = accountQuery.Where("email IN ?", emails)
	}
	if err := accountQuery.Order("id asc").Find(&accounts).Error; err != nil {
		return nil, 0, err
	}
	accountStatus := map[string]string{}
	for _, account := range accounts {
		key := sunnyEmailKey(account.Email)
		accountStatus[key] = account.Status
		if all {
			emails = append(emails, account.Email)
		}
	}
	if !all && len(sessions) == 0 {
		return []sunnyHealthCandidate{}, 0, nil
	}
	candidates := make([]sunnyHealthCandidate, 0, len(emails))
	skipped := 0
	seen := map[string]bool{}
	for _, email := range emails {
		key := sunnyEmailKey(email)
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		session := sessionByEmail[key]
		mailbox, ok := mailboxByEmail[key]
		if sunnyHealthBannedStatus(mailbox.Status) || sunnyHealthBannedStatus(accountStatus[key]) ||
			(!sunnyHealthRegisteredStatus(mailbox.Status) && !sunnyHealthRegisteredStatus(accountStatus[key])) {
			skipped++
			continue
		}
		if !ok {
			candidates = append(candidates, sunnyHealthCandidate{SessionID: session.ID, Email: email, Error: "邮箱凭证不完整"})
			continue
		}
		mailboxType := normalizeSunnyMailboxType(mailbox.MailboxType)
		if (mailboxType == "apple" && strings.TrimSpace(mailbox.AccessKey) == "") || (mailboxType == "remail" && strings.TrimSpace(mailbox.AccessKey) == "") || (mailboxType == "microsoft" && (strings.TrimSpace(mailbox.ClientID) == "" || strings.TrimSpace(mailbox.RefreshToken) == "")) {
			candidates = append(candidates, sunnyHealthCandidate{SessionID: session.ID, Email: email, Error: "邮箱凭证不完整"})
			continue
		}
		candidates = append(candidates, sunnyHealthCandidate{SessionID: session.ID, Email: mailbox.Email, MailboxType: mailboxType, Channel: normalizeSunnyMailboxChannel(mailboxType, mailbox.MailboxChannel), AccessKey: mailbox.AccessKey, ClientID: mailbox.ClientID, RefreshToken: mailbox.RefreshToken})
	}
	return candidates, skipped, nil
}

func (s *Server) createSunnyHealthTask(body map[string]any) (Task, error) {
	var ids []uint
	if raw := uintSlice(body["session_ids"]); len(raw) > 0 {
		ids = raw
	}
	all := boolValue(body["scheduled"], false)
	if len(ids) == 0 && !all {
		return Task{}, fmt.Errorf("请选择需要测活的账户")
	}
	var active int64
	s.db.Model(&Task{}).Where("type = ? AND status NOT IN ?", sunnyHealthTaskType, []string{TaskSucceeded, TaskFailed, TaskInterrupted, TaskCancelled}).Count(&active)
	if active > 0 {
		return Task{}, fmt.Errorf("已有账户测活任务正在执行，请稍候")
	}
	candidates, skipped, err := s.sunnyHealthCandidates(ids, all)
	if err != nil {
		return Task{}, err
	}
	payload := map[string]any{"session_ids": ids, "scheduled": all, "skipped": skipped}
	total := len(candidates)
	task := s.createTask(sunnyHealthTaskType, "sunny", payload, total)
	return task, nil
}

func (s *Server) executeSunnyAccountHealthCheckTask(task *Task, payload map[string]any) {
	task.Status = TaskRunning
	task.StartedAt = sql.NullTime{Time: time.Now(), Valid: true}
	s.db.Save(task)
	ctx, cancel := s.taskCancellationContext(task)
	defer cancel()
	ids := uintSlice(payload["session_ids"])
	all := boolValue(payload["scheduled"], false)
	candidates, skipped, err := s.sunnyHealthCandidates(ids, all)
	if err != nil {
		s.failSunnyHealthTask(task, err.Error())
		return
	}
	result := map[string]any{"requested": len(candidates), "checked": 0, "alive": 0, "banned": 0, "failed": 0, "skipped": skipped, "items": []any{}}
	if len(candidates) == 0 {
		s.completeSunnyHealthTask(task, result)
		return
	}
	proxyURL := s.sunnyMailboxProxyURL()
	concurrency := s.sunnyHealthCheckConcurrency()
	items := make([]any, 0, len(candidates))
	results := streamSunnyWorkerPoolContext(ctx, candidates, concurrency, func(candidate sunnyHealthCandidate) sunnyHealthResult {
		if candidate.Error != "" {
			return sunnyHealthResult{SessionID: candidate.SessionID, Email: candidate.Email, Error: candidate.Error}
		}
		var subjects []string
		var fetchErr error
		meter := &sunnyTrafficMeter{}
		if candidate.MailboxType == "remail" {
			var latest map[string]any
			latest, fetchErr = remailLatestMail(candidate.AccessKey, candidate.Email, 5)
			if fetchErr == nil {
				subjects = []string{text(latest["subject"]), text(latest["body"])}
				if rawItems, ok := latest["items"].([]map[string]any); ok && len(rawItems) > 0 {
					subjects = append(subjects, text(rawItems[0]["subject"]), text(rawItems[0]["body"]), text(rawItems[0]["body_preview"]))
				} else if rawItems, ok := latest["items"].([]any); ok && len(rawItems) > 0 {
					if item, itemOK := rawItems[0].(map[string]any); itemOK {
						subjects = append(subjects, text(item["subject"]), text(item["body"]), text(item["body_preview"]))
					}
				}
			}
		} else if candidate.MailboxType == "apple" && candidate.Channel == "xbovo" {
			subjects, fetchErr = fetchXbovoHealthMailEvidence(candidate.Email, candidate.AccessKey, 5, proxyURL)
		} else if candidate.MailboxType == "apple" && candidate.Channel == "url_api" {
			subjects, fetchErr = fetchURLAPIMailSubjects(candidate.Email, candidate.AccessKey, 5, proxyURL)
		} else if strings.TrimSpace(proxyURL) != "" {
			var token string
			for _, endpoint := range hotmailGraphTokenEndpoints {
				token, fetchErr = refreshHotmailAccessTokenFromEndpoint(candidate.ClientID, candidate.RefreshToken, endpoint, proxyURL, meter)
				if fetchErr == nil {
					subjects, fetchErr = fetchMailSubjectsViaGraphWithMeter(token, 5, proxyURL, meter)
					break
				}
			}
		} else {
			subjects, fetchErr = sunnyFetchOutlookMailSubjects(candidate.Email, candidate.ClientID, candidate.RefreshToken, 5, proxyURL)
		}
		trafficBytes := meter.totalBytes()
		if fetchErr != nil {
			return sunnyHealthResult{SessionID: candidate.SessionID, Email: candidate.Email, Error: fetchErr.Error(), TrafficBytes: trafficBytes}
		}
		banned := false
		for _, subject := range subjects {
			if sunnyHealthBanMarker.MatchString(subject) {
				banned = true
				break
			}
		}
		return sunnyHealthResult{SessionID: candidate.SessionID, Email: candidate.Email, Banned: banned, Checked: true, TrafficBytes: trafficBytes}
	})
	for outcome := range results {
		if ctx.Err() != nil {
			break
		}
		s.recordSunnyProxyTraffic(outcome.Email, outcome.TrafficBytes)
		item := map[string]any{"email": outcome.Email, "status": "alive"}
		item["proxy_traffic_bytes"] = outcome.TrafficBytes
		if outcome.Error != "" {
			now := time.Now()
			result["failed"] = result["failed"].(int) + 1
			item["status"] = "failed"
			item["error"] = outcome.Error
			s.appendAccountTaskEvent(task.ID, outcome.Email, "health", "health.check_failed", fmt.Sprintf("账户 %s 测活失败：%s", outcome.Email, outcome.Error), "warning", map[string]any{"error": outcome.Error})
			s.db.Model(&SunnyMailbox{}).Where("email = ?", outcome.Email).UpdateColumns(map[string]any{"last_health_checked_at": now, "updated_at": now})
			s.db.Model(&SunnyAccount{}).Where("email = ?", outcome.Email).UpdateColumns(map[string]any{"last_health_checked_at": now, "updated_at": now})
			s.db.Model(&SunnySession{}).Where("email = ?", outcome.Email).Updates(map[string]any{"health_check_status": "failed", "health_check_error": outcome.Error})
		} else {
			result["checked"] = result["checked"].(int) + 1
			now := time.Now()
			if outcome.Banned {
				result["banned"] = result["banned"].(int) + 1
				item["status"] = "banned"
				s.appendAccountTaskEvent(task.ID, outcome.Email, "health", "health.banned", fmt.Sprintf("账户 %s：已封禁", outcome.Email), "warning", nil)
				s.db.Model(&SunnyMailbox{}).Where("email = ?", outcome.Email).UpdateColumns(map[string]any{
					"last_health_checked_at": now, "status": "已封禁", "status_changed_at": now,
					"last_error": "测活邮件内容明确显示账户已封禁或停用", "updated_at": now,
				})
				s.db.Model(&SunnyAccount{}).Where("email = ?", outcome.Email).UpdateColumns(map[string]any{
					"last_health_checked_at": now, "status": "已封禁", "status_changed_at": now,
					"last_error": "测活邮件内容明确显示账户已封禁或停用", "updated_at": now,
				})
				s.db.Model(&SunnySession{}).Where("email = ?", outcome.Email).Updates(map[string]any{
					"health_check_status": "banned", "health_check_error": "",
				})
			} else {
				result["alive"] = result["alive"].(int) + 1
				s.appendAccountTaskEvent(task.ID, outcome.Email, "health", "health.alive", fmt.Sprintf("账户 %s：存活", outcome.Email), "info", nil)
				// A successful health check is not a mailbox edit or an account status change.
				s.db.Model(&SunnyMailbox{}).Where("email = ?", outcome.Email).UpdateColumn("last_health_checked_at", now)
				s.db.Model(&SunnyAccount{}).Where("email = ?", outcome.Email).UpdateColumn("last_health_checked_at", now)
				s.db.Model(&SunnySession{}).Where("email = ?", outcome.Email).Updates(map[string]any{"health_check_status": "alive", "health_check_error": ""})
			}
		}
		items = append(items, item)
		current := task.ProgressCurrent + 1
		task.ProgressCurrent = current
		s.persistTaskProgress(task, intValue(result["alive"], 0)+intValue(result["banned"], 0), intValue(result["failed"], 0), time.Now())
	}
	result["items"] = items
	if s.finishCancelledTask(task, result, "用户已停止账户测活任务") {
		return
	}
	s.completeSunnyHealthTask(task, result)
}

func (s *Server) failSunnyHealthTask(task *Task, message string) {
	task.Status = TaskFailed
	task.Error = message
	task.ErrorCount = task.ProgressTotal
	task.FinishedAt = sql.NullTime{Time: time.Now(), Valid: true}
	task.ResultJSON = dumpJSON(map[string]any{"requested": task.ProgressTotal, "checked": 0, "alive": 0, "banned": 0, "failed": task.ProgressTotal, "skipped": 0})
	s.db.Save(task)
	s.appendTaskEvent(task.ID, message, "log", "error", nil)
}

func (s *Server) completeSunnyHealthTask(task *Task, result map[string]any) {
	task.Status = TaskSucceeded
	task.SuccessCount = intValue(result["alive"], 0) + intValue(result["banned"], 0)
	task.ErrorCount = intValue(result["failed"], 0)
	task.ResultJSON = dumpJSON(result)
	task.FinishedAt = sql.NullTime{Time: time.Now(), Valid: true}
	s.db.Save(task)
	s.appendTaskEvent(task.ID, "账户测活任务完成", "log", "info", result)
}

func fetchOutlookMailSubjects(emailAddr, clientID, refreshToken string, limit int, proxyURL string) ([]string, error) {
	errors := []string{}
	for _, endpoint := range hotmailGraphTokenEndpoints {
		token, err := refreshHotmailAccessTokenFromEndpoint(clientID, refreshToken, endpoint, proxyURL)
		if err != nil {
			if isTerminalOutlookMailError(err) {
				return nil, err
			}
			errors = append(errors, endpoint.Name+" token: "+err.Error())
			continue
		}
		subjects, err := sunnyFetchMailSubjectsViaGraph(token, limit, proxyURL)
		if err == nil {
			return subjects, nil
		}
		errors = append(errors, endpoint.Name+" Graph: "+err.Error())
	}
	for _, endpoint := range hotmailTokenEndpoints {
		token, err := refreshHotmailAccessTokenFromEndpoint(clientID, refreshToken, endpoint, proxyURL)
		if err != nil {
			if isTerminalOutlookMailError(err) {
				return nil, err
			}
			errors = append(errors, endpoint.Name+" token: "+err.Error())
			continue
		}
		headers, err := sunnyFetchMailHeadersViaIMAP(emailAddr, token, limit, proxyURL)
		if err == nil {
			return headers, nil
		}
		errors = append(errors, endpoint.Name+" IMAP: "+err.Error())
	}
	return nil, newOutlookMailAggregateError(errors)
}

func fetchMailSubjectsViaGraph(accessToken string, limit int, proxyURL string) ([]string, error) {
	return fetchMailSubjectsViaGraphWithMeter(accessToken, limit, proxyURL, nil)
}

func fetchMailSubjectsViaGraphWithMeter(accessToken string, limit int, proxyURL string, meter *sunnyTrafficMeter) ([]string, error) {
	if limit < 1 {
		limit = 5
	}
	if limit > 20 {
		limit = 20
	}
	endpoint, err := url.Parse(outlookGraphMessagesURL)
	if err != nil {
		return nil, fmt.Errorf("invalid Graph messages URL: %w", err)
	}
	query := endpoint.Query()
	query.Set("$top", strconv.Itoa(limit))
	query.Set("$orderby", "receivedDateTime desc")
	query.Set("$select", "subject,bodyPreview")
	endpoint.RawQuery = query.Encode()

	client := &http.Client{Timeout: 15 * time.Second}
	if strings.TrimSpace(proxyURL) != "" {
		proxy, parseErr := url.Parse(proxyURL)
		if parseErr != nil {
			return nil, fmt.Errorf("invalid Graph proxy URL: %w", parseErr)
		}
		transport := &http.Transport{Proxy: http.ProxyURL(proxy)}
		if meter != nil {
			client.Transport = &sunnyTrafficTransport{base: transport, meter: meter}
		} else {
			client.Transport = transport
		}
	}
	req, err := http.NewRequest(http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Graph request failed: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("Graph response read failed: %w", err)
	}
	var payload struct {
		Value []struct {
			Subject     string `json:"subject"`
			BodyPreview string `json:"bodyPreview"`
		} `json:"value"`
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, fmt.Errorf("Graph returned invalid JSON (HTTP %d)", resp.StatusCode)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		detail := strings.TrimSpace(strings.Join([]string{payload.Error.Code, payload.Error.Message}, ": "))
		return nil, fmt.Errorf("Graph HTTP %d: %s", resp.StatusCode, fallback(detail, string(raw[:min(len(raw), 300)])))
	}
	subjects := make([]string, 0, len(payload.Value))
	for _, message := range payload.Value {
		if evidence := strings.TrimSpace(message.Subject + "\n" + message.BodyPreview); evidence != "" {
			subjects = append(subjects, evidence)
		}
	}
	return subjects, nil
}

func fetchMailHeadersViaIMAP(emailAddr, accessToken string, limit int, proxyURL string) ([]string, error) {
	if limit < 1 {
		limit = 5
	}
	if limit > 5 {
		limit = 5
	}
	conn, err := dialOutlookIMAPS(proxyURL)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	reader := bufio.NewReader(conn)
	if _, err := reader.ReadString('\n'); err != nil {
		return nil, fmt.Errorf("IMAP greeting failed: %w", err)
	}
	write := func(format string, args ...any) error {
		_, err := fmt.Fprintf(conn, format+"\r\n", args...)
		return err
	}
	readUntil := func(tag string) (string, error) {
		var b strings.Builder
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return b.String(), err
			}
			b.WriteString(line)
			if strings.HasPrefix(line, tag+" ") {
				return b.String(), nil
			}
		}
	}
	auth := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("user=%s\x01auth=Bearer %s\x01\x01", emailAddr, accessToken)))
	if err := write("A1 AUTHENTICATE XOAUTH2 %s", auth); err != nil {
		return nil, err
	}
	var authOut strings.Builder
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("IMAP XOAUTH2 response failed: %w", err)
		}
		authOut.WriteString(line)
		if strings.HasPrefix(line, "+") {
			if err := write(""); err != nil {
				return nil, err
			}
			continue
		}
		if strings.HasPrefix(line, "A1 ") {
			break
		}
	}
	if !strings.Contains(authOut.String(), "A1 OK") {
		return nil, fmt.Errorf("IMAP XOAUTH2 authentication failed: %s", strings.TrimSpace(authOut.String()))
	}
	allHeaders := make([]sunnyHealthMailHeader, 0, limit*2)
	for index, folder := range []string{"INBOX", "Junk", "Junk Email"} {
		selectTag := fmt.Sprintf("S%d", index+1)
		quotedFolder := folder
		if folder != "INBOX" {
			quotedFolder = `"` + folder + `"`
		}
		if err := write("%s SELECT %s", selectTag, quotedFolder); err != nil {
			return nil, err
		}
		selectOut, err := readUntil(selectTag)
		if err != nil || !strings.Contains(selectOut, selectTag+" OK") {
			continue
		}
		total := 0
		for _, line := range strings.Split(selectOut, "\n") {
			fields := strings.Fields(strings.TrimSpace(line))
			if len(fields) >= 3 && fields[0] == "*" && fields[2] == "EXISTS" {
				total, _ = strconv.Atoi(fields[1])
				break
			}
		}
		if total <= 0 {
			continue
		}
		start := total - limit + 1
		if start < 1 {
			start = 1
		}
		fetchTag := fmt.Sprintf("F%d", index+1)
		if err := write("%s FETCH %d:%d BODY.PEEK[HEADER.FIELDS (SUBJECT DATE)]", fetchTag, start, total); err != nil {
			return nil, err
		}
		raw, err := readUntil(fetchTag)
		if err != nil {
			return nil, err
		}
		for sequence := start; sequence <= total; sequence++ {
			if header, ok := extractSunnyHeader(raw, sequence, fetchTag); ok {
				allHeaders = append(allHeaders, header)
			}
		}
	}
	if err := write("ZZ LOGOUT"); err == nil {
		_, _ = readUntil("ZZ")
	}
	sort.SliceStable(allHeaders, func(i, j int) bool { return allHeaders[i].Date.After(allHeaders[j].Date) })
	if len(allHeaders) > limit {
		allHeaders = allHeaders[:limit]
	}
	result := make([]string, 0, len(allHeaders))
	for _, header := range allHeaders {
		result = append(result, header.Subject)
	}
	return result, nil
}

func extractSunnyHeader(raw string, sequence int, _ string) (sunnyHealthMailHeader, bool) {
	marker := fmt.Sprintf("* %d FETCH", sequence)
	start := strings.Index(raw, marker)
	if start < 0 {
		return sunnyHealthMailHeader{}, false
	}
	literalMarker := strings.Index(raw[start:], "}\r\n")
	if literalMarker < 0 {
		return sunnyHealthMailHeader{}, false
	}
	literalMarker += start
	openBrace := strings.LastIndex(raw[start:literalMarker], "{")
	if openBrace < 0 {
		return sunnyHealthMailHeader{}, false
	}
	openBrace += start
	literalLength, err := strconv.Atoi(strings.TrimSpace(raw[openBrace+1 : literalMarker]))
	literalStart := literalMarker + 3
	if err != nil || literalLength < 1 || literalStart+literalLength > len(raw) {
		return sunnyHealthMailHeader{}, false
	}
	headerRaw := raw[literalStart : literalStart+literalLength]
	mimeHeader, err := textproto.NewReader(bufio.NewReader(strings.NewReader(headerRaw))).ReadMIMEHeader()
	if err != nil {
		return sunnyHealthMailHeader{}, false
	}
	subject := mimeHeader.Get("Subject")
	if decoded, decodeErr := (&mime.WordDecoder{CharsetReader: mailCharsetReader}).DecodeHeader(subject); decodeErr == nil {
		subject = decoded
	}
	date, _ := mail.ParseDate(mimeHeader.Get("Date"))
	return sunnyHealthMailHeader{Subject: subject, Date: date}, true
}

func (s *Server) sunnyAccountHealthScheduleLoop() {
	interval := time.Minute
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		s.sunnyMaybeScheduleHealthCheck()
		s.sunnyMaybeScheduleAccessTokenCheck()
		select {
		case <-s.stop:
			return
		case <-ticker.C:
		}
	}
}

func (s *Server) sunnyMaybeScheduleHealthCheck() {
	config := s.sunnyMaintenanceSnapshot()
	if raw := strings.TrimSpace(os.Getenv("SUNNY_HEALTHCHECK_ENABLED")); raw != "" {
		config["health_enabled"] = boolValue(raw, true)
	}
	if !boolValue(config["health_enabled"], true) {
		return
	}
	timeText := text(config["health_time"])
	if raw := strings.TrimSpace(os.Getenv("SUNNY_HEALTHCHECK_TIME")); raw != "" {
		timeText = raw
	}
	now := time.Now().In(applicationLocation())
	if !sunnyScheduledTaskDue(now, timeText, intValue(config["health_frequency_hours"], 24), s.latestScheduledTaskTime(sunnyHealthTaskType)) {
		return
	}
	if _, err := s.createSunnyHealthTask(map[string]any{"scheduled": true}); err != nil {
		if !strings.Contains(err.Error(), "正在执行") {
			log.Printf("scheduled account health check skipped: %v", err)
		}
	}
}
