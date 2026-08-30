package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	TaskPending         = "pending"
	TaskClaimed         = "claimed"
	TaskRunning         = "running"
	TaskSucceeded       = "succeeded"
	TaskFailed          = "failed"
	TaskInterrupted     = "interrupted"
	TaskCancelRequested = "cancel_requested"
	TaskCancelled       = "cancelled"
)

var terminalTaskStatuses = map[string]bool{
	TaskSucceeded: true, TaskFailed: true, TaskInterrupted: true, TaskCancelled: true,
}

type Runtime struct {
	db      *gormDB
	wake    chan struct{}
	stop    chan struct{}
	running map[string]bool
	mu      sync.Mutex
}

type gormDB = interface {
}

type TaskEventContext struct {
	Email       string
	AccountID   uint
	MailboxID   uint
	Module      string
	Action      string
	Scope       string
	SubjectType string
	OperationID string
	SubjectKey  string
}

var (
	taskEventBracketEmailPattern = regexp.MustCompile(`^\s*\[([^\]\s]+@[^\]\s]+)\]`)
	taskEventInlineEmailPattern  = regexp.MustCompile(`(?i)\b[[:alnum:]._%+\-]+@[[:alnum:].\-]+\.[[:alpha:]]{2,}\b`)
	taskEventModulePattern       = regexp.MustCompile(`^\s*(?:\[[^\]\s]+@[^\]\s]+\]\s*)?\[([^\]]+)\]`)
)

func normalizeTaskEventModule(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "认证", "auth", "oauth", "登录", "注册":
		return "auth"
	case "邮箱", "邮件", "mail", "mailbox", "email":
		return "mailbox"
	case "接码", "phone", "sms", "mobile":
		return "sms"
	case "session", "token", "at", "rt":
		return "session"
	case "代理", "proxy":
		return "proxy"
	case "反代", "sub2api":
		return "sub2api"
	case "试用", "trial":
		return "trial"
	case "checkout", "提链":
		return "checkout"
	case "订阅", "subscription":
		return "subscription"
	case "测活", "health":
		return "health"
	case "system", "系统", "":
		return "system"
	default:
		return value
	}
}

func inferTaskEventEmail(message string, detail map[string]any) string {
	if email := text(detail["email"]); email != "" {
		return email
	}
	if match := taskEventBracketEmailPattern.FindStringSubmatch(message); len(match) > 1 {
		return strings.TrimSpace(match[1])
	}
	if match := taskEventInlineEmailPattern.FindString(message); match != "" {
		return strings.TrimSpace(match)
	}
	return ""
}

func inferTaskEventModule(message, typ string, detail map[string]any) string {
	if module := text(detail["module"]); module != "" {
		return normalizeTaskEventModule(module)
	}
	if match := taskEventModulePattern.FindStringSubmatch(message); len(match) > 1 {
		return normalizeTaskEventModule(match[1])
	}
	lower := strings.ToLower(message)
	checks := []struct {
		module string
		words  []string
	}{
		{"sub2api", []string{"sub2api", "反代"}}, {"trial", []string{"试用", "trial"}},
		{"checkout", []string{"checkout", "支付方式", "提链"}}, {"health", []string{"测活", "封禁"}},
		{"subscription", []string{"订阅", "subscription"}}, {"mailbox", []string{"邮箱", "邮件", "mail", "otp"}},
		{"sms", []string{"接码", "手机号", "phone", "sms"}}, {"session", []string{"session", "access token", "refresh token", " rt", " at"}},
		{"proxy", []string{"代理", "proxy"}}, {"auth", []string{"登录", "注册", "认证", "oauth", "login", "register"}},
	}
	for _, check := range checks {
		for _, word := range check.words {
			if strings.Contains(lower, word) {
				return check.module
			}
		}
	}
	if normalized := normalizeTaskEventModule(typ); normalized != "system" && normalized != "log" && normalized != "state" {
		return normalized
	}
	return "system"
}

func uintDetail(detail map[string]any, key string) uint {
	value, _ := strconv.ParseUint(text(detail[key]), 10, 64)
	return uint(value)
}

func taskEventMetadata(message, typ string, detail map[string]any, ctx TaskEventContext) TaskEventContext {
	if detail == nil {
		detail = map[string]any{}
	}
	if ctx.Email == "" {
		ctx.Email = inferTaskEventEmail(message, detail)
	}
	ctx.Email = strings.TrimSpace(ctx.Email)
	if ctx.AccountID == 0 {
		ctx.AccountID = uintDetail(detail, "account_id")
	}
	if ctx.MailboxID == 0 {
		ctx.MailboxID = uintDetail(detail, "mailbox_id")
	}
	if ctx.Module == "" {
		ctx.Module = inferTaskEventModule(message, typ, detail)
	} else {
		ctx.Module = normalizeTaskEventModule(ctx.Module)
	}
	if ctx.Action == "" {
		ctx.Action = fallback(text(detail["action"]), ctx.Module+".event")
	}
	if ctx.OperationID == "" {
		ctx.OperationID = text(detail["operation_id"])
	}
	if ctx.Email != "" {
		ctx.Scope = "account"
		ctx.SubjectType = fallback(ctx.SubjectType, "account")
		ctx.SubjectKey = strings.ToLower(ctx.Email)
	} else {
		ctx.Scope = fallback(ctx.Scope, text(detail["scope"]))
		if ctx.Scope == "selected" {
			ctx.Scope = "account"
		}
		ctx.Scope = fallback(ctx.Scope, "global")
		ctx.SubjectType = fallback(ctx.SubjectType, "system")
	}
	return ctx
}

func (s *Server) createTask(taskType, platform string, payload map[string]any, total int) Task {
	if total <= 0 {
		total = 1
	}
	task := Task{
		ID:            randomID("task"),
		Type:          taskType,
		Platform:      platform,
		Status:        TaskPending,
		PayloadJSON:   dumpJSON(payload),
		ResultJSON:    "{}",
		ProgressTotal: total,
	}
	s.db.Create(&task)
	s.appendTaskEvent(task.ID, "Task created", "log", "info", nil)
	s.wakeRuntime()
	return task
}

// persistTaskProgress records the counters after one account outcome has been
// consumed. Keeping these fields in the task row lets polling clients display
// live success/failure totals instead of waiting for the final summary save.
func (s *Server) persistTaskProgress(task *Task, success, failed int, updatedAt time.Time) {
	task.SuccessCount = success
	task.ErrorCount = failed
	task.UpdatedAt = updatedAt
	s.db.Model(&Task{}).Where("id = ?", task.ID).Updates(map[string]any{
		"progress_current": task.ProgressCurrent,
		"success_count":    success,
		"error_count":      failed,
		"updated_at":       updatedAt,
	})
}

func serializeTask(t Task) map[string]any {
	result := jsonMap(t.ResultJSON)
	errors := []any{}
	if v, ok := result["errors"]; ok {
		errors, _ = v.([]any)
	}
	cashier := []any{}
	if v, ok := result["cashier_urls"]; ok {
		cashier, _ = v.([]any)
	}
	label := fmt.Sprintf("%d/%d", t.ProgressCurrent, t.ProgressTotal)
	if t.ProgressTotal <= 0 {
		label = fmt.Sprint(t.ProgressCurrent)
	}
	return map[string]any{
		"id": t.ID, "task_id": t.ID, "type": t.Type, "platform": t.Platform, "status": t.Status,
		"progress":        label,
		"progress_detail": map[string]any{"current": t.ProgressCurrent, "total": t.ProgressTotal, "label": label},
		"success":         t.SuccessCount, "error_count": t.ErrorCount, "errors": errors, "cashier_urls": cashier,
		"error":      t.Error,
		"created_at": formatTime(t.CreatedAt), "started_at": nullableTime(t.StartedAt.Valid, t.StartedAt.Time),
		"finished_at": nullableTime(t.FinishedAt.Valid, t.FinishedAt.Time), "updated_at": formatTime(t.UpdatedAt),
		"result":      result,
		"terminal":    terminalTaskStatuses[t.Status],
		"cancellable": t.Status == TaskPending || t.Status == TaskClaimed || t.Status == TaskRunning || t.Status == TaskCancelRequested,
	}
}

func (s *Server) appendTaskEvent(taskID, message, typ, level string, detail map[string]any) TaskEvent {
	return s.appendTaskEventWithContext(taskID, message, typ, level, detail, TaskEventContext{})
}

func (s *Server) appendAccountTaskEvent(taskID, email, module, action, message, level string, detail map[string]any) TaskEvent {
	return s.appendTaskEventWithContext(taskID, message, "log", level, detail, TaskEventContext{
		Email: email, Module: module, Action: action, Scope: "account", SubjectType: "account",
	})
}

func (s *Server) appendTaskEventWithContext(taskID, message, typ, level string, detail map[string]any, ctx TaskEventContext) TaskEvent {
	if typ == "" {
		typ = "log"
	}
	if level == "" {
		level = "info"
	}
	clonedDetail := make(map[string]any, len(detail)+5)
	for key, value := range detail {
		clonedDetail[key] = value
	}
	detail = clonedDetail
	ctx = taskEventMetadata(message, typ, detail, ctx)
	if ctx.OperationID == "" && ctx.Email != "" {
		ctx.OperationID = taskID + ":" + ctx.SubjectKey + ":" + ctx.Module
	}
	detail["scope"] = ctx.Scope
	detail["module"] = ctx.Module
	detail["action"] = ctx.Action
	if ctx.Email != "" {
		detail["email"] = ctx.Email
	}
	if ctx.OperationID != "" {
		detail["operation_id"] = ctx.OperationID
	}
	sanitizedDetail, _ := sanitizePersistedValue(detail, "").(map[string]any)
	ev := TaskEvent{
		TaskID: taskID, Type: typ, Level: level, Message: sanitizePersistedString(message),
		Scope: ctx.Scope, SubjectType: ctx.SubjectType, SubjectKey: ctx.SubjectKey, Email: ctx.Email,
		AccountID: ctx.AccountID, MailboxID: ctx.MailboxID, Module: ctx.Module, Action: ctx.Action,
		OperationID: ctx.OperationID, DetailJSON: dumpJSON(sanitizedDetail),
	}
	s.db.Create(&ev)
	// Automatic maintenance tasks (for example AT renewal started by a
	// subscription check) carry the originating task ID in their payload. Mirror
	// their events to that parent so a single account-management log view keeps
	// showing the complete workflow instead of stopping at task creation.
	if parentID := s.parentTaskID(taskID); parentID != "" && parentID != taskID {
		parentEvent := ev
		parentEvent.ID = 0
		parentEvent.TaskID = parentID
		s.db.Create(&parentEvent)
	}
	return ev
}

func (s *Server) parentTaskID(taskID string) string {
	var task Task
	if err := s.db.Select("payload_json").Where("id = ?", taskID).First(&task).Error; err != nil {
		return ""
	}
	parentID := strings.TrimSpace(text(jsonMap(task.PayloadJSON)["source_task_id"]))
	if parentID == "" || parentID == taskID {
		return ""
	}
	var parent Task
	if s.db.Select("id").Where("id = ?", parentID).First(&parent).Error != nil {
		return ""
	}
	return parentID
}

func serializeEvent(ev TaskEvent) map[string]any {
	return map[string]any{
		"id": ev.ID, "task_id": ev.TaskID, "type": ev.Type, "level": ev.Level,
		"message": ev.Message, "line": ev.Message, "scope": ev.Scope, "subject_type": ev.SubjectType,
		"subject_key": ev.SubjectKey, "email": ev.Email, "account_id": ev.AccountID, "mailbox_id": ev.MailboxID,
		"module": ev.Module, "action": ev.Action, "operation_id": ev.OperationID,
		"detail": jsonMap(ev.DetailJSON), "created_at": formatTime(ev.CreatedAt),
	}
}

func (s *Server) handleTasks(w http.ResponseWriter, r *http.Request, rest string) {
	if rest == "" && r.Method == http.MethodGet {
		q := r.URL.Query()
		page := intValue(q.Get("page"), 1)
		if page < 1 {
			page = 1
		}
		size := intValue(q.Get("page_size"), 50)
		if size < 1 {
			size = 50
		}
		query := s.db.Model(&Task{})
		if q.Get("platform") != "" {
			query = query.Where("platform = ?", q.Get("platform"))
		}
		if q.Get("status") != "" {
			query = query.Where("status = ?", q.Get("status"))
		}
		var total int64
		query.Count(&total)
		var tasks []Task
		query.Order("created_at DESC").Offset((page - 1) * size).Limit(size).Find(&tasks)
		items := []map[string]any{}
		for _, t := range tasks {
			items = append(items, serializeTask(t))
		}
		writeJSON(w, 200, map[string]any{"total": total, "page": page, "items": items})
		return
	}
	if rest == "/register" && r.Method == http.MethodPost {
		body, _ := parseBody(r)
		total := intValue(body["count"], 1)
		task := s.createTask("register", text(body["platform"]), body, total)
		writeJSON(w, 200, serializeTask(task))
		return
	}
	if rest == "/phone-bind" && r.Method == http.MethodPost {
		s.createSimpleTask(w, r, "phone_bind", "chatgpt")
		return
	}
	if rest == "/codex-oauth" && r.Method == http.MethodPost {
		body, _ := parseBody(r)
		total := len(uintSlice(body["ids"]))
		if total == 0 {
			total = 1
		}
		task := s.createTask("codex_oauth", fallback(text(body["platform"]), "chatgpt"), body, total)
		writeJSON(w, 200, serializeTask(task))
		return
	}
	if rest == "/get-rt" && r.Method == http.MethodPost {
		s.createSimpleTask(w, r, "get_rt", "chatgpt")
		return
	}
	if rest == "/get-rt-bypass" && r.Method == http.MethodPost {
		s.createSimpleTask(w, r, "get_rt_bypass", "chatgpt")
		return
	}
	if rest == "/gopay-pay-chatgpt" && r.Method == http.MethodPost {
		body, _ := parseBody(r)
		total := len(uintSlice(body["chatgpt_account_ids"]))
		if total == 0 {
			total = intValue(body["register_count"], 1)
		}
		task := s.createTask("gopay_pay_chatgpt", "chatgpt", body, total)
		writeJSON(w, 200, serializeTask(task))
		return
	}
	if rest == "/gopay-register-account" && r.Method == http.MethodPost {
		body, _ := parseBody(r)
		task := s.createTask("gopay_register_account", "gopay", body, 1)
		writeJSON(w, 200, serializeTask(task))
		return
	}
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	if len(parts) >= 1 && parts[0] != "" {
		taskID := parts[0]
		var task Task
		if s.db.First(&task, "id = ?", taskID).Error != nil {
			writeError(w, 404, "task not found")
			return
		}
		if len(parts) == 1 && r.Method == http.MethodGet {
			s.reconcilePythonTaskStatus(&task)
			writeJSON(w, 200, serializeTask(task))
			return
		}
		if len(parts) == 2 && parts[1] == "events" && r.Method == http.MethodGet {
			s.handleTaskEvents(w, r, taskID)
			return
		}
		if len(parts) == 2 && parts[1] == "cancel" && r.Method == http.MethodPost {
			if terminalTaskStatuses[task.Status] {
				writeJSON(w, 200, serializeTask(task))
				return
			}
			isRegistrationTask := task.Type == "sunny_register" || task.Type == "sunny_login"
			cancelMessage := "用户已停止任务"
			requestMessage := "Task cancel requested"
			if task.Type == "sunny_refresh_session" {
				cancelMessage = "用户已停止 AT 续期任务"
				requestMessage = "用户已请求停止 AT 续期任务，正在关闭当前任务进程、浏览器与邮箱读取资源；等待中的账户将不再执行"
			} else if strings.HasPrefix(task.Type, "sunny_") && !sunnyGoTaskType(task.Type) {
				cancelMessage = "用户已停止 SunnyRegister 注册任务"
				requestMessage = "用户已请求停止 SunnyRegister 注册任务，正在关闭任务进程、浏览器与邮箱读取资源"
			}
			if task.Status == TaskPending {
				task.Status = TaskCancelled
				task.Error = cancelMessage
				task.FinishedAt = sql.NullTime{Time: time.Now(), Valid: true}
			} else {
				task.Status = TaskCancelRequested
			}
			s.db.Save(&task)
			s.appendTaskEvent(task.ID, requestMessage, "log", "warning", map[string]any{"cancelled": true})
			if strings.HasPrefix(task.Type, "sunny_") && !sunnyGoTaskType(task.Type) {
				if task.Status == TaskCancelled {
					if isRegistrationTask {
						s.markSunnyUnfinishedMailboxes(&task, "任务已由用户停止，当前邮箱未完成本次注册流程")
					}
				} else if err := s.requestPythonWorkerCancel(task.ID); err != nil {
					s.appendTaskEvent(task.ID, "Python Worker 停止接口调用失败，将继续通过数据库取消信号终止任务: "+err.Error(), "log", "warning", map[string]any{"cancelled": true})
				}
				_ = s.db.First(&task, "id = ?", task.ID).Error
			}
			writeJSON(w, 200, serializeTask(task))
			return
		}
		if len(parts) == 3 && parts[1] == "logs" && parts[2] == "stream" && r.Method == http.MethodGet {
			s.streamTaskEvents(w, r, taskID)
			return
		}
	}
	writeError(w, 404, "not found")
}

func (s *Server) createSimpleTask(w http.ResponseWriter, r *http.Request, typ, platform string) {
	body, _ := parseBody(r)
	if text(body["platform"]) != "" {
		platform = text(body["platform"])
	}
	total := len(uintSlice(body["ids"]))
	if total == 0 {
		total = len(uintSlice(body["account_ids"]))
	}
	if total == 0 {
		total = len(uintSlice(body["chatgpt_account_ids"]))
	}
	if total == 0 {
		total = 1
	}
	task := s.createTask(typ, platform, body, total)
	writeJSON(w, 200, serializeTask(task))
}

func (s *Server) handleTaskEvents(w http.ResponseWriter, r *http.Request, taskID string) {
	since := intValue(r.URL.Query().Get("since"), 0)
	limit := intValue(r.URL.Query().Get("limit"), 200)
	if limit < 1 || limit > 1000 {
		limit = 200
	}
	query := s.db.Where("task_id = ? AND id > ?", taskID, since)
	for _, filter := range []struct{ query, column string }{
		{"email", "email"}, {"module", "module"}, {"action", "action"}, {"level", "level"}, {"scope", "scope"}, {"operation_id", "operation_id"},
	} {
		if value := strings.TrimSpace(r.URL.Query().Get(filter.query)); value != "" {
			if filter.column == "email" {
				query = query.Where("LOWER(email) = ?", strings.ToLower(value))
			} else {
				query = query.Where(filter.column+" = ?", value)
			}
		}
	}
	var evs []TaskEvent
	query.Order("id ASC").Limit(limit).Find(&evs)
	items := []map[string]any{}
	for _, ev := range evs {
		items = append(items, serializeEvent(ev))
	}
	writeJSON(w, 200, map[string]any{"items": items})
}

func (s *Server) streamTaskEvents(w http.ResponseWriter, r *http.Request, taskID string) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	flusher, _ := w.(http.Flusher)
	since := uint(intValue(r.URL.Query().Get("since"), 0))
	if since == 0 {
		since = uint(intValue(r.Header.Get("Last-Event-ID"), 0))
	}
	fmt.Fprintf(w, "retry: 5000\n: connected\n\n")
	if flusher != nil {
		flusher.Flush()
	}
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	deadline := time.After(10 * time.Minute)
	for {
		select {
		case <-r.Context().Done():
			return
		case <-deadline:
			return
		case <-ticker.C:
			var evs []TaskEvent
			s.db.Where("task_id = ? AND id > ?", taskID, since).Order("id ASC").Limit(200).Find(&evs)
			for _, ev := range evs {
				since = ev.ID
				b, _ := json.Marshal(serializeEvent(ev))
				fmt.Fprintf(w, "id: %d\ndata: %s\n\n", ev.ID, string(b))
			}
			var task Task
			if s.db.First(&task, "id = ?", taskID).Error != nil {
				fmt.Fprintf(w, "data: {\"done\":true,\"status\":\"failed\",\"line\":\"task not found\"}\n\n")
				if flusher != nil {
					flusher.Flush()
				}
				return
			}
			if terminalTaskStatuses[task.Status] {
				b, _ := json.Marshal(map[string]any{"done": true, "status": task.Status, "line": fallback(task.Error, "Task completed")})
				fmt.Fprintf(w, "data: %s\n\n", b)
				if flusher != nil {
					flusher.Flush()
				}
				return
			}
			if len(evs) == 0 {
				fmt.Fprintf(w, ": ping\n\n")
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
	}
}

func (s *Server) reconcilePythonTaskStatus(task *Task) {
	if task == nil || terminalTaskStatuses[task.Status] || !strings.HasPrefix(task.Type, "sunny_") || sunnyGoTaskType(task.Type) {
		return
	}
	if task.Status != TaskClaimed && task.Status != TaskRunning && task.Status != TaskCancelRequested {
		return
	}
	lastActivity := task.UpdatedAt
	var ev TaskEvent
	if err := s.db.Where("task_id = ?", task.ID).Order("created_at DESC").First(&ev).Error; err == nil && ev.CreatedAt.After(lastActivity) {
		lastActivity = ev.CreatedAt
	}
	if !lastActivity.IsZero() && time.Since(lastActivity) < 90*time.Second {
		if task.Status != TaskCancelRequested || time.Since(lastActivity) < 20*time.Second {
			return
		}
	}
	silentFor := time.Since(lastActivity)
	if task.Status == TaskCancelRequested && silentFor >= 20*time.Second {
		s.interruptStaleSunnyTask(task, "Python Worker 未在停止请求后及时退出，已强制结束注册任务")
		return
	}

	workerURL := strings.TrimRight(strings.TrimSpace(os.Getenv("PYTHON_WORKER_URL")), "/")
	if workerURL == "" {
		workerURL = "http://127.0.0.1:8765"
	}
	healthOK, stillRunning := s.pythonWorkerTaskRunning(workerURL, task.ID)
	// A failed health request is a transport signal, not proof that the task
	// stopped. The worker process owns the task and its watcher will finalize it
	// if the child actually exits; interrupting here turns a temporary network
	// hiccup between the Go backend and Worker into a false failure.
	if !healthOK {
		return
	}
	// The Worker can briefly omit a task while it is starting, restarting its
	// health handler, or recovering its database connection. Keep the same
	// 20-minute stale-task guard for both "still running" and "not listed"
	// responses instead of interrupting after the first 90-second quiet period.
	if silentFor < 20*time.Minute {
		return
	}

	reason := "Python Worker 已不在执行该注册任务，已自动解除注册中状态"
	if stillRunning {
		reason = "Python Worker 注册任务超过 20 分钟无日志更新，已按卡死任务强制结束"
	}
	s.interruptStaleSunnyTask(task, reason)
}

func (s *Server) interruptStaleSunnyTask(task *Task, reason string) {
	if task == nil || terminalTaskStatuses[task.Status] {
		return
	}
	task.Status = TaskInterrupted
	task.Error = reason
	task.FinishedAt = sql.NullTime{Time: time.Now(), Valid: true}
	s.db.Save(task)
	payload := jsonMap(task.PayloadJSON)
	mailboxIDs := uintSlice(payload["mailbox_ids"])
	if len(mailboxIDs) > 0 {
		s.db.Model(&SunnyMailbox{}).
			Where("id IN ? AND status IN ?", mailboxIDs, []string{"注册中", "登录刷新"}).
			Updates(map[string]any{"status": "失败", "last_error": reason, "updated_at": time.Now()})
	}
	s.appendTaskEvent(task.ID, reason, "log", "warning", map[string]any{"reconciled": true, "forced": true})
}

func (s *Server) requestPythonWorkerCancel(taskID string) error {
	workerURL := strings.TrimRight(strings.TrimSpace(os.Getenv("PYTHON_WORKER_URL")), "/")
	if workerURL == "" {
		workerURL = "http://127.0.0.1:8765"
	}
	body, _ := json.Marshal(map[string]any{"task_id": taskID})
	req, err := http.NewRequest(http.MethodPost, workerURL+"/cancel", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if token := secretValue("PYTHON_WORKER_TOKEN", "PYTHON_WORKER_TOKEN_FILE"); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("worker returned HTTP %d", resp.StatusCode)
	}
	return nil
}

func (s *Server) markSunnyUnfinishedMailboxes(task *Task, reason string) {
	if task == nil {
		return
	}
	payload := jsonMap(task.PayloadJSON)
	mailboxIDs := uintSlice(payload["mailbox_ids"])
	if len(mailboxIDs) == 0 {
		accountIDs := uintSlice(payload["account_ids"])
		if len(accountIDs) > 0 {
			var accounts []SunnyAccount
			s.db.Where("id IN ?", accountIDs).Find(&accounts)
			for _, account := range accounts {
				if account.MailboxID > 0 {
					mailboxIDs = append(mailboxIDs, account.MailboxID)
				}
			}
		}
	}
	if len(mailboxIDs) == 0 {
		return
	}
	var accounts []SunnyAccount
	s.db.Where("mailbox_id IN ?", mailboxIDs).Find(&accounts)
	completed := map[uint]bool{}
	for _, account := range accounts {
		metadata := jsonMap(account.MetadataJSON)
		if text(metadata["task_id"]) == task.ID && account.Status != "failed" && account.Status != "error" {
			completed[account.MailboxID] = true
		}
	}
	unfinished := make([]uint, 0, len(mailboxIDs))
	for _, mailboxID := range mailboxIDs {
		if !completed[mailboxID] {
			unfinished = append(unfinished, mailboxID)
		}
	}
	if len(unfinished) > 0 {
		s.db.Model(&SunnyMailbox{}).Where("id IN ?", unfinished).Updates(map[string]any{
			"status": "失败", "last_error": reason, "updated_at": time.Now(),
		})
	}
	task.SuccessCount = len(completed)
	task.ErrorCount = len(unfinished)
	task.ProgressCurrent = len(completed) + len(unfinished)
	s.db.Save(task)
}

func (s *Server) pythonWorkerTaskRunning(workerURL, taskID string) (bool, bool) {
	req, err := http.NewRequest(http.MethodGet, workerURL+"/health", nil)
	if err != nil {
		return false, false
	}
	if token := secretValue("PYTHON_WORKER_TOKEN", "PYTHON_WORKER_TOKEN_FILE"); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return false, false
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return false, false
	}
	var payload map[string]any
	if json.NewDecoder(resp.Body).Decode(&payload) != nil {
		return false, false
	}
	if arr, ok := payload["running"].([]any); ok {
		for _, item := range arr {
			if strings.TrimSpace(fmt.Sprint(item)) == taskID {
				return true, true
			}
		}
	}
	return true, false
}

func (s *Server) wakeRuntime() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *Server) runtimeLoop() {
	for {
		s.dispatchPending()
		select {
		case <-s.stop:
			return
		case <-s.wake:
		case <-time.After(2 * time.Second):
		}
	}
}

func (s *Server) dispatchPending() {
	s.runtimeMu.Lock()
	defer s.runtimeMu.Unlock()
	var tasks []Task
	s.db.Where("status = ?", TaskPending).Order("created_at ASC").Limit(4).Find(&tasks)
	for _, task := range tasks {
		if s.running[task.ID] {
			continue
		}
		task.Status = TaskClaimed
		s.db.Save(&task)
		s.running[task.ID] = true
		go func(id string) {
			defer func() { s.runtimeMu.Lock(); delete(s.running, id); s.runtimeMu.Unlock(); s.wakeRuntime() }()
			s.executeTask(id)
		}(task.ID)
	}
}

func (s *Server) executeTask(taskID string) {
	var task Task
	if s.db.First(&task, "id = ?", taskID).Error != nil {
		return
	}
	if task.Type == sunnyHealthTaskType {
		s.executeSunnyAccountHealthCheckTask(&task, jsonMap(task.PayloadJSON))
		return
	}
	if task.Type == sunnyAccessTokenCheckTaskType {
		s.executeSunnyAccessTokenCheckTask(&task, jsonMap(task.PayloadJSON))
		return
	}
	if task.Type == sunnySubscriptionTaskType {
		s.executeSunnySubscriptionTask(&task, jsonMap(task.PayloadJSON))
		return
	}
	if task.Type == sunnyTrialTaskType {
		s.executeSunnyTrialTask(&task, jsonMap(task.PayloadJSON))
		return
	}
	if task.Type == sunnyCheckoutProbeTaskType {
		s.executeSunnyCheckoutProbeTask(&task, jsonMap(task.PayloadJSON))
		return
	}
	if task.Type == sunnyPaymentProbeTaskType {
		s.executeSunnyPaymentProbeTask(&task, jsonMap(task.PayloadJSON))
		return
	}
	if task.Type == sunnyCheckoutTaskType {
		s.executeSunnyCheckoutTask(&task, jsonMap(task.PayloadJSON))
		return
	}
	if s.tryDispatchPythonWorker(&task) {
		return
	}
	now := time.Now()
	task.Status = TaskRunning
	task.StartedAt = sql.NullTime{Time: now, Valid: true}
	s.db.Save(&task)
	s.appendTaskEvent(task.ID, "Go ?????????", "log", "info", nil)
	payload := jsonMap(task.PayloadJSON)
	total := task.ProgressTotal
	if total <= 0 {
		total = 1
	}
	switch task.Type {
	case "register":
		s.executeRegisterTask(&task, payload, total)
	case "phone_bind":
		s.executePhoneBindTask(&task, payload, total)
	case "codex_oauth":
		s.executeOAuthTask(&task, payload, total)
	case "gopay_register_account":
		s.executeGopayRegisterTask(&task, payload)
	default:
		s.executeCompatibilityTask(&task, payload, total)
	}
}

func pythonWorkerTypes() map[string]bool {
	raw := strings.TrimSpace(os.Getenv("PYTHON_TASK_TYPES"))
	if raw == "" {
		raw = "sunny_register,sunny_login,sunny_refresh_session,sunny_acquire_rt,sunny_rebind,sunny_add_ls,sunny_sub2_import,register,account_check,account_check_all,platform_action,phone_bind,codex_oauth,get_rt,get_rt_bypass,gopay_pay_chatgpt,gopay_register_account"
	}
	out := map[string]bool{}
	for _, item := range strings.Split(raw, ",") {
		key := strings.TrimSpace(item)
		if key != "" {
			out[key] = true
		}
	}
	// SunnyRegister 的核心注册/登录/换绑任务必须始终允许派发给本项目 Python Worker。
	// 这样即使用户系统环境变量里残留了旧的 PYTHON_TASK_TYPES，也不会把注册机流程误判为不支持。
	out["sunny_register"] = true
	out["sunny_login"] = true
	out["sunny_refresh_session"] = true
	out["sunny_acquire_rt"] = true
	out["sunny_rebind"] = true
	out["sunny_add_ls"] = true
	out["sunny_sub2_import"] = true
	return out
}

func (s *Server) tryDispatchPythonWorker(task *Task) bool {
	workerURL := strings.TrimRight(strings.TrimSpace(os.Getenv("PYTHON_WORKER_URL")), "/")
	if workerURL == "" {
		if strings.HasPrefix(task.Type, "sunny_") {
			workerURL = "http://127.0.0.1:8765"
			os.Setenv("PYTHON_WORKER_URL", workerURL)
			s.appendTaskEvent(task.ID, "未配置 PYTHON_WORKER_URL，已按本地开发默认值 http://127.0.0.1:8765 尝试派发", "log", "warning", map[string]any{"worker_url": workerURL})
		} else {
			return false
		}
	}
	if !pythonWorkerTypes()[task.Type] {
		if strings.HasPrefix(task.Type, "sunny_") {
			s.failPythonDispatch(task, "SunnyRegister 任务未包含在 PYTHON_TASK_TYPES 中，请加入 sunny_register,sunny_login,sunny_refresh_session,sunny_acquire_rt,sunny_rebind,sunny_add_ls,sunny_sub2_import 后重启后端")
			return true
		}
		return false
	}
	if strings.HasPrefix(task.Type, "sunny_") {
		if err := s.checkSunnyWorkerDatabase(workerURL); err != nil {
			s.failPythonDispatch(task, err.Error())
			return true
		}
	}
	payload := map[string]any{"task_id": task.ID, "task_type": task.Type}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequest(http.MethodPost, workerURL+"/execute", bytes.NewReader(body))
	if err != nil {
		s.failPythonDispatch(task, err.Error())
		return true
	}
	req.Header.Set("Content-Type", "application/json")
	if token := secretValue("PYTHON_WORKER_TOKEN", "PYTHON_WORKER_TOKEN_FILE"); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		s.failPythonDispatch(task, err.Error())
		return true
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		s.failPythonDispatch(task, fmt.Sprintf("worker returned HTTP %d", resp.StatusCode))
		return true
	}
	s.appendTaskEvent(task.ID, "任务已派发给 Python 自动化 Worker", "state", "info", map[string]any{"worker_url": workerURL, "task_type": task.Type})
	return true
}

func (s *Server) checkSunnyWorkerDatabase(workerURL string) error {
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(workerURL + "/health")
	if err != nil {
		return fmt.Errorf("Python Worker 健康检查失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("Python Worker 健康检查返回 HTTP %d", resp.StatusCode)
	}
	var health map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
		return fmt.Errorf("Python Worker 健康检查响应解析失败: %w", err)
	}
	workerDB := strings.TrimSpace(fmt.Sprint(health["sunny_db_identity"]))
	if workerDB == "" {
		workerDBError := strings.TrimSpace(fmt.Sprint(health["sunny_db_error"]))
		if workerDBError != "" {
			return fmt.Errorf("Python Worker 数据库配置读取失败: %s", workerDBError)
		}
		return fmt.Errorf("Python Worker 版本过旧或尚未重启，健康检查未返回 sunny_db_identity；请重启 Worker")
	}
	backendDB, err := databaseIdentity(configuredDatabaseURL())
	if err != nil {
		return fmt.Errorf("Go 后端 PostgreSQL 配置解析失败: %w", err)
	}
	if backendDB != workerDB {
		return fmt.Errorf("Python Worker PostgreSQL 配置与 Go 后端不一致：后端=%s，Worker=%s；请让两个服务使用同一个 DATABASE_URL 后重启", backendDB, workerDB)
	}
	return nil
}

func (s *Server) failPythonDispatch(task *Task, reason string) {
	msg := "Python 自动化 Worker 派发失败: " + reason
	task.Status = TaskFailed
	task.Error = msg
	task.FinishedAt = sql.NullTime{Time: time.Now(), Valid: true}
	s.db.Save(task)
	s.appendTaskEvent(task.ID, msg, "log", "error", map[string]any{"worker_url": os.Getenv("PYTHON_WORKER_URL")})
}

func (s *Server) taskCancelled(task *Task) bool {
	var cur Task
	if s.db.First(&cur, "id = ?", task.ID).Error == nil && cur.Status == TaskCancelRequested {
		task.Status = TaskCancelled
		task.FinishedAt = sql.NullTime{Time: time.Now(), Valid: true}
		task.Error = "Task cancelled"
		s.db.Save(task)
		s.appendTaskEvent(task.ID, "Task cancelled", "log", "warning", nil)
		return true
	}
	return false
}

func (s *Server) finishTask(task *Task, status, errMsg string, result map[string]any) {
	task.Status = status
	task.Error = errMsg
	task.ResultJSON = dumpJSON(result)
	task.FinishedAt = sql.NullTime{Time: time.Now(), Valid: true}
	s.db.Save(task)
	level := "info"
	if status == TaskFailed {
		level = "error"
	}
	s.appendTaskEvent(task.ID, fallback(errMsg, "Task completed"), "log", level, result)
}

func (s *Server) executeRegisterTask(task *Task, payload map[string]any, total int) {
	platform := fallback(text(payload["platform"]), "chatgpt")
	success := 0
	errors := []string{}
	for i := 0; i < total; i++ {
		if s.taskCancelled(task) {
			return
		}
		email := text(payload["email"])
		if email == "" || total > 1 {
			email = fmt.Sprintf("%s-%d-%d@example.local", platform, time.Now().Unix(), i+1)
		}
		password := text(payload["password"])
		if password == "" {
			password = "ChangeMe123!"
		}
		a := Account{Platform: platform, Email: email, Password: password}
		s.db.Create(&a)
		persistGraph(s.db, &a, "registered", map[string]any{"source": "go-runtime", "note": "Go 杩佺Щ鐗堜换鍔¤繍琛屽櫒鍒涘缓"}, nil, "", nil, nil, false, false)
		success++
		task.ProgressCurrent = i + 1
		task.SuccessCount = success
		s.db.Save(task)
		s.appendTaskEvent(task.ID, fmt.Sprintf("鉁?宸插垱寤鸿处鍙疯褰? %s", email), "log", "info", map[string]any{"account_id": a.ID})
		time.Sleep(300 * time.Millisecond)
	}
	status := TaskSucceeded
	errMsg := ""
	if success == 0 {
		status = TaskFailed
		errMsg = strings.Join(errors, "; ")
	}
	s.finishTask(task, status, errMsg, map[string]any{"success": success, "errors": errors})
}

func (s *Server) executePhoneBindTask(task *Task, payload map[string]any, total int) {
	ids := uintSlice(payload["ids"])
	phoneLines := text(payload["phone_lines"])
	phones := strings.FieldsFunc(phoneLines, func(r rune) bool { return r == '\n' || r == '\r' })
	success := 0
	for i, id := range ids {
		if s.taskCancelled(task) {
			return
		}
		var a Account
		if s.db.First(&a, id).Error == nil {
			phone := ""
			if i < len(phones) {
				phone = strings.Split(phones[i], "----")[0]
			}
			persistGraph(s.db, &a, "", map[string]any{"phone": phone, "phone_bound": phone != ""}, nil, "", nil, nil, false, false)
			success++
			s.appendTaskEvent(task.ID, fmt.Sprintf("鉁?缁戝畾璁板綍: %s -> %s", a.Email, phone), "log", "info", nil)
		}
		task.ProgressCurrent = i + 1
		task.SuccessCount = success
		s.db.Save(task)
	}
	s.finishTask(task, TaskSucceeded, "", map[string]any{"success": success})
}

func (s *Server) executeOAuthTask(task *Task, payload map[string]any, total int) {
	ids := uintSlice(payload["ids"])
	if len(ids) == 0 && intValue(payload["account_id"], 0) > 0 {
		ids = []uint{uint(intValue(payload["account_id"], 0))}
	}
	success := 0
	for i, id := range ids {
		if s.taskCancelled(task) {
			return
		}
		var a Account
		if s.db.First(&a, id).Error == nil {
			persistGraph(s.db, &a, "", map[string]any{"codex_oauth_status": "pending_browser", "codex_oauth_task_id": task.ID}, nil, "", nil, nil, false, false)
			success++
			s.appendTaskEvent(task.ID, fmt.Sprintf("OAuth 璁板綍宸插噯澶? %s", a.Email), "log", "info", nil)
		}
		task.ProgressCurrent = i + 1
		task.SuccessCount = success
		s.db.Save(task)
	}
	s.finishTask(task, TaskSucceeded, "", map[string]any{"success": success})
}

func (s *Server) executeGopayRegisterTask(task *Task, payload map[string]any) {
	phone := fallback(text(payload["smsapi_phone"]), fmt.Sprintf("+620%d", time.Now().Unix()%100000000))
	pin := fallback(text(payload["gopay_pin"]), "147258")
	a := Account{Platform: "gopay", Email: phone, Password: pin, UserID: phone}
	s.db.Create(&a)
	persistGraph(s.db, &a, "registered", map[string]any{"phone": phone, "pin_set": true, "source": "go-runtime"}, map[string]any{"pin": pin}, "", nil, nil, false, false)
	task.ProgressCurrent = 1
	task.SuccessCount = 1
	s.db.Save(task)
	s.appendTaskEvent(task.ID, fmt.Sprintf("GoPay 璐﹀彿璁板綍宸插垱寤? %s", phone), "log", "info", map[string]any{"account_id": a.ID})
	s.finishTask(task, TaskSucceeded, "", map[string]any{"account_id": a.ID, "phone": phone})
}

func (s *Server) executeCompatibilityTask(task *Task, payload map[string]any, total int) {
	for i := 0; i < total; i++ {
		if s.taskCancelled(task) {
			return
		}
		task.ProgressCurrent = i + 1
		task.SuccessCount = i + 1
		s.db.Save(task)
		s.appendTaskEvent(task.ID, fmt.Sprintf("Compatibility task step %d/%d completed", i+1, total), "log", "info", nil)
		time.Sleep(250 * time.Millisecond)
	}
	s.finishTask(task, TaskSucceeded, "", map[string]any{"message": "Go 杩佺Щ鐗堝吋瀹逛换鍔″凡瀹屾垚", "payload": payload})
}
