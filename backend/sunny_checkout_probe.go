package main

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

const sunnyCheckoutProbeTaskType = "sunny_account_checkout_probe"

var sunnyCheckCheckoutProbe = checkSunnyCheckoutProbe

type sunnyCheckoutProbeCandidate struct {
	SessionID   uint
	AccountID   uint
	Email       string
	AccessToken string
	SkipReason  string
	Error       string
}

type sunnyCheckoutProbeOutcome struct {
	Candidate    sunnyCheckoutProbeCandidate
	CheckoutKind string
	InvalidToken bool
	Retried      bool
	Error        string
	TrafficBytes int64
}

func checkSunnyCheckoutProbe(ctx context.Context, accessToken string) sunnyCommerceProbeResult {
	result := sunnyCommerceProbeResult{Eligibility: sunnyTrialUnknown, CheckoutKind: sunnyCheckoutUnknown, PaymentMethods: []string{}}
	token := strings.TrimSpace(accessToken)
	if token == "" {
		result.CheckoutError = "账户缺少 Access Token"
		return result
	}
	proxyURL, _ := ctx.Value(sunnyCheckoutProxyContextKey{}).(string)
	country, currency := sunnyCheckoutBilling()
	probed := sunnyProbePaymentMethods(ctx, token, country, currency, proxyURL)
	sunnyTrafficMeterFromContext(ctx).addExternal(probed.TrafficBytes)
	result.CheckoutKind = normalizeSunnyCheckoutKind(probed.Kind)
	result.InvalidToken = probed.InvalidToken
	if probed.Error != "" {
		result.CheckoutError = probed.Error
	} else if result.CheckoutKind == sunnyCheckoutUnknown {
		result.CheckoutError = "Checkout 响应未包含可识别的会话类型"
	}
	return result
}

func checkSunnyCheckoutProbeWithRetry(ctx context.Context, accessToken string) (sunnyCommerceProbeResult, bool) {
	initial := sunnyCheckCheckoutProbe(ctx, accessToken)
	if initial.InvalidToken || normalizeSunnyCheckoutKind(initial.CheckoutKind) != sunnyCheckoutUnknown {
		return initial, false
	}
	retried := sunnyCheckCheckoutProbe(ctx, accessToken)
	if normalizeSunnyCheckoutKind(retried.CheckoutKind) == sunnyCheckoutUnknown && strings.TrimSpace(retried.CheckoutError) == "" {
		retried.CheckoutError = initial.CheckoutError
	}
	retried.InvalidToken = initial.InvalidToken || retried.InvalidToken
	return retried, true
}

func (s *Server) sunnyCheckoutProbeConcurrency() int {
	return s.sunnyConfiguredConcurrency("checkout_probe_concurrency", "SUNNY_CHECKOUT_PROBE_CONCURRENCY", 16)
}

func (s *Server) sunnyCheckoutProbeCandidates(ids []uint) ([]sunnyCheckoutProbeCandidate, error) {
	if len(ids) == 0 {
		return nil, fmt.Errorf("请选择需要探测 Checkout 类型的账户")
	}
	var sessions []SunnySession
	if err := s.db.Where("id IN ?", ids).Order("id asc").Find(&sessions).Error; err != nil {
		return nil, err
	}
	accounts, mailboxes := s.sunnySessionSidecars(sessions)
	candidates := make([]sunnyCheckoutProbeCandidate, 0, len(sessions))
	for _, session := range sessions {
		account := accounts[sunnyEmailKey(session.Email)]
		item := s.serializeSunnySession(session, accounts, mailboxes)
		candidate := sunnyCheckoutProbeCandidate{
			SessionID: session.ID, AccountID: firstUint(session.AccountID, account.ID), Email: session.Email,
			AccessToken: sunnyPreferredAccessToken(session.AccessToken, sunnyAccessTokenFromSessionJSON(session.SessionJSON), account.AccessToken),
		}
		if !sunnyTrialApplies(text(item["status"]), text(item["plan_type"])) {
			candidate.SkipReason = "仅已注册且套餐为 free 的账户支持 Checkout 探测"
		} else if strings.TrimSpace(candidate.AccessToken) == "" {
			candidate.Error = "账户缺少 Access Token"
		}
		candidates = append(candidates, candidate)
	}
	return candidates, nil
}

func (s *Server) activeSunnyCheckoutProbeSessionIDs() (map[uint]bool, error) {
	var tasks []Task
	if err := s.db.Where("type = ? AND status NOT IN ?", sunnyCheckoutProbeTaskType, []string{TaskSucceeded, TaskFailed, TaskInterrupted, TaskCancelled}).Find(&tasks).Error; err != nil {
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

func (s *Server) createSunnyCheckoutProbeTask(body map[string]any) (Task, error) {
	s.trialCheckMu.Lock()
	defer s.trialCheckMu.Unlock()
	ids := uintSlice(body["session_ids"])
	candidates, err := s.sunnyCheckoutProbeCandidates(ids)
	if err != nil {
		return Task{}, err
	}
	if len(candidates) == 0 {
		return Task{}, fmt.Errorf("未找到需要探测 Checkout 类型的账户")
	}
	active, err := s.activeSunnyCheckoutProbeSessionIDs()
	if err != nil {
		return Task{}, err
	}
	skipped := make([]uint, 0)
	for _, candidate := range candidates {
		if active[candidate.SessionID] {
			skipped = append(skipped, candidate.SessionID)
		}
	}
	payload := map[string]any{"session_ids": ids, "skip_session_ids": skipped}
	return s.createTask(sunnyCheckoutProbeTaskType, "sunny", payload, len(candidates)), nil
}

func (s *Server) executeSunnyCheckoutProbeTask(task *Task, payload map[string]any) {
	task.Status = TaskRunning
	task.StartedAt = sql.NullTime{Time: time.Now(), Valid: true}
	s.db.Save(task)
	ctx, cancel := s.taskCancellationContext(task)
	defer cancel()
	candidates, err := s.sunnyCheckoutProbeCandidates(uintSlice(payload["session_ids"]))
	if err != nil {
		s.failSunnyCheckoutProbeTask(task, err.Error())
		return
	}
	skipped := map[uint]bool{}
	for _, id := range uintSlice(payload["skip_session_ids"]) {
		skipped[id] = true
	}
	for index := range candidates {
		if skipped[candidates[index].SessionID] {
			candidates[index].SkipReason = "已有 Checkout 探测任务正在执行，已跳过"
		}
	}
	result := map[string]any{"requested": len(candidates), "detected": 0, "retried": 0, "skipped": 0, "failed": 0, "items": []any{}}
	items := make([]any, 0, len(candidates))
	outcomes := streamSunnyWorkerPoolContext(ctx, candidates, s.sunnyCheckoutProbeConcurrency(), func(candidate sunnyCheckoutProbeCandidate) sunnyCheckoutProbeOutcome {
		outcome := sunnyCheckoutProbeOutcome{Candidate: candidate}
		if candidate.SkipReason != "" || candidate.Error != "" {
			return outcome
		}
		meter := &sunnyTrafficMeter{}
		probeCtx := withSunnyTrafficMeter(ctx, meter)
		probeCtx = context.WithValue(probeCtx, sunnyCheckoutProxyContextKey{}, s.sunnyCommerceProxyURL(candidate.Email))
		probed, retried := checkSunnyCheckoutProbeWithRetry(probeCtx, candidate.AccessToken)
		outcome.CheckoutKind = normalizeSunnyCheckoutKind(probed.CheckoutKind)
		outcome.InvalidToken = probed.InvalidToken
		outcome.Retried = retried
		outcome.Error = probed.CheckoutError
		outcome.TrafficBytes = meter.totalBytes()
		return outcome
	})
	for outcome := range outcomes {
		if ctx.Err() != nil {
			break
		}
		now := time.Now()
		candidate := outcome.Candidate
		item := map[string]any{"session_id": candidate.SessionID, "email": candidate.Email, "checkout_kind": outcome.CheckoutKind, "proxy_traffic_bytes": outcome.TrafficBytes}
		s.recordSunnyProxyTraffic(candidate.Email, outcome.TrafficBytes)
		if outcome.Retried {
			result["retried"] = result["retried"].(int) + 1
			item["retried"] = true
		}
		switch {
		case candidate.SkipReason != "":
			result["skipped"] = result["skipped"].(int) + 1
			item["status"], item["message"] = "skipped", candidate.SkipReason
		case candidate.Error != "":
			result["failed"] = result["failed"].(int) + 1
			item["status"], item["error"] = "failed", candidate.Error
			if persistErr := s.persistSunnyCheckoutProbe(candidate, sunnyCheckoutUnknown, candidate.Error, now); persistErr != nil {
				item["error"] = persistErr.Error()
			}
		case outcome.Error != "" || outcome.CheckoutKind == sunnyCheckoutUnknown:
			message := fallback(outcome.Error, "无法识别 Checkout 类型")
			result["failed"] = result["failed"].(int) + 1
			item["status"], item["error"] = "failed", message
			if persistErr := s.persistSunnyCheckoutProbe(candidate, sunnyCheckoutUnknown, message, now); persistErr != nil {
				item["error"] = persistErr.Error()
			}
			s.appendAccountTaskEvent(task.ID, candidate.Email, "checkout", "checkout.probe_failed", fmt.Sprintf("账户 %s Checkout 探测失败：%s", candidate.Email, message), "warning", map[string]any{"error": message})
		default:
			if persistErr := s.persistSunnyCheckoutProbe(candidate, outcome.CheckoutKind, "", now); persistErr != nil {
				result["failed"] = result["failed"].(int) + 1
				item["status"], item["error"] = "failed", persistErr.Error()
			} else {
				result["detected"] = result["detected"].(int) + 1
				item["status"] = "detected"
				s.appendAccountTaskEvent(task.ID, candidate.Email, "checkout", "checkout.probed", fmt.Sprintf("账户 %s Checkout 类型探测完成：%s", candidate.Email, outcome.CheckoutKind), "info", map[string]any{"checkout_kind": outcome.CheckoutKind})
			}
		}
		if outcome.InvalidToken {
			message := fallback(outcome.Error, "Access Token 无效或已过期")
			s.db.Model(&SunnySession{}).Where("id = ?", candidate.SessionID).Updates(map[string]any{"access_token_status": "invalid", "access_token_error": message, "access_token_checked_at": now})
		}
		items = append(items, item)
		task.ProgressCurrent++
		s.persistTaskProgress(task, intValue(result["detected"], 0), intValue(result["failed"], 0), now)
	}
	result["items"] = items
	if s.finishCancelledTask(task, result, "用户已停止 Checkout 探测任务") {
		return
	}
	task.Status = TaskSucceeded
	task.SuccessCount = intValue(result["detected"], 0)
	task.ErrorCount = intValue(result["failed"], 0)
	task.ResultJSON = dumpJSON(result)
	task.FinishedAt = sql.NullTime{Time: time.Now(), Valid: true}
	s.db.Save(task)
	s.appendTaskEvent(task.ID, "账户 Checkout 类型探测任务完成", "log", "info", result)
}

func (s *Server) persistSunnyCheckoutProbe(candidate sunnyCheckoutProbeCandidate, checkoutKind, message string, checkedAt time.Time) error {
	query := s.db.Model(&SunnyAccount{})
	if candidate.AccountID != 0 {
		query = query.Where("id = ?", candidate.AccountID)
	} else {
		query = query.Where("lower(trim(email)) = lower(trim(?))", candidate.Email)
	}
	result := query.Updates(map[string]any{"checkout_kind": checkoutKind, "commerce_check_error": message, "commerce_checked_at": checkedAt})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("账户 %s 不存在，Checkout 类型未保存", candidate.Email)
	}
	return nil
}

func (s *Server) failSunnyCheckoutProbeTask(task *Task, message string) {
	task.Status = TaskFailed
	task.Error = message
	task.ErrorCount = task.ProgressTotal
	task.ResultJSON = dumpJSON(map[string]any{"requested": task.ProgressTotal, "detected": 0, "skipped": 0, "failed": task.ProgressTotal})
	task.FinishedAt = sql.NullTime{Time: time.Now(), Valid: true}
	s.db.Save(task)
	s.appendTaskEvent(task.ID, message, "log", "error", nil)
}
