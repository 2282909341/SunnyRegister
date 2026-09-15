package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"
)

// 提链只负责把账号送到 Stripe/MoMo 的支付页；真正的扣款与订阅生效发生在用户
// 浏览器里，服务端拿不到任何回调。因此 Plus 到账只能靠在观察窗口内轮询判定：
// 先看 Access Token 的 chatgpt_plan_type，再回退到 OpenAI 的订阅成功邮件。
// 窗口内的判定失败不算失败，只有超过 24 小时仍未确认才收敛为 expired。
const (
	sunnyPlusWatchStatusPending = "pending"
	sunnyPlusWatchStatusActive  = "active"
	sunnyPlusWatchStatusExpired = "expired"

	sunnyPlusWatchDeadline = 24 * time.Hour
	sunnyPlusWatchBatch    = 8
	sunnyPlusWatchTimeout  = 3 * time.Minute
)

// 退避节奏：+2min → +5min → +15min → +30min → +1h → +3h → +6h，共 7 次判定。
// 0 元优惠的订阅通常在支付完成后 1 分钟内生效，前两次频繁判定即可覆盖，
// 之后的间隔用来兜住异步入账，避免拿代理配额做无意义的密集轮询。
var sunnyPlusWatchIntervals = []time.Duration{
	2 * time.Minute, 5 * time.Minute, 15 * time.Minute,
	30 * time.Minute, time.Hour, 3 * time.Hour, 6 * time.Hour,
}

// 单独建表而不是塞进 sunny_accounts.metadata_json：该字段会被后续任务整体覆写
// （2026-09-11 的复查任务就覆盖过 186 个账号的 task_id），不适合承载观察状态。
type SunnyPlusWatch struct {
	ID             uint       `gorm:"primaryKey" json:"id"`
	AccountID      uint       `gorm:"index" json:"account_id"`
	SessionID      uint       `json:"session_id"`
	Email          string     `gorm:"index;size:255" json:"email"`
	CheckoutTaskID string     `gorm:"size:64" json:"checkout_task_id"`
	Plan           string     `gorm:"size:32;default:plus" json:"plan"`
	LinkType       string     `gorm:"size:32" json:"link_type"`
	Country        string     `gorm:"size:8" json:"country"`
	Currency       string     `gorm:"size:8" json:"currency"`
	Amount         int64      `json:"amount"`
	PromoApplied   bool       `json:"promo_applied"`
	Status         string     `gorm:"index;size:16;default:pending" json:"status"`
	Attempts       int        `json:"attempts"`
	LastError      string     `gorm:"type:text" json:"last_error"`
	NextCheckAt    *time.Time `gorm:"index" json:"next_check_at"`
	DeadlineAt     *time.Time `json:"deadline_at"`
	ConfirmedAt    *time.Time `json:"confirmed_at"`
	LastCheckedAt  *time.Time `json:"last_checked_at"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

func (SunnyPlusWatch) TableName() string { return "sunny_plus_watch" }

// 判定入口都留成可替换变量，测试可以注入固定结论而不触碰网络。
var (
	sunnyPlusWatchProbeAT = func(ctx context.Context, s *Server, candidate sunnySubscriptionCandidate, proxyURL string) sunnySubscriptionATResult {
		return s.sunnySubscriptionProbeATContext(ctx, candidate, proxyURL)
	}
	sunnyPlusWatchDetectMail = func(s *Server, candidate sunnySubscriptionCandidate, proxyURL string) (bool, string, error) {
		return s.detectSunnySubscriptionMail(candidate, proxyURL)
	}
	sunnyPlusWatchAudit = func(s *Server, item AuditLog) { s.recordAudit(item) }
)

func sunnyPlusWatchNextCheck(now time.Time, attempts int) (time.Time, bool) {
	if attempts < 0 || attempts >= len(sunnyPlusWatchIntervals) {
		return time.Time{}, false
	}
	return now.Add(sunnyPlusWatchIntervals[attempts]), true
}

func (s *Server) sunnyPlusWatchEnabled() bool {
	if raw := strings.TrimSpace(os.Getenv("SUNNY_PLUS_WATCH_ENABLED")); raw != "" {
		return boolValue(raw, true)
	}
	return boolValue(s.sunnyMaintenanceSnapshot()["plus_watch_enabled"], true)
}

// enqueueSunnyPlusWatch 在提链成功、且本次建单目标就是 Plus 时登记一次观察。
// 同一个账号重复提链会重启窗口：新链接才是当前有效的那一条。
func (s *Server) enqueueSunnyPlusWatch(taskID string, payload, item map[string]any, email string, accountID uint) {
	email = strings.TrimSpace(email)
	if email == "" || normalizeSunnyPlanType(text(payload["plan"])) != "plus" {
		return
	}
	now := time.Now()
	next, ok := sunnyPlusWatchNextCheck(now, 0)
	if !ok {
		return
	}
	deadline := now.Add(sunnyPlusWatchDeadline)
	watch := SunnyPlusWatch{
		AccountID: accountID, SessionID: accountID, Email: email, CheckoutTaskID: taskID,
		Plan: "plus", LinkType: text(item["link_type"]), Country: text(item["country"]), Currency: text(item["currency"]),
		Amount: int64(intValue(item["checkout_amount"], 0)), PromoApplied: boolValue(payload["use_promo"], false),
		Status: sunnyPlusWatchStatusPending, Attempts: 0,
		NextCheckAt: &next, DeadlineAt: &deadline, CreatedAt: now, UpdatedAt: now,
	}
	if err := s.upsertSunnyPlusWatch(watch); err != nil {
		log.Printf("plus watch enqueue failed for %s: %v", email, err)
	}
}

func (s *Server) upsertSunnyPlusWatch(watch SunnyPlusWatch) error {
	var existing SunnyPlusWatch
	if err := s.db.Where("email = ? AND status = ?", watch.Email, sunnyPlusWatchStatusPending).
		Order("id desc").First(&existing).Error; err == nil {
		return s.db.Model(&SunnyPlusWatch{}).Where("id = ?", existing.ID).Updates(map[string]any{
			"account_id": watch.AccountID, "checkout_task_id": watch.CheckoutTaskID,
			"link_type": watch.LinkType, "country": watch.Country, "currency": watch.Currency,
			"amount": watch.Amount, "promo_applied": watch.PromoApplied, "plan": watch.Plan,
			"attempts": 0, "last_error": "", "next_check_at": watch.NextCheckAt,
			"deadline_at": watch.DeadlineAt, "updated_at": watch.UpdatedAt,
		}).Error
	}
	return s.db.Create(&watch).Error
}

func (s *Server) sunnyMaybeRunPlusWatches() {
	if !s.sunnyPlusWatchEnabled() {
		return
	}
	now := time.Now()
	var watches []SunnyPlusWatch
	if err := s.db.Where("status = ? AND next_check_at IS NOT NULL AND next_check_at <= ?", sunnyPlusWatchStatusPending, now).
		Order("next_check_at asc").Limit(sunnyPlusWatchBatch).Find(&watches).Error; err != nil {
		return
	}
	for index := range watches {
		s.sunnyRunPlusWatch(&watches[index])
	}
}

func (s *Server) sunnyRunPlusWatch(watch *SunnyPlusWatch) {
	now := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), sunnyPlusWatchTimeout)
	defer cancel()
	confirmed, detail, err := s.sunnyCheckPlusArrival(ctx, *watch)
	attempts := watch.Attempts + 1
	updates := map[string]any{"attempts": attempts, "last_checked_at": now, "updated_at": now}
	if err != nil {
		updates["last_error"] = err.Error()
	} else {
		updates["last_error"] = ""
	}
	switch {
	case confirmed:
		updates["status"] = sunnyPlusWatchStatusActive
		updates["confirmed_at"] = now
		updates["next_check_at"] = nil
		sunnyPlusWatchAudit(s, AuditLog{
			LogType: "scheduler", Category: "account", Action: "plus_watch_confirmed", Status: "success",
			Summary: fmt.Sprintf("账户 %s 的 Plus 已到账：%s", watch.Email, detail), Count: 1,
			DetailsJSON: dumpJSON(map[string]any{"email": watch.Email, "account_id": watch.AccountID, "detail": detail, "attempts": attempts}),
		})
	case watch.DeadlineAt != nil && now.After(*watch.DeadlineAt):
		updates["status"] = sunnyPlusWatchStatusExpired
		updates["next_check_at"] = nil
		sunnyPlusWatchAudit(s, AuditLog{
			LogType: "scheduler", Category: "account", Action: "plus_watch_expired", Status: "warning",
			Summary: fmt.Sprintf("账户 %s 超过 24 小时仍未检测到 Plus 到账，已停止观察：%s", watch.Email, fallback(detail, "无可用证据")), Count: 1,
			DetailsJSON: dumpJSON(map[string]any{"email": watch.Email, "account_id": watch.AccountID, "detail": detail, "attempts": attempts}),
		})
	default:
		if next, ok := sunnyPlusWatchNextCheck(now, attempts); ok {
			updates["next_check_at"] = next
		} else {
			updates["status"] = sunnyPlusWatchStatusExpired
			updates["next_check_at"] = nil
		}
	}
	if err := s.db.Model(&SunnyPlusWatch{}).Where("id = ?", watch.ID).Updates(updates).Error; err != nil {
		log.Printf("plus watch update failed for %s: %v", watch.Email, err)
	}
}

// sunnyCheckPlusArrival 只判定「是否已到账」，不做任何可能触发风控的建单动作。
func (s *Server) sunnyCheckPlusArrival(ctx context.Context, watch SunnyPlusWatch) (bool, string, error) {
	candidate, err := s.sunnyPlusWatchCandidate(watch)
	if err != nil {
		return false, "", err
	}
	proxyURL := s.sunnyMailboxProxyURL()
	atResult := sunnyPlusWatchProbeAT(ctx, s, candidate, proxyURL)
	if atResult.Status == "valid" {
		if planType := normalizeSunnyPlanType(atResult.PlanType); planType == "plus" {
			if err := s.updateSunnySubscriptionPlan(candidate, planType); err != nil {
				return false, "", err
			}
			return true, "Access Token 套餐为 plus", nil
		}
	}
	subscribed, subject, mailErr := sunnyPlusWatchDetectMail(s, candidate, proxyURL)
	if subscribed {
		if err := s.updateSunnySubscriptionPlan(candidate, "plus"); err != nil {
			return false, "", err
		}
		return true, fmt.Sprintf("订阅邮件已确认：%s", fallback(strings.TrimSpace(subject), "无主题")), nil
	}
	detail := fmt.Sprintf("Access Token 状态 %s，套餐 %s", fallback(atResult.Status, "unknown"), fallback(normalizeSunnyPlanType(atResult.PlanType), "unknown"))
	if atResult.Error != "" {
		detail += "，" + atResult.Error
	}
	if mailErr != nil {
		detail += "；邮件检测：" + mailErr.Error()
	}
	return false, detail, nil
}

// sunnyPlusWatchCandidate 按账号维度组装订阅判定所需的凭证。提链既可能来自
// 账户库（有 session 行），也可能来自外部 AT（只有邮箱），两条路径都要能取到令牌。
func (s *Server) sunnyPlusWatchCandidate(watch SunnyPlusWatch) (sunnySubscriptionCandidate, error) {
	candidate := sunnySubscriptionCandidate{SessionID: watch.SessionID, AccountID: watch.AccountID, Email: watch.Email}
	var account SunnyAccount
	accountQuery := s.db.Select("id", "mailbox_id", "email", "access_token")
	if watch.AccountID != 0 {
		accountQuery = accountQuery.Where("id = ? OR email = ?", watch.AccountID, watch.Email)
	} else {
		accountQuery = accountQuery.Where("email = ?", watch.Email)
	}
	accountFound := accountQuery.First(&account).Error == nil
	if accountFound {
		candidate.AccountID = account.ID
		candidate.Email = fallback(strings.TrimSpace(account.Email), watch.Email)
	}
	var session SunnySession
	hasSession := false
	if err := s.db.Select("id", "account_id", "email", "access_token", "session_json").
		Where("account_id = ? OR email = ?", candidate.AccountID, candidate.Email).
		Order("id desc").First(&session).Error; err == nil {
		hasSession = true
		candidate.SessionID = session.ID
	}
	accountToken := ""
	if accountFound {
		accountToken = account.AccessToken
	}
	sessionToken := ""
	if hasSession {
		sessionToken = sunnyPreferredAccessToken(session.AccessToken, sunnyAccessTokenFromSessionJSON(session.SessionJSON), "")
	}
	candidate.AccessToken = sunnyPreferredAccessToken(sessionToken, accountToken)
	if candidate.AccessToken == "" && !accountFound && !hasSession {
		return candidate, fmt.Errorf("账户 %s 已不存在", watch.Email)
	}
	var mailbox SunnyMailbox
	mailboxQuery := s.db.Model(&SunnyMailbox{})
	if accountFound && account.MailboxID != 0 {
		mailboxQuery = mailboxQuery.Where("id = ?", account.MailboxID)
	} else {
		mailboxQuery = mailboxQuery.Where("email = ? OR rebind_email = ?", candidate.Email, candidate.Email)
	}
	if err := mailboxQuery.First(&mailbox).Error; err == nil {
		candidate.MailboxID = mailbox.ID
		candidate.MailEmail = mailbox.Email
		candidate.MailboxType = normalizeSunnyMailboxType(mailbox.MailboxType)
		candidate.Channel = normalizeSunnyMailboxChannel(candidate.MailboxType, mailbox.MailboxChannel)
		candidate.AccessKey = mailbox.AccessKey
		candidate.ClientID = mailbox.ClientID
		candidate.RefreshToken = mailbox.RefreshToken
		if strings.TrimSpace(mailbox.RebindEmail) != "" && strings.TrimSpace(mailbox.RebindMailboxAPI) != "" {
			candidate.MailEmail = strings.TrimSpace(mailbox.RebindEmail)
			candidate.MailboxType = "domain"
			candidate.Channel = "domain_api"
			candidate.AccessKey = strings.TrimSpace(mailbox.RebindMailboxAPI)
			candidate.ClientID = ""
			candidate.RefreshToken = ""
		}
	}
	return candidate, nil
}
