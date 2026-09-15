package main

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func newPlusWatchTestServer(t *testing.T) *Server {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:"+filepath.ToSlash(filepath.Join(t.TempDir(), "plus.db"))+"?cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open plus watch database: %v", err)
	}
	if err := db.AutoMigrate(&SunnyPlusWatch{}, &SunnyAccount{}, &SunnySession{}, &SunnyMailbox{}, &AuditLog{}); err != nil {
		t.Fatalf("migrate plus watch database: %v", err)
	}
	if sqlDB, err := db.DB(); err == nil {
		t.Cleanup(func() { _ = sqlDB.Close() })
	}
	return &Server{db: db, adminUser: "admin", sessions: map[string]time.Time{}, loginFailures: map[string]*loginFailure{}, stop: make(chan struct{})}
}

// stubPlusWatchDetection 把 AT 与邮件两条判定通道固定成给定结论，避免测试触网。
func stubPlusWatchDetection(t *testing.T, at sunnySubscriptionATResult, subscribed bool, subject string) {
	t.Helper()
	previousAT, previousMail, previousAudit := sunnyPlusWatchProbeAT, sunnyPlusWatchDetectMail, sunnyPlusWatchAudit
	sunnyPlusWatchProbeAT = func(context.Context, *Server, sunnySubscriptionCandidate, string) sunnySubscriptionATResult {
		return at
	}
	sunnyPlusWatchDetectMail = func(*Server, sunnySubscriptionCandidate, string) (bool, string, error) {
		return subscribed, subject, nil
	}
	sunnyPlusWatchAudit = func(*Server, AuditLog) {}
	t.Cleanup(func() {
		sunnyPlusWatchProbeAT, sunnyPlusWatchDetectMail, sunnyPlusWatchAudit = previousAT, previousMail, previousAudit
	})
}

func seedPlusWatchAccount(t *testing.T, s *Server, email, token string) SunnyAccount {
	t.Helper()
	mailbox := SunnyMailbox{Email: email, MailboxType: "domain", MailboxChannel: "domain_api", AccessKey: "https://mail.example.com/code/abc", Status: "已注册"}
	if err := s.db.Create(&mailbox).Error; err != nil {
		t.Fatalf("create mailbox: %v", err)
	}
	account := SunnyAccount{Email: email, MailboxID: mailbox.ID, AccessToken: token, Status: "registered"}
	if err := s.db.Create(&account).Error; err != nil {
		t.Fatalf("create account: %v", err)
	}
	if err := s.db.Create(&SunnySession{AccountID: account.ID, Email: email, AccessToken: token}).Error; err != nil {
		t.Fatalf("create session: %v", err)
	}
	return account
}

func plusWatchCheckoutPayload(plan string) map[string]any {
	return map[string]any{"plan": plan, "use_promo": true}
}

var plusWatchCheckoutItem = map[string]any{"link_type": "momo", "checkout_amount": 0, "country": "VN", "currency": "VND"}

func TestSunnyPlusWatchBackoffSchedule(t *testing.T) {
	now := time.Now()
	want := []time.Duration{2 * time.Minute, 5 * time.Minute, 15 * time.Minute, 30 * time.Minute, time.Hour, 3 * time.Hour, 6 * time.Hour}
	for index, delay := range want {
		next, ok := sunnyPlusWatchNextCheck(now, index)
		if !ok || !next.Equal(now.Add(delay)) {
			t.Fatalf("attempt %d should be scheduled at +%s, got %s (ok=%v)", index, delay, next, ok)
		}
	}
	if _, ok := sunnyPlusWatchNextCheck(now, len(want)); ok {
		t.Fatal("exhausted schedule must stop watching")
	}
	if _, ok := sunnyPlusWatchNextCheck(now, -1); ok {
		t.Fatal("negative attempt must not be scheduled")
	}
}

func TestSunnyPlusWatchEnqueueOnlyForPlusPlan(t *testing.T) {
	s := newPlusWatchTestServer(t)
	s.enqueueSunnyPlusWatch("task_free", plusWatchCheckoutPayload("free"), plusWatchCheckoutItem, "free@example.com", 1)
	var count int64
	s.db.Model(&SunnyPlusWatch{}).Count(&count)
	if count != 0 {
		t.Fatalf("non-plus checkout must not be watched, got %d rows", count)
	}

	s.enqueueSunnyPlusWatch("task_plus", plusWatchCheckoutPayload("plus"), plusWatchCheckoutItem, "plus@example.com", 2)
	var watch SunnyPlusWatch
	if err := s.db.Where("email = ?", "plus@example.com").First(&watch).Error; err != nil {
		t.Fatalf("load watch: %v", err)
	}
	if watch.Status != sunnyPlusWatchStatusPending || watch.Attempts != 0 {
		t.Fatalf("unexpected initial watch state: %#v", watch)
	}
	if watch.CheckoutTaskID != "task_plus" || watch.LinkType != "momo" || watch.Country != "VN" || watch.Currency != "VND" || watch.Amount != 0 || !watch.PromoApplied {
		t.Fatalf("checkout evidence not recorded: %#v", watch)
	}
	if watch.NextCheckAt == nil || watch.DeadlineAt == nil {
		t.Fatalf("watch window not scheduled: %#v", watch)
	}
	if delta := watch.NextCheckAt.Sub(watch.CreatedAt) - sunnyPlusWatchIntervals[0]; delta > time.Second || delta < -time.Second {
		t.Fatalf("first check should be +%s, got %s", sunnyPlusWatchIntervals[0], delta)
	}
	if delta := watch.DeadlineAt.Sub(watch.CreatedAt) - sunnyPlusWatchDeadline; delta > time.Second || delta < -time.Second {
		t.Fatalf("deadline should be +%s, got %s", sunnyPlusWatchDeadline, delta)
	}
}

func TestSunnyPlusWatchRerunRestartsWindow(t *testing.T) {
	s := newPlusWatchTestServer(t)
	s.enqueueSunnyPlusWatch("task_a", plusWatchCheckoutPayload("plus"), plusWatchCheckoutItem, "again@example.com", 3)
	var first SunnyPlusWatch
	if err := s.db.Where("email = ?", "again@example.com").First(&first).Error; err != nil {
		t.Fatalf("load watch: %v", err)
	}
	if err := s.db.Model(&SunnyPlusWatch{}).Where("id = ?", first.ID).Updates(map[string]any{"attempts": 3, "last_error": "旧的失败"}).Error; err != nil {
		t.Fatalf("seed attempts: %v", err)
	}
	s.enqueueSunnyPlusWatch("task_b", plusWatchCheckoutPayload("plus"), plusWatchCheckoutItem, "again@example.com", 3)
	var rows []SunnyPlusWatch
	if err := s.db.Where("email = ?", "again@example.com").Find(&rows).Error; err != nil {
		t.Fatalf("reload watches: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("re-checkout must restart the existing window, got %d rows", len(rows))
	}
	if rows[0].ID != first.ID || rows[0].Attempts != 0 || rows[0].LastError != "" || rows[0].CheckoutTaskID != "task_b" {
		t.Fatalf("window not restarted: %#v", rows[0])
	}
}

func TestSunnyPlusWatchConfirmsOnAccessTokenPlus(t *testing.T) {
	s := newPlusWatchTestServer(t)
	account := seedPlusWatchAccount(t, s, "arrived@example.com", "at_live")
	stubPlusWatchDetection(t, sunnySubscriptionATResult{Status: "valid", PlanType: "plus"}, false, "")

	s.enqueueSunnyPlusWatch("task_plus", plusWatchCheckoutPayload("plus"), plusWatchCheckoutItem, "arrived@example.com", account.ID)
	var watch SunnyPlusWatch
	if err := s.db.Where("email = ?", "arrived@example.com").First(&watch).Error; err != nil {
		t.Fatalf("load watch: %v", err)
	}
	s.sunnyRunPlusWatch(&watch)

	var updated SunnyPlusWatch
	if err := s.db.First(&updated, watch.ID).Error; err != nil {
		t.Fatalf("reload watch: %v", err)
	}
	if updated.Status != sunnyPlusWatchStatusActive || updated.ConfirmedAt == nil || updated.NextCheckAt != nil {
		t.Fatalf("arrival not confirmed: %#v", updated)
	}
	if updated.Attempts != 1 {
		t.Fatalf("attempts should be 1, got %d", updated.Attempts)
	}
	var reloaded SunnyAccount
	if err := s.db.First(&reloaded, account.ID).Error; err != nil {
		t.Fatalf("reload account: %v", err)
	}
	if reloaded.AccountType != "plus" {
		t.Fatalf("account plan should be plus, got %q", reloaded.AccountType)
	}
	var mailbox SunnyMailbox
	if err := s.db.First(&mailbox, account.MailboxID).Error; err != nil {
		t.Fatalf("reload mailbox: %v", err)
	}
	if mailbox.AccountType != "plus" {
		t.Fatalf("mailbox plan should be plus, got %q", mailbox.AccountType)
	}
}

func TestSunnyPlusWatchConfirmsOnSubscriptionMail(t *testing.T) {
	s := newPlusWatchTestServer(t)
	account := seedPlusWatchAccount(t, s, "mailed@example.com", "at_live")
	stubPlusWatchDetection(t, sunnySubscriptionATResult{Status: "valid", PlanType: "free"}, true, "Your new ChatGPT Plus subscription")

	s.enqueueSunnyPlusWatch("task_plus", plusWatchCheckoutPayload("plus"), plusWatchCheckoutItem, "mailed@example.com", account.ID)
	var watch SunnyPlusWatch
	if err := s.db.Where("email = ?", "mailed@example.com").First(&watch).Error; err != nil {
		t.Fatalf("load watch: %v", err)
	}
	s.sunnyRunPlusWatch(&watch)

	var updated SunnyPlusWatch
	if err := s.db.First(&updated, watch.ID).Error; err != nil {
		t.Fatalf("reload watch: %v", err)
	}
	if updated.Status != sunnyPlusWatchStatusActive || updated.ConfirmedAt == nil {
		t.Fatalf("mail evidence should confirm arrival: %#v", updated)
	}
	var reloaded SunnyAccount
	if err := s.db.First(&reloaded, account.ID).Error; err != nil {
		t.Fatalf("reload account: %v", err)
	}
	if reloaded.AccountType != "plus" {
		t.Fatalf("account plan should be plus, got %q", reloaded.AccountType)
	}
}

func TestSunnyPlusWatchStaysPendingWithinDeadline(t *testing.T) {
	s := newPlusWatchTestServer(t)
	account := seedPlusWatchAccount(t, s, "waiting@example.com", "at_live")
	stubPlusWatchDetection(t, sunnySubscriptionATResult{Status: "valid", PlanType: "free"}, false, "")

	s.enqueueSunnyPlusWatch("task_plus", plusWatchCheckoutPayload("plus"), plusWatchCheckoutItem, "waiting@example.com", account.ID)
	var watch SunnyPlusWatch
	if err := s.db.Where("email = ?", "waiting@example.com").First(&watch).Error; err != nil {
		t.Fatalf("load watch: %v", err)
	}
	before := time.Now()
	s.sunnyRunPlusWatch(&watch)

	var updated SunnyPlusWatch
	if err := s.db.First(&updated, watch.ID).Error; err != nil {
		t.Fatalf("reload watch: %v", err)
	}
	if updated.Status != sunnyPlusWatchStatusPending || updated.Attempts != 1 || updated.NextCheckAt == nil {
		t.Fatalf("watch should keep pending inside the window: %#v", updated)
	}
	if delta := updated.NextCheckAt.Sub(before) - sunnyPlusWatchIntervals[1]; delta > time.Second || delta < -time.Second {
		t.Fatalf("second check should back off to +%s, got %s", sunnyPlusWatchIntervals[1], delta)
	}
	if updated.LastError != "" {
		t.Fatalf("pending check must not record an error: %q", updated.LastError)
	}
}

func TestSunnyPlusWatchExpiresAfterDeadline(t *testing.T) {
	s := newPlusWatchTestServer(t)
	account := seedPlusWatchAccount(t, s, "expired@example.com", "at_live")
	stubPlusWatchDetection(t, sunnySubscriptionATResult{Status: "invalid", Error: "Access Token 无效"}, false, "")

	s.enqueueSunnyPlusWatch("task_plus", plusWatchCheckoutPayload("plus"), plusWatchCheckoutItem, "expired@example.com", account.ID)
	var watch SunnyPlusWatch
	if err := s.db.Where("email = ?", "expired@example.com").First(&watch).Error; err != nil {
		t.Fatalf("load watch: %v", err)
	}
	past := time.Now().Add(-time.Minute)
	if err := s.db.Model(&SunnyPlusWatch{}).Where("id = ?", watch.ID).Update("deadline_at", past).Error; err != nil {
		t.Fatalf("rewind deadline: %v", err)
	}
	if err := s.db.First(&watch, watch.ID).Error; err != nil {
		t.Fatalf("reload watch: %v", err)
	}
	s.sunnyRunPlusWatch(&watch)

	var updated SunnyPlusWatch
	if err := s.db.First(&updated, watch.ID).Error; err != nil {
		t.Fatalf("reload watch: %v", err)
	}
	if updated.Status != sunnyPlusWatchStatusExpired || updated.NextCheckAt != nil {
		t.Fatalf("watch past deadline must expire: %#v", updated)
	}
}

func TestSunnyPlusWatchSkipsAccountWithoutCredentials(t *testing.T) {
	s := newPlusWatchTestServer(t)
	stubPlusWatchDetection(t, sunnySubscriptionATResult{Status: "valid", PlanType: "plus"}, false, "")
	s.enqueueSunnyPlusWatch("task_plus", plusWatchCheckoutPayload("plus"), plusWatchCheckoutItem, "ghost@example.com", 999)
	var watch SunnyPlusWatch
	if err := s.db.Where("email = ?", "ghost@example.com").First(&watch).Error; err != nil {
		t.Fatalf("load watch: %v", err)
	}
	s.sunnyRunPlusWatch(&watch)

	var updated SunnyPlusWatch
	if err := s.db.First(&updated, watch.ID).Error; err != nil {
		t.Fatalf("reload watch: %v", err)
	}
	if updated.Status != sunnyPlusWatchStatusPending || updated.LastError == "" {
		t.Fatalf("missing account must stay pending with an error: %#v", updated)
	}
}

func TestSunnyMaybeRunPlusWatchesOnlyPicksDueRows(t *testing.T) {
	s := newPlusWatchTestServer(t)
	stubPlusWatchDetection(t, sunnySubscriptionATResult{Status: "valid", PlanType: "plus"}, false, "")
	seedPlusWatchAccount(t, s, "due@example.com", "at_live")
	past := time.Now().Add(-time.Minute)
	future := time.Now().Add(time.Hour)
	for _, watch := range []SunnyPlusWatch{
		{Email: "due@example.com", Plan: "plus", Status: sunnyPlusWatchStatusPending, NextCheckAt: &past, DeadlineAt: &future},
		{Email: "later@example.com", Plan: "plus", Status: sunnyPlusWatchStatusPending, NextCheckAt: &future, DeadlineAt: &future},
		{Email: "done@example.com", Plan: "plus", Status: sunnyPlusWatchStatusActive, NextCheckAt: &past, DeadlineAt: &future},
	} {
		if err := s.db.Create(&watch).Error; err != nil {
			t.Fatalf("seed watch: %v", err)
		}
	}
	s.sunnyMaybeRunPlusWatches()

	var due, later, done SunnyPlusWatch
	if err := s.db.Where("email = ?", "due@example.com").First(&due).Error; err != nil {
		t.Fatalf("reload due watch: %v", err)
	}
	if due.Status != sunnyPlusWatchStatusActive {
		t.Fatalf("due watch should have been checked: %#v", due)
	}
	if err := s.db.Where("email = ?", "later@example.com").First(&later).Error; err != nil {
		t.Fatalf("reload later watch: %v", err)
	}
	if later.Attempts != 0 {
		t.Fatalf("not-yet-due watch must be untouched, attempts=%d", later.Attempts)
	}
	if err := s.db.Where("email = ?", "done@example.com").First(&done).Error; err != nil {
		t.Fatalf("reload done watch: %v", err)
	}
	if done.Attempts != 0 {
		t.Fatalf("active watch must not be re-checked, attempts=%d", done.Attempts)
	}
}
