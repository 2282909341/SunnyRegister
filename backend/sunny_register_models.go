package main

import (
	"database/sql"
	"time"
)

type SunnyMailboxGroup struct {
	ID          uint      `gorm:"primaryKey" json:"id"`
	Name        string    `gorm:"uniqueIndex;size:120" json:"name"`
	Description string    `gorm:"type:text" json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func (SunnyMailboxGroup) TableName() string { return "sunny_mailbox_groups" }

type SunnyMailbox struct {
	ID                             uint         `gorm:"primaryKey" json:"id"`
	GroupID                        uint         `gorm:"index" json:"group_id"`
	Email                          string       `gorm:"uniqueIndex;index" json:"email"`
	RebindEmail                    string       `gorm:"index" json:"rebind_email"`
	RebindMailboxAPI               string       `gorm:"type:text" json:"rebind_mailbox_api"`
	MailboxType                    string       `gorm:"index;size:32;default:microsoft" json:"mailbox_type"`
	MailboxChannel                 string       `gorm:"index;size:64;default:outlook" json:"mailbox_channel"`
	AccessKey                      string       `gorm:"type:text" json:"access_key"`
	PickupTokenHash                string       `gorm:"column:pickup_token_hash;size:64;index" json:"-"`
	Password                       string       `gorm:"type:text" json:"password"`
	ChatGPTPassword                string       `gorm:"type:text" json:"chatgpt_password"`
	TOTPSecret                     string       `gorm:"type:text" json:"totp_secret"`
	ClientID                       string       `gorm:"type:text" json:"client_id"`
	RefreshToken                   string       `gorm:"type:text" json:"refresh_token"`
	OpenAIRT                       string       `gorm:"column:openai_rt;type:text" json:"openai_rt"`
	Raw                            string       `gorm:"type:text" json:"raw"`
	AccountType                    string       `gorm:"index;default:free" json:"account_type"`
	TrialEligibility               string       `gorm:"index;default:unknown" json:"trial_eligibility"`
	TrialCheckError                string       `gorm:"type:text" json:"trial_check_error"`
	TrialCountryResultsJSON        string       `gorm:"type:text;default:'{}'" json:"trial_country_results_json"`
	TrialCheckedAt                 *time.Time   `gorm:"index" json:"trial_checked_at"`
	Status                         string       `gorm:"index;default:unused" json:"status"`
	Enabled                        bool         `gorm:"default:true" json:"enabled"`
	LastError                      string       `gorm:"type:text" json:"last_error"`
	LatestMailJSON                 string       `gorm:"type:text;default:'{}'" json:"latest_mail_json"`
	LastMailAt                     sql.NullTime `json:"last_mail_at"`
	LastHealthCheckedAt            *time.Time   `gorm:"index" json:"last_health_checked_at"`
	StatusChangedAt                *time.Time   `gorm:"index" json:"status_changed_at"`
	RegisteredAt                   sql.NullTime `json:"registered_at"`
	ChatGPTRegisterTrafficBytes    int64        `gorm:"column:chatgpt_register_traffic_bytes;default:0" json:"chatgpt_register_traffic_bytes"`
	ProxyTrafficBytes              int64        `gorm:"default:0" json:"proxy_traffic_bytes"`
	RegistrationTrafficFinalizedAt *time.Time   `json:"registration_traffic_finalized_at"`
	CreatedAt                      time.Time    `json:"created_at"`
	UpdatedAt                      time.Time    `json:"updated_at"`
}

func (SunnyMailbox) TableName() string { return "sunny_mailboxes" }

type SunnyPhone struct {
	ID            uint         `gorm:"primaryKey" json:"id"`
	Number        string       `gorm:"uniqueIndex;index" json:"number"`
	SmsURL        string       `gorm:"type:text" json:"sms_url"`
	Status        string       `gorm:"index;default:available" json:"status"`
	Enabled       bool         `gorm:"default:true" json:"enabled"`
	SuccessCount  int          `gorm:"default:0" json:"success_count"`
	MaxSuccess    int          `gorm:"default:3" json:"max_success"`
	CooldownUntil sql.NullTime `gorm:"index" json:"cooldown_until"`
	LastCode      string       `json:"last_code"`
	LastError     string       `gorm:"type:text" json:"last_error"`
	LastUsedAt    sql.NullTime `json:"last_used_at"`
	CreatedAt     time.Time    `json:"created_at"`
	UpdatedAt     time.Time    `json:"updated_at"`
}

func (SunnyPhone) TableName() string { return "sunny_phones" }

type SunnyProxy struct {
	ID            uint       `gorm:"primaryKey" json:"id"`
	Address       string     `gorm:"type:text;index" json:"address"`
	Country       string     `gorm:"index;size:80" json:"country"`
	PurposeTags   string     `gorm:"type:text" json:"purpose_tags"`
	Status        string     `gorm:"index;default:enabled" json:"status"`
	Enabled       bool       `gorm:"default:true" json:"enabled"`
	LastCheckOK   bool       `gorm:"default:false" json:"last_check_ok"`
	LatencyMS     int64      `gorm:"default:0" json:"latency_ms"`
	LastError     string     `gorm:"type:text" json:"last_error"`
	LastCheckedAt *time.Time `json:"last_checked_at"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

func (SunnyProxy) TableName() string { return "sunny_proxies" }

type SunnyMailboxLease struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	MailboxID uint      `gorm:"uniqueIndex;not null" json:"mailbox_id"`
	Owner     string    `gorm:"index;size:255;not null" json:"owner"`
	ExpiresAt time.Time `gorm:"index;not null" json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (SunnyMailboxLease) TableName() string { return "sunny_mailbox_leases" }

type SunnyAccount struct {
	ID                      uint       `gorm:"primaryKey" json:"id"`
	MailboxID               uint       `gorm:"index" json:"mailbox_id"`
	Email                   string     `gorm:"uniqueIndex;index" json:"email"`
	GroupName               string     `gorm:"index" json:"group_name"`
	Status                  string     `gorm:"index;default:pending" json:"status"`
	AccountType             string     `gorm:"index;default:free" json:"account_type"`
	TrialEligibility        string     `gorm:"index;default:unknown" json:"trial_eligibility"`
	TrialCheckError         string     `gorm:"type:text" json:"trial_check_error"`
	TrialCountryResultsJSON string     `gorm:"type:text;default:'{}'" json:"trial_country_results_json"`
	TrialCheckedAt          *time.Time `gorm:"index" json:"trial_checked_at"`
	CheckoutKind            string     `gorm:"index;size:32;default:unknown" json:"checkout_kind"`
	CheckoutResultJSON      string     `gorm:"type:text;default:'{}'" json:"checkout_result_json"`
	PaymentMethodsJSON      string     `gorm:"type:text;default:'[]'" json:"payment_methods_json"`
	PaymentProbeMethodsJSON string     `gorm:"type:text;default:'[]'" json:"payment_probe_methods_json"`
	PaymentProbeResultsJSON string     `gorm:"type:text;default:'{}'" json:"payment_probe_results_json"`
	PaymentProbeError       string     `gorm:"type:text" json:"payment_probe_error"`
	PaymentProbedAt         *time.Time `gorm:"index" json:"payment_probed_at"`
	MomoPromoStatus         string     `gorm:"index;size:32;default:unknown" json:"momo_promo_status"`
	MomoPromoResultJSON     string     `gorm:"type:text;default:'{}'" json:"momo_promo_result_json"`
	MomoPromoError          string     `gorm:"type:text" json:"momo_promo_error"`
	MomoPromoProbedAt       *time.Time `gorm:"index" json:"momo_promo_probed_at"`
	CommerceCheckError      string     `gorm:"type:text" json:"commerce_check_error"`
	CommerceCheckedAt       *time.Time `gorm:"index" json:"commerce_checked_at"`
	OpenAIRT                string     `gorm:"column:openai_rt;type:text" json:"openai_rt"`
	AccessToken             string     `gorm:"type:text" json:"access_token"`
	PhoneNumber             string     `gorm:"index" json:"phone_number"`
	Sub2APIStatus           string     `gorm:"column:sub2api_status;index" json:"sub2api_status"`
	Sub2APIID               string     `gorm:"column:sub2api_id" json:"sub2api_id"`
	LastError               string     `gorm:"type:text" json:"last_error"`
	MetadataJSON            string     `gorm:"type:text;default:'{}'" json:"metadata_json"`
	RebindEmail             string     `gorm:"index" json:"rebind_email"`
	RebindMailboxAPI        string     `gorm:"type:text" json:"rebind_mailbox_api"`
	LastHealthCheckedAt     *time.Time `gorm:"index" json:"last_health_checked_at"`
	StatusChangedAt         *time.Time `gorm:"index" json:"status_changed_at"`
	CreatedAt               time.Time  `json:"created_at"`
	UpdatedAt               time.Time  `json:"updated_at"`
}

func (SunnyAccount) TableName() string { return "sunny_accounts" }

type SunnySession struct {
	ID                   uint         `gorm:"primaryKey" json:"id"`
	AccountID            uint         `gorm:"index" json:"account_id"`
	Email                string       `gorm:"uniqueIndex;index" json:"email"`
	AccessToken          string       `gorm:"type:text" json:"access_token"`
	RefreshToken         string       `gorm:"type:text" json:"refresh_token"`
	IDToken              string       `gorm:"type:text" json:"id_token"`
	SessionJSON          string       `gorm:"type:text" json:"session_json"`
	StorageStateJSON     string       `gorm:"type:text" json:"storage_state_json"`
	RawMailboxLine       string       `gorm:"type:text" json:"raw_mailbox_line"`
	AccessTokenStatus    string       `gorm:"index;default:unknown" json:"access_token_status"`
	AccessTokenError     string       `gorm:"type:text" json:"access_token_error"`
	AccessTokenCheckedAt *time.Time   `gorm:"index" json:"access_token_checked_at"`
	HealthCheckStatus    string       `gorm:"index;default:unknown" json:"health_check_status"`
	HealthCheckError     string       `gorm:"type:text" json:"health_check_error"`
	ExpiresAt            sql.NullTime `json:"expires_at"`
	LastRefreshAt        sql.NullTime `json:"last_refresh_at"`
	CreatedAt            time.Time    `json:"created_at"`
	UpdatedAt            time.Time    `json:"updated_at"`
}

func (SunnySession) TableName() string { return "sunny_sessions" }

type SunnyKVConfig struct {
	Key       string    `gorm:"primaryKey;size:80" json:"key"`
	ValueJSON string    `gorm:"type:text;default:'{}'" json:"value_json"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (SunnyKVConfig) TableName() string { return "sunny_configs" }

type SunnySMSProviderOption struct {
	ID          uint      `gorm:"primaryKey" json:"id"`
	Provider    string    `gorm:"uniqueIndex:idx_sunny_sms_option;size:40;index" json:"provider"`
	Kind        string    `gorm:"uniqueIndex:idx_sunny_sms_option;size:20;index" json:"kind"`
	ParentValue string    `gorm:"uniqueIndex:idx_sunny_sms_option;size:80;default:''" json:"parent_value"`
	Value       string    `gorm:"uniqueIndex:idx_sunny_sms_option;size:120" json:"value"`
	Label       string    `gorm:"size:240" json:"label"`
	ExtraJSON   string    `gorm:"type:text;default:'{}'" json:"extra_json"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func (SunnySMSProviderOption) TableName() string { return "sunny_sms_provider_options" }

type SunnySMSProviderNumber struct {
	ID            uint       `gorm:"primaryKey" json:"id"`
	Provider      string     `gorm:"uniqueIndex:idx_sunny_sms_provider_number;size:40;index" json:"provider"`
	PhoneNumber   string     `gorm:"uniqueIndex:idx_sunny_sms_provider_number;size:64;index" json:"phone_number"`
	Country       string     `gorm:"uniqueIndex:idx_sunny_sms_provider_number;size:80;default:''" json:"country"`
	Service       string     `gorm:"uniqueIndex:idx_sunny_sms_provider_number;size:120;default:''" json:"service"`
	Pool          string     `gorm:"size:120;default:''" json:"pool"`
	LastOrderID   string     `gorm:"type:text" json:"last_order_id"`
	Token         string     `gorm:"type:text" json:"token"`
	Status        string     `gorm:"index;size:32;default:available" json:"status"`
	SuccessCount  int        `gorm:"default:0" json:"success_count"`
	MaxSuccess    int        `gorm:"default:3" json:"max_success"`
	CooldownUntil *time.Time `gorm:"index" json:"cooldown_until"`
	LastError     string     `gorm:"type:text" json:"last_error"`
	LastUsedAt    *time.Time `gorm:"index" json:"last_used_at"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

func (SunnySMSProviderNumber) TableName() string { return "sunny_sms_provider_numbers" }
