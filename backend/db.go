package main

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type sqliteTableName struct {
	Name string `gorm:"column:name"`
}

type sqliteColumnInfo struct {
	Name string `gorm:"column:name"`
	Type string `gorm:"column:type"`
}

func quoteSQLiteIdentifier(value string) string {
	return `"` + strings.ReplaceAll(value, `"`, `""`) + `"`
}

// ensureShanghaiTimestampStorage is retained for SQLite source compatibility
// in tests and the one-time migration path. PostgreSQL stores time.Time values
// as timestamptz and does not call this function during normal startup.
func ensureShanghaiTimestampStorage(db *gorm.DB) {
	const migrationKey = "timezone_storage_asia_shanghai_v1"
	var migrated int64
	if db.Model(&SunnyKVConfig{}).Where("key = ?", migrationKey).Count(&migrated).Error == nil && migrated > 0 {
		return
	}
	var tables []sqliteTableName
	if err := db.Raw("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").Scan(&tables).Error; err != nil {
		return
	}
	for _, table := range tables {
		var columns []sqliteColumnInfo
		if err := db.Raw("PRAGMA table_info(" + quoteSQLiteIdentifier(table.Name) + ")").Scan(&columns).Error; err != nil {
			continue
		}
		for _, column := range columns {
			columnType := strings.ToLower(strings.TrimSpace(column.Type))
			if !strings.Contains(columnType, "date") && !strings.Contains(columnType, "time") {
				continue
			}
			tableName := quoteSQLiteIdentifier(table.Name)
			columnName := quoteSQLiteIdentifier(column.Name)
			statement := fmt.Sprintf(`UPDATE %s SET %s = trim(%s) || '+08:00'
				WHERE typeof(%s) = 'text' AND length(trim(%s)) >= 16
				AND (substr(trim(%s), 11, 1) = ' ' OR substr(trim(%s), 11, 1) = 'T')
				AND upper(substr(trim(%s), -1, 1)) <> 'Z'
				AND instr(substr(trim(%s), 11), '+') = 0
				AND instr(substr(trim(%s), 11), '-') = 0`,
				tableName, columnName, columnName, columnName, columnName,
				columnName, columnName, columnName, columnName, columnName)
			_ = db.Exec(statement).Error
		}
	}
	now := time.Now().In(applicationLocation())
	marker := SunnyKVConfig{Key: migrationKey, ValueJSON: `{"timezone":"Asia/Shanghai"}`, CreatedAt: now, UpdatedAt: now}
	_ = db.Create(&marker).Error
}

func configuredDatabaseURL() string {
	if file := strings.TrimSpace(os.Getenv("DATABASE_URL_FILE")); file != "" {
		if data, err := os.ReadFile(file); err == nil && strings.TrimSpace(string(data)) != "" {
			return strings.TrimSpace(string(data))
		}
	}
	return strings.TrimSpace(firstText(os.Getenv("DATABASE_URL"), os.Getenv("ACCOUNT_MANAGER_DATABASE_URL"), os.Getenv("ACCOUNT_MANAGER_DB")))
}

func databaseURL() string {
	raw := configuredDatabaseURL()
	if raw == "" {
		log.Fatal("PostgreSQL is required: set DATABASE_URL or ACCOUNT_MANAGER_DATABASE_URL")
	}
	lower := strings.ToLower(raw)
	if !strings.HasPrefix(lower, "postgres://") && !strings.HasPrefix(lower, "postgresql://") {
		log.Fatal("PostgreSQL is required: database URL must start with postgres:// or postgresql://")
	}
	return raw
}

func databaseModels() []any {
	return []any{
		&ConfigItem{}, &Account{}, &AccountOverview{}, &AccountCredential{},
		&ProviderAccount{}, &ProviderResource{}, &ProviderDefinition{}, &ProviderSetting{},
		&PlatformCapabilityOverride{}, &TaskLog{}, &Task{}, &TaskEvent{}, &Proxy{}, &SmsPoolBlacklist{},
		&SunnyMailboxGroup{}, &SunnyMailbox{}, &SunnyPhone{}, &SunnyProxy{}, &SunnyMailboxLease{}, &SunnyAccount{},
		&SunnySession{}, &SunnyKVConfig{}, &SunnySMSProviderOption{}, &SunnySMSProviderNumber{},
		&AuditLog{}, &AuditSetting{}, &AuditExportJob{}, &SunnyPlusWatch{},
	}
}

func openDB() *gorm.DB {
	gormLogger := logger.New(
		log.New(os.Stdout, "", log.LstdFlags),
		logger.Config{
			SlowThreshold:             200 * time.Millisecond,
			LogLevel:                  logger.Warn,
			IgnoreRecordNotFoundError: true,
			Colorful:                  true,
		},
	)
	db, err := gorm.Open(postgres.Open(databaseURL()), &gorm.Config{Logger: gormLogger})
	if err != nil {
		log.Fatalf("open PostgreSQL failed: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		log.Fatalf("read PostgreSQL connection pool failed: %v", err)
	}
	if sqlDB != nil {
		maxOpen := intValue(os.Getenv("SUNNY_DB_MAX_OPEN_CONNS"), 20)
		if maxOpen < 1 {
			maxOpen = 1
		}
		maxIdle := intValue(os.Getenv("SUNNY_DB_MAX_IDLE_CONNS"), 5)
		if maxIdle < 1 {
			maxIdle = 1
		}
		if maxIdle > maxOpen {
			maxIdle = maxOpen
		}
		sqlDB.SetMaxOpenConns(maxOpen)
		sqlDB.SetMaxIdleConns(maxIdle)
		sqlDB.SetConnMaxIdleTime(10 * time.Minute)
		sqlDB.SetConnMaxLifetime(30 * time.Minute)
		if err := sqlDB.Ping(); err != nil {
			log.Fatalf("connect PostgreSQL failed: %v", err)
		}
	}
	if err := db.AutoMigrate(databaseModels()...); err != nil {
		log.Fatalf("migrate PostgreSQL failed: %v", err)
	}
	ensureSunnySchema(db)
	reconcileSunnyDuplicateIdentities(db)
	ensureSunnyStatusTriggers(db)
	ensureSunnyIndexes(db)
	sanitizeHistoricalTaskData(db)
	return db
}

func ensureSunnyStatusTriggers(db *gorm.DB) {
	functionStatement := `CREATE OR REPLACE FUNCTION sunny_set_status_changed_at()
		RETURNS trigger AS $$
		BEGIN
			IF TG_OP = 'INSERT' THEN
				NEW.status_changed_at := COALESCE(NEW.status_changed_at, NEW.created_at, NEW.updated_at, CURRENT_TIMESTAMP);
			ELSIF NEW.status IS DISTINCT FROM OLD.status THEN
				NEW.status_changed_at := CASE
					WHEN NEW.updated_at IS DISTINCT FROM OLD.updated_at THEN NEW.updated_at
					ELSE CURRENT_TIMESTAMP
				END;
			END IF;
			RETURN NEW;
		END;
		$$ LANGUAGE plpgsql`
	if err := db.Exec(functionStatement).Error; err != nil {
		log.Printf("create status timestamp function failed: %v", err)
		return
	}
	for _, table := range []string{"sunny_mailboxes", "sunny_accounts"} {
		trigger := "trg_" + table + "_status_changed"
		db.Exec("DROP TRIGGER IF EXISTS " + trigger + " ON " + table)
		statement := "CREATE TRIGGER " + trigger + " BEFORE INSERT OR UPDATE OF status ON " + table +
			" FOR EACH ROW EXECUTE FUNCTION sunny_set_status_changed_at()"
		if err := db.Exec(statement).Error; err != nil {
			log.Printf("create status timestamp trigger for %s failed: %v", table, err)
		}
	}
}

func ensureSunnyIndexes(db *gorm.DB) {
	indexes := []string{
		"CREATE INDEX IF NOT EXISTS idx_sunny_mailboxes_enabled_updated ON sunny_mailboxes(enabled, updated_at DESC)",
		"CREATE INDEX IF NOT EXISTS idx_sunny_mailboxes_group_status_enabled ON sunny_mailboxes(group_id, status, enabled)",
		"CREATE INDEX IF NOT EXISTS idx_sunny_sessions_updated ON sunny_sessions(updated_at DESC)",
		"CREATE INDEX IF NOT EXISTS idx_sunny_sessions_email ON sunny_sessions(email)",
		"CREATE INDEX IF NOT EXISTS idx_sunny_accounts_email ON sunny_accounts(email)",
		"CREATE UNIQUE INDEX IF NOT EXISTS ux_sunny_sessions_email_ci ON sunny_sessions(LOWER(BTRIM(email))) WHERE BTRIM(email) <> ''",
		"CREATE UNIQUE INDEX IF NOT EXISTS ux_sunny_accounts_email_ci ON sunny_accounts(LOWER(BTRIM(email))) WHERE BTRIM(email) <> ''",
		"CREATE INDEX IF NOT EXISTS idx_sunny_accounts_health_checked ON sunny_accounts(last_health_checked_at DESC)",
		"CREATE INDEX IF NOT EXISTS idx_sunny_accounts_checkout_kind ON sunny_accounts(checkout_kind)",
		"CREATE INDEX IF NOT EXISTS idx_sunny_accounts_commerce_checked ON sunny_accounts(commerce_checked_at DESC)",
		"CREATE INDEX IF NOT EXISTS idx_sunny_mailboxes_health_checked ON sunny_mailboxes(last_health_checked_at DESC)",
		"CREATE INDEX IF NOT EXISTS idx_sunny_accounts_status_changed ON sunny_accounts(status_changed_at DESC)",
		"CREATE INDEX IF NOT EXISTS idx_sunny_mailboxes_status_changed ON sunny_mailboxes(status_changed_at DESC)",
		"CREATE INDEX IF NOT EXISTS idx_sunny_proxies_status_enabled_checked ON sunny_proxies(status, enabled, last_checked_at)",
		"CREATE INDEX IF NOT EXISTS idx_sunny_proxies_country_status ON sunny_proxies(country, status)",
		"CREATE INDEX IF NOT EXISTS idx_task_events_task_id_id ON task_events(task_id, id)",
		"CREATE INDEX IF NOT EXISTS idx_task_events_task_subject_id ON task_events(task_id, subject_key, id)",
		"CREATE INDEX IF NOT EXISTS idx_task_events_email_created ON task_events(email, created_at DESC)",
		"CREATE INDEX IF NOT EXISTS idx_task_events_operation_id ON task_events(operation_id, id)",
		"CREATE INDEX IF NOT EXISTS idx_task_events_module_created ON task_events(module, created_at DESC)",
		"CREATE INDEX IF NOT EXISTS idx_task_events_level_created ON task_events(level, created_at DESC)",
		"CREATE INDEX IF NOT EXISTS idx_tasks_status_created ON tasks(status, created_at)",
		"CREATE INDEX IF NOT EXISTS idx_audit_logs_time_type ON audit_logs(occurred_at DESC, log_type)",
		"CREATE INDEX IF NOT EXISTS idx_audit_logs_category_action ON audit_logs(category, action, occurred_at DESC)",
		"CREATE INDEX IF NOT EXISTS idx_audit_logs_actor_ip ON audit_logs(actor, ip, occurred_at DESC)",
		"CREATE INDEX IF NOT EXISTS idx_audit_logs_task_entity ON audit_logs(task_id, entity_type, entity_id)",
		"CREATE INDEX IF NOT EXISTS idx_audit_logs_subject_key ON audit_logs(subject_key)",
		"CREATE INDEX IF NOT EXISTS idx_audit_export_jobs_status_created ON audit_export_jobs(status, created_at DESC)",
	}
	for _, statement := range indexes {
		if err := db.Exec(statement).Error; err != nil {
			log.Printf("create performance index failed: %v", err)
		}
	}
}

func reconcileSunnyDuplicateIdentities(db *gorm.DB) {
	reconcileSunnyRebindIdentityDuplicates(db)
	var accounts []SunnyAccount
	var sessions []SunnySession
	if db.Order("updated_at desc, id desc").Find(&accounts).Error != nil || db.Order("updated_at desc, id desc").Find(&sessions).Error != nil {
		return
	}
	sessionsByAccount := map[uint][]SunnySession{}
	for _, session := range sessions {
		sessionsByAccount[session.AccountID] = append(sessionsByAccount[session.AccountID], session)
	}
	accountGroups := map[string][]SunnyAccount{}
	for _, account := range accounts {
		if key := sunnyEmailKey(account.Email); key != "" {
			accountGroups[key] = append(accountGroups[key], account)
		}
	}
	removedAccounts := 0
	for _, group := range accountGroups {
		if len(group) < 2 {
			continue
		}
		winner := group[0]
		for _, candidate := range group[1:] {
			if winner.MailboxID == 0 && candidate.MailboxID != 0 {
				winner = candidate
			}
		}
		accessTokens := []string{winner.AccessToken}
		refreshToken := strings.TrimSpace(winner.OpenAIRT)
		mailboxID := winner.MailboxID
		duplicateIDs := make([]uint, 0, len(group)-1)
		for _, account := range group {
			accessTokens = append(accessTokens, account.AccessToken)
			if refreshToken == "" && strings.TrimSpace(account.OpenAIRT) != "" {
				refreshToken = account.OpenAIRT
			}
			if mailboxID == 0 && account.MailboxID != 0 {
				mailboxID = account.MailboxID
			}
			for _, session := range sessionsByAccount[account.ID] {
				accessTokens = append(accessTokens, session.AccessToken, sunnyAccessTokenFromSessionJSON(session.SessionJSON))
				if refreshToken == "" && strings.TrimSpace(session.RefreshToken) != "" {
					refreshToken = session.RefreshToken
				}
			}
			if account.ID != winner.ID {
				duplicateIDs = append(duplicateIDs, account.ID)
			}
		}
		_ = db.Model(&SunnyAccount{}).Where("id = ?", winner.ID).Updates(map[string]any{
			"mailbox_id": mailboxID, "access_token": sunnyPreferredAccessToken(accessTokens...), "openai_rt": refreshToken,
		}).Error
		if len(duplicateIDs) > 0 {
			db.Model(&SunnySession{}).Where("account_id IN ?", duplicateIDs).Update("account_id", winner.ID)
			db.Where("id IN ?", duplicateIDs).Delete(&SunnyAccount{})
			removedAccounts += len(duplicateIDs)
		}
	}

	if db.Order("updated_at desc, id desc").Find(&sessions).Error != nil {
		return
	}
	sessionGroups := map[string][]SunnySession{}
	for _, session := range sessions {
		if key := sunnyEmailKey(session.Email); key != "" {
			sessionGroups[key] = append(sessionGroups[key], session)
		}
	}
	removedSessions := 0
	for key, group := range sessionGroups {
		if len(group) < 2 {
			continue
		}
		winner := group[0]
		accessTokens := []string{}
		refreshToken := ""
		duplicateIDs := make([]uint, 0, len(group)-1)
		for _, session := range group {
			accessTokens = append(accessTokens, session.AccessToken, sunnyAccessTokenFromSessionJSON(session.SessionJSON))
			if refreshToken == "" && strings.TrimSpace(session.RefreshToken) != "" {
				refreshToken = session.RefreshToken
			}
			if session.ID != winner.ID {
				duplicateIDs = append(duplicateIDs, session.ID)
			}
		}
		var account SunnyAccount
		db.Where("id = ? OR LOWER(TRIM(email)) = ?", winner.AccountID, key).Order("updated_at desc, id desc").First(&account)
		accessTokens = append(accessTokens, account.AccessToken)
		accessToken := sunnyPreferredAccessToken(accessTokens...)
		expiresAt := sunnyAccessTokenExpiry(accessToken, winner.ExpiresAt)
		updates := map[string]any{
			"account_id": winner.AccountID, "access_token": accessToken, "refresh_token": refreshToken,
			"access_token_status": "unknown", "access_token_error": "", "expires_at": nil,
		}
		if expiresAt.Valid {
			updates["expires_at"] = expiresAt.Time
		}
		db.Model(&SunnySession{}).Where("id = ?", winner.ID).Updates(updates)
		if account.ID != 0 && accessToken != "" {
			db.Model(&SunnyAccount{}).Where("id = ?", account.ID).Update("access_token", accessToken)
		}
		if len(duplicateIDs) > 0 {
			db.Where("id IN ?", duplicateIDs).Delete(&SunnySession{})
			removedSessions += len(duplicateIDs)
		}
	}
	if removedAccounts > 0 || removedSessions > 0 {
		log.Printf("reconciled duplicate Sunny identities: accounts=%d sessions=%d", removedAccounts, removedSessions)
	}
}

func reconcileSunnyRebindIdentityDuplicates(db *gorm.DB) {
	var mailboxes []SunnyMailbox
	if db.Where("TRIM(COALESCE(rebind_email, '')) <> ''").Find(&mailboxes).Error != nil {
		return
	}
	removedAccounts := 0
	removedSessions := 0
	for _, mailbox := range mailboxes {
		originalEmail := sunnyEmailKey(mailbox.Email)
		rebindEmail := sunnyEmailKey(mailbox.RebindEmail)
		if originalEmail == "" || rebindEmail == "" || originalEmail == rebindEmail {
			continue
		}
		var original SunnyAccount
		if db.Where("LOWER(TRIM(email)) = ?", originalEmail).First(&original).Error != nil {
			continue
		}
		var duplicates []SunnyAccount
		if db.Where("id <> ? AND mailbox_id = ? AND LOWER(TRIM(email)) = ?", original.ID, mailbox.ID, rebindEmail).Find(&duplicates).Error != nil {
			continue
		}
		for _, duplicate := range duplicates {
			_ = db.Transaction(func(tx *gorm.DB) error {
				var originalSession SunnySession
				originalSessionErr := tx.Where("account_id = ?", original.ID).Order("updated_at desc, id desc").First(&originalSession).Error
				var duplicateSessions []SunnySession
				if err := tx.Where("account_id = ?", duplicate.ID).Order("updated_at desc, id desc").Find(&duplicateSessions).Error; err != nil {
					return err
				}
				tokens := []string{duplicate.AccessToken}
				refreshToken := strings.TrimSpace(duplicate.OpenAIRT)
				var sourceSession SunnySession
				for _, session := range duplicateSessions {
					tokens = append(tokens, session.AccessToken, sunnyAccessTokenFromSessionJSON(session.SessionJSON))
					if sourceSession.ID == 0 {
						sourceSession = session
					}
					if refreshToken == "" && strings.TrimSpace(session.RefreshToken) != "" {
						refreshToken = session.RefreshToken
					}
				}
				tokens = append(tokens, original.AccessToken)
				if originalSessionErr == nil {
					tokens = append(tokens, originalSession.AccessToken, sunnyAccessTokenFromSessionJSON(originalSession.SessionJSON))
					if refreshToken == "" {
						refreshToken = originalSession.RefreshToken
					}
				}
				accessToken := sunnyPreferredAccessToken(tokens...)
				accountUpdates := map[string]any{"access_token": accessToken, "last_error": ""}
				if refreshToken != "" {
					accountUpdates["openai_rt"] = refreshToken
				}
				if plan := sunnySubscriptionPlanTypeFromAccessToken(accessToken); plan != "" {
					accountUpdates["account_type"] = plan
					if err := tx.Model(&SunnyMailbox{}).Where("id = ?", mailbox.ID).Update("account_type", plan).Error; err != nil {
						return err
					}
				}
				if err := tx.Model(&SunnyAccount{}).Where("id = ?", original.ID).Updates(accountUpdates).Error; err != nil {
					return err
				}
				if originalSessionErr == nil {
					sessionUpdates := map[string]any{"account_id": original.ID, "email": mailbox.Email, "access_token": accessToken, "access_token_error": ""}
					if sourceSession.ID != 0 {
						sessionUpdates["refresh_token"] = firstText(sourceSession.RefreshToken, refreshToken)
						sessionUpdates["id_token"] = sourceSession.IDToken
						sessionUpdates["session_json"] = sourceSession.SessionJSON
						sessionUpdates["storage_state_json"] = sourceSession.StorageStateJSON
						sessionUpdates["expires_at"] = sourceSession.ExpiresAt
						sessionUpdates["last_refresh_at"] = sourceSession.LastRefreshAt
					}
					if err := tx.Model(&SunnySession{}).Where("id = ?", originalSession.ID).Updates(sessionUpdates).Error; err != nil {
						return err
					}
				} else if sourceSession.ID != 0 {
					if err := tx.Model(&SunnySession{}).Where("id = ?", sourceSession.ID).Updates(map[string]any{
						"account_id": original.ID, "email": mailbox.Email, "access_token": accessToken,
					}).Error; err != nil {
						return err
					}
				}
				keepSessionID := originalSession.ID
				if keepSessionID == 0 {
					keepSessionID = sourceSession.ID
				}
				deleteQuery := tx.Where("account_id = ?", duplicate.ID)
				if keepSessionID != 0 {
					deleteQuery = deleteQuery.Where("id <> ?", keepSessionID)
				}
				result := deleteQuery.Delete(&SunnySession{})
				if result.Error != nil {
					return result.Error
				}
				removedSessions += int(result.RowsAffected)
				if err := tx.Delete(&SunnyAccount{}, duplicate.ID).Error; err != nil {
					return err
				}
				removedAccounts++
				return nil
			})
		}
	}
	if removedAccounts > 0 || removedSessions > 0 {
		log.Printf("reconciled rebound Sunny identity duplicates: accounts=%d sessions=%d", removedAccounts, removedSessions)
	}
}

func sanitizeHistoricalTaskData(db *gorm.DB) {
	var events []TaskEvent
	if db.Select("id", "type", "message", "detail_json", "scope", "subject_type", "subject_key", "email", "account_id", "mailbox_id", "module", "action", "operation_id").Find(&events).Error == nil {
		for _, event := range events {
			message := sanitizePersistedString(event.Message)
			detailJSON := sanitizePersistedJSON(event.DetailJSON)
			detail := jsonMap(detailJSON)
			metadata := taskEventMetadata(message, event.Type, detail, TaskEventContext{
				Email: event.Email, AccountID: event.AccountID, MailboxID: event.MailboxID,
				Module: event.Module, Action: event.Action, Scope: event.Scope,
				SubjectType: event.SubjectType, OperationID: event.OperationID,
			})
			updates := map[string]any{
				"message": message, "detail_json": detailJSON, "scope": metadata.Scope,
				"subject_type": metadata.SubjectType, "subject_key": metadata.SubjectKey,
				"email": metadata.Email, "account_id": metadata.AccountID, "mailbox_id": metadata.MailboxID,
				"module": metadata.Module, "action": metadata.Action, "operation_id": metadata.OperationID,
			}
			if message != event.Message || detailJSON != event.DetailJSON ||
				event.Scope != metadata.Scope || event.SubjectType != metadata.SubjectType || event.SubjectKey != metadata.SubjectKey ||
				event.Email != metadata.Email || event.AccountID != metadata.AccountID || event.MailboxID != metadata.MailboxID ||
				event.Module != metadata.Module || event.Action != metadata.Action || event.OperationID != metadata.OperationID {
				db.Model(&TaskEvent{}).Where("id = ?", event.ID).Updates(updates)
			}
		}
	}
	var tasks []Task
	terminal := []string{"succeeded", "failed", "cancelled", "interrupted"}
	if db.Select("id", "status", "payload_json", "result_json", "error").Where("status IN ?", terminal).Find(&tasks).Error == nil {
		for _, task := range tasks {
			payload := sanitizePersistedJSON(task.PayloadJSON)
			result := sanitizePersistedJSON(task.ResultJSON)
			errorText := sanitizePersistedString(task.Error)
			if payload != task.PayloadJSON || result != task.ResultJSON || errorText != task.Error {
				db.Model(&Task{}).Where("id = ?", task.ID).Updates(map[string]any{"payload_json": payload, "result_json": result, "error": errorText})
			}
		}
	}
}

func ensureSunnySchema(db *gorm.DB) {
	required := map[string]map[string]string{
		"sunny_accounts": {
			"mailbox_id":                 "integer DEFAULT 0",
			"group_name":                 "text DEFAULT ''",
			"status":                     "text DEFAULT 'pending'",
			"account_type":               "text DEFAULT 'free'",
			"trial_eligibility":          "text DEFAULT 'unknown'",
			"trial_check_error":          "text DEFAULT ''",
			"trial_country_results_json": "text DEFAULT '{}'",
			"trial_checked_at":           "timestamptz",
			"checkout_kind":              "text DEFAULT 'unknown'",
			"checkout_result_json":       "text DEFAULT '{}'",
			"payment_methods_json":       "text DEFAULT '[]'",
			"payment_probe_methods_json": "text DEFAULT '[]'",
			"payment_probe_results_json": "text DEFAULT '{}'",
			"payment_probe_error":        "text DEFAULT ''",
			"payment_probed_at":          "timestamptz",
			"commerce_check_error":       "text DEFAULT ''",
			"commerce_checked_at":        "timestamptz",
			"openai_rt":                  "text DEFAULT ''",
			"access_token":               "text DEFAULT ''",
			"phone_number":               "text DEFAULT ''",
			"sub2api_status":             "text DEFAULT ''",
			"sub2api_id":                 "text DEFAULT ''",
			"last_error":                 "text DEFAULT ''",
			"metadata_json":              "text DEFAULT '{}'",
			"last_health_checked_at":     "timestamptz",
			"status_changed_at":          "timestamptz",
		},
		"sunny_mailboxes": {
			"chat_gpt_password":                 "text DEFAULT ''",
			"totp_secret":                       "text DEFAULT ''",
			"openai_rt":                         "text DEFAULT ''",
			"trial_eligibility":                 "text DEFAULT 'unknown'",
			"trial_check_error":                 "text DEFAULT ''",
			"trial_country_results_json":        "text DEFAULT '{}'",
			"trial_checked_at":                  "timestamptz",
			"registered_at":                     "timestamptz",
			"chatgpt_register_traffic_bytes":    "bigint DEFAULT 0",
			"proxy_traffic_bytes":               "bigint DEFAULT 0",
			"registration_traffic_finalized_at": "timestamptz",
			"last_error":                        "text DEFAULT ''",
			"last_health_checked_at":            "timestamptz",
			"status_changed_at":                 "timestamptz",
		},
		"sunny_sessions": {
			"refresh_token":           "text DEFAULT ''",
			"id_token":                "text DEFAULT ''",
			"session_json":            "text DEFAULT '{}'",
			"storage_state_json":      "text DEFAULT '{}'",
			"raw_mailbox_line":        "text DEFAULT ''",
			"access_token_status":     "text DEFAULT 'unknown'",
			"access_token_error":      "text DEFAULT ''",
			"access_token_checked_at": "timestamptz",
			"health_check_status":     "text DEFAULT 'unknown'",
			"health_check_error":      "text DEFAULT ''",
			"last_refresh_at":         "timestamptz",
		},
	}
	for table, cols := range required {
		for col, ddl := range cols {
			if !db.Migrator().HasColumn(table, col) {
				db.Exec("ALTER TABLE " + table + " ADD COLUMN " + col + " " + ddl)
			}
		}
	}
	for _, table := range []string{"sunny_accounts", "sunny_mailboxes"} {
		if db.Migrator().HasColumn(table, "open_airt") && db.Migrator().HasColumn(table, "openai_rt") {
			db.Exec("UPDATE " + table + " SET openai_rt = open_airt WHERE coalesce(openai_rt,'') = '' AND coalesce(open_airt,'') <> ''")
		}
		db.Exec("UPDATE " + table + " SET status_changed_at = updated_at WHERE status_changed_at IS NULL")
	}
	db.Exec("UPDATE sunny_mailboxes SET status = '已接码' WHERE status = 'PLUS试用中'")
	db.Exec("UPDATE sunny_accounts SET status = 'phone_bound' WHERE status = 'PLUS试用中'")
	reconcileSunnyRebindCredentials(db)
	sanitizeSunnyMailboxCredentials(db)
}

func reconcileSunnyRebindCredentials(db *gorm.DB) {
	var accounts []SunnyAccount
	if err := db.Where("coalesce(rebind_email,'') <> '' AND coalesce(rebind_mailbox_api,'') <> ''").Find(&accounts).Error; err != nil {
		return
	}
	for _, account := range accounts {
		rebindEmail := strings.TrimSpace(account.RebindEmail)
		rebindAPI := strings.TrimSpace(account.RebindMailboxAPI)
		if validateDomainMailboxAccessKey(rebindAPI, rebindEmail) != nil {
			continue
		}
		var mailbox SunnyMailbox
		if account.MailboxID != 0 {
			db.First(&mailbox, account.MailboxID)
		}
		if mailbox.ID == 0 {
			db.Where("LOWER(email) = ? OR LOWER(rebind_email) = ?", sunnyEmailKey(account.Email), sunnyEmailKey(account.Email)).First(&mailbox)
		}
		if mailbox.ID == 0 {
			continue
		}
		raw := sunnyURLAPIRaw(rebindEmail, rebindAPI)
		canonicalEmail := strings.TrimSpace(mailbox.Email)
		_ = db.Transaction(func(tx *gorm.DB) error {
			if err := tx.Model(&SunnyMailbox{}).Where("id = ?", mailbox.ID).Updates(map[string]any{
				"rebind_email": rebindEmail, "rebind_mailbox_api": rebindAPI,
				"mailbox_type": "domain", "mailbox_channel": "domain_api", "access_key": rebindAPI,
				"pickup_token_hash": domainMailboxTokenHashFromCredential(rebindAPI, rebindEmail), "raw": raw,
			}).Error; err != nil {
				return err
			}
			if account.MailboxID != mailbox.ID {
				if err := tx.Model(&SunnyAccount{}).Where("id = ?", account.ID).Update("mailbox_id", mailbox.ID).Error; err != nil {
					return err
				}
			}
			if canonicalEmail != "" && strings.EqualFold(strings.TrimSpace(account.Email), rebindEmail) && !strings.EqualFold(strings.TrimSpace(account.Email), canonicalEmail) {
				if err := tx.Model(&SunnyAccount{}).Where("id = ?", account.ID).Update("email", canonicalEmail).Error; err != nil {
					return err
				}
				sessionQuery := tx.Model(&SunnySession{}).Where("LOWER(email) = ?", sunnyEmailKey(rebindEmail))
				if account.ID != 0 {
					sessionQuery = sessionQuery.Or("account_id = ?", account.ID)
				}
				if err := sessionQuery.Update("email", canonicalEmail).Error; err != nil {
					return err
				}
			}
			return tx.Model(&SunnySession{}).Where("account_id = ?", account.ID).Update("raw_mailbox_line", raw).Error
		})
	}
}

func sanitizeSunnyMailboxCredentials(db *gorm.DB) {
	var mailboxes []SunnyMailbox
	if err := db.Find(&mailboxes).Error; err != nil {
		return
	}
	credentials := make(map[string]string, len(mailboxes))
	for _, mailbox := range mailboxes {
		credential := strings.TrimSpace(sunnyMailboxCredentialLine(mailbox))
		if credential == "" {
			continue
		}
		credentials[sunnyEmailKey(mailbox.Email)] = credential
		if strings.TrimSpace(mailbox.RebindEmail) != "" {
			credentials[sunnyEmailKey(mailbox.RebindEmail)] = credential
		}
		if credential != strings.TrimSpace(mailbox.Raw) {
			db.Model(&SunnyMailbox{}).Where("id = ?", mailbox.ID).UpdateColumn("raw", credential)
		}
	}
	var sessions []SunnySession
	if err := db.Select("id", "email", "raw_mailbox_line").Find(&sessions).Error; err != nil {
		return
	}
	for _, session := range sessions {
		credential := credentials[sunnyEmailKey(session.Email)]
		if credential != "" && credential != strings.TrimSpace(session.RawMailboxLine) {
			db.Model(&SunnySession{}).Where("id = ?", session.ID).UpdateColumn("raw_mailbox_line", credential)
		}
	}
}

func seedProviderDefinitions(db *gorm.DB) {
	seeds := []map[string]any{
		{
			"provider_type": "mailbox", "provider_key": "cfworker_admin_api", "label": "CF Worker / cloud-mail", "description": "Cloudflare Worker 自建域名邮箱", "driver_type": "cfworker_admin_api", "default_auth_mode": "token", "category": "selfhost",
			"auth_modes": []map[string]any{{"value": "token", "label": "Token 认证"}},
			"fields":     []map[string]any{{"key": "cfworker_api_url", "label": "API 地址", "placeholder": "https://your-worker.example.com", "category": "connection"}, {"key": "cfworker_admin_token", "label": "Admin Token", "secret": true, "category": "auth"}, {"key": "cfworker_domain", "label": "邮箱域名", "placeholder": "example.com", "category": "connection"}},
		},
		{
			"provider_type": "mailbox", "provider_key": "moemail_api", "label": "MoeMail", "description": "自部署临时邮箱服务", "driver_type": "moemail_api", "default_auth_mode": "password", "category": "selfhost",
			"auth_modes": []map[string]any{{"value": "password", "label": "账号密码"}, {"value": "token", "label": "Session Token"}},
			"fields":     []map[string]any{{"key": "moemail_api_url", "label": "API 地址", "placeholder": "https://moemail.example.com", "category": "connection"}, {"key": "moemail_username", "label": "用户名", "category": "auth"}, {"key": "moemail_password", "label": "密码", "secret": true, "category": "auth"}, {"key": "moemail_session_token", "label": "Session Token", "secret": true, "category": "auth"}},
		},
		{"provider_type": "mailbox", "provider_key": "tempmail_lol_api", "label": "TempMail.lol", "description": "免费临时邮箱", "driver_type": "tempmail_lol_api", "category": "free", "auth_modes": []map[string]any{}, "fields": []map[string]any{}},
		{
			"provider_type": "mailbox", "provider_key": "outlook_email_api", "label": "Outlook Email Pool", "description": "对接 Outlook/Hotmail 邮箱池 API", "driver_type": "outlook_email_api", "default_auth_mode": "apikey", "category": "selfhost",
			"auth_modes": []map[string]any{{"value": "apikey", "label": "API Key"}},
			"fields":     []map[string]any{{"key": "outlook_email_api_url", "label": "服务地址", "placeholder": "https://outlook-email.example.com", "category": "connection"}, {"key": "outlook_email_api_key", "label": "API Key", "secret": true, "category": "auth"}, {"key": "outlook_email_fixed_email", "label": "固定邮箱", "placeholder": "user@outlook.com", "category": "identity"}},
		},
		{"provider_type": "mailbox", "provider_key": "generic_http_mailbox", "label": "通用 HTTP 邮箱", "description": "通过 HTTP 配置对接任意邮箱 API", "driver_type": "generic_http_mailbox", "category": "custom", "auth_modes": []map[string]any{}, "fields": []map[string]any{}},
		{"provider_type": "captcha", "provider_key": "yescaptcha_api", "label": "YesCaptcha", "description": "云端验证码识别服务", "driver_type": "yescaptcha_api", "default_auth_mode": "apikey", "category": "thirdparty", "auth_modes": []map[string]any{{"value": "apikey", "label": "API Key"}}, "fields": []map[string]any{{"key": "yescaptcha_key", "label": "Client Key", "secret": true}}},
		{"provider_type": "captcha", "provider_key": "twocaptcha_api", "label": "2Captcha", "description": "云端验证码识别服务", "driver_type": "twocaptcha_api", "default_auth_mode": "apikey", "category": "thirdparty", "auth_modes": []map[string]any{{"value": "apikey", "label": "API Key"}}, "fields": []map[string]any{{"key": "twocaptcha_key", "label": "API Key", "secret": true}}},
		{"provider_type": "captcha", "provider_key": "local_solver", "label": "本地验证码求解器", "description": "调用本地 solver 服务", "driver_type": "local_solver", "category": "local", "auth_modes": []map[string]any{}, "fields": []map[string]any{{"key": "solver_url", "label": "Solver 地址", "placeholder": "http://localhost:8889"}}},
		{"provider_type": "captcha", "provider_key": "manual", "label": "人工处理", "description": "等待人工完成验证码", "driver_type": "manual", "category": "manual", "auth_modes": []map[string]any{}, "fields": []map[string]any{}},
		{
			"provider_type": "sms", "provider_key": "herosms_api", "label": "HeroSMS", "description": "HeroSMS 接码平台", "driver_type": "herosms_api", "default_auth_mode": "apikey", "category": "thirdparty",
			"auth_modes": []map[string]any{{"value": "apikey", "label": "API Key"}},
			"fields":     []map[string]any{{"key": "herosms_api_key", "label": "API Key", "secret": true, "category": "auth"}, {"key": "herosms_default_country", "label": "默认国家", "type": "async-select", "asyncUrl": "/sms/herosms/countries", "asyncValueKey": "id", "asyncLabelKey": "chn"}, {"key": "herosms_default_service", "label": "默认服务", "type": "async-select", "asyncUrl": "/sms/herosms/services", "asyncValueKey": "code", "asyncLabelKey": "name"}, {"key": "herosms_max_price", "label": "最高价格", "placeholder": "-1"}, {"key": "register_phone_extra_max", "label": "号码复用额外上限", "placeholder": "3"}, {"key": "register_reuse_phone_to_max", "label": "复用号码至最大", "type": "toggle"}},
		},
		{
			"provider_type": "sms", "provider_key": "smsbower_api", "label": "SMSBower", "description": "SMSBower 接码平台", "driver_type": "smsbower_api", "default_auth_mode": "apikey", "category": "thirdparty",
			"auth_modes": []map[string]any{{"value": "apikey", "label": "API Key"}},
			"fields":     []map[string]any{{"key": "smsbower_api_key", "label": "API Key", "secret": true, "category": "auth"}, {"key": "smsbower_default_country", "label": "默认国家", "type": "async-select", "asyncUrl": "/sms/smsbower/countries", "asyncValueKey": "id", "asyncLabelKey": "chn"}, {"key": "smsbower_default_service", "label": "默认服务", "type": "async-select", "asyncUrl": "/sms/smsbower/services", "asyncValueKey": "code", "asyncLabelKey": "name"}, {"key": "smsbower_max_price", "label": "最高价格", "placeholder": "-1"}},
		},
		{"provider_type": "proxy", "provider_key": "api_extract", "label": "API 提取代理", "description": "通过 HTTP API 动态提取代理列表", "driver_type": "api_extract", "category": "thirdparty", "auth_modes": []map[string]any{}, "fields": []map[string]any{{"key": "proxy_api_url", "label": "API 地址"}, {"key": "proxy_protocol", "label": "协议"}}},
	}

	for _, seed := range seeds {
		pt := text(seed["provider_type"])
		pk := text(seed["provider_key"])
		if pt == "" || pk == "" {
			continue
		}
		var item ProviderDefinition
		err := db.Where("provider_type = ? AND provider_key = ?", pt, pk).First(&item).Error
		if err != nil {
			item = ProviderDefinition{ProviderType: pt, ProviderKey: pk}
		}
		item.Label = text(seed["label"])
		item.Description = text(seed["description"])
		item.DriverType = text(seed["driver_type"])
		item.DefaultAuthMode = text(seed["default_auth_mode"])
		item.Enabled = true
		item.IsBuiltin = true
		item.Category = text(seed["category"])
		item.AuthModesJSON = dumpJSON(seed["auth_modes"])
		item.FieldsJSON = dumpJSON(seed["fields"])
		if strings.TrimSpace(item.MetadataJSON) == "" {
			item.MetadataJSON = "{}"
		}
		db.Save(&item)
	}
}

func markInterrupted(db *gorm.DB) {
	reason := "服务重启，任务已中断"
	var tasks []Task
	db.Where("status IN ?", []string{"pending", "claimed", "running", "cancel_requested"}).Find(&tasks)
	for _, task := range tasks {
		if !strings.HasPrefix(task.Type, "sunny_") {
			continue
		}
		payload := jsonMap(task.PayloadJSON)
		mailboxIDs := uintSlice(payload["mailbox_ids"])
		if len(mailboxIDs) == 0 {
			continue
		}
		db.Model(&SunnyMailbox{}).
			Where("id IN ? AND status IN ?", mailboxIDs, []string{"注册中", "登录刷新"}).
			Updates(map[string]any{"status": "失败", "last_error": reason, "updated_at": time.Now()})
	}
	db.Model(&Task{}).
		Where("status IN ?", []string{"pending", "claimed", "running", "cancel_requested"}).
		Updates(map[string]any{"status": "interrupted", "error": reason, "finished_at": time.Now(), "updated_at": time.Now()})
}
