package main

import (
	"fmt"
	"sort"
	"strings"
)

func (s *Server) createSunnyRebindTask(body map[string]any) (Task, error) {
	cfg := mergeConfig(defaultDomainMailboxConfig(), s.sunnyGetConfig(sunnyCfgDomainMailbox, defaultDomainMailboxConfig()))
	if !boolValue(cfg["enabled"], true) {
		return Task{}, fmt.Errorf("自建域名邮箱池已关闭，请先在邮箱配置中启用")
	}
	if !boolValue(cfg["enabled_for_rebinding"], false) {
		return Task{}, fmt.Errorf("自建域名邮箱未启用邮箱换绑，请先在邮箱配置中启用")
	}
	if strings.TrimSpace(text(cfg["base_url"])) == "" || strings.TrimSpace(text(cfg["auth_token"])) == "" || strings.TrimSpace(text(cfg["site_password"])) == "" || strings.TrimSpace(text(cfg["domain"])) == "" {
		return Task{}, fmt.Errorf("自建域名邮箱配置不完整，请先配置 CloudMail API、PUBLIC_API_TOKEN、PASSWORDS 和域名")
	}
	if _, err := domainMailboxPickupBaseURL(cfg); err != nil {
		return Task{}, err
	}
	sessionIDs := uintSlice(body["session_ids"])
	accountIDs := uintSlice(body["account_ids"])
	if len(accountIDs) == 0 && len(sessionIDs) > 0 {
		var sessions []SunnySession
		if err := s.db.Select("id", "account_id", "email").Where("id IN ?", sessionIDs).Find(&sessions).Error; err != nil {
			return Task{}, err
		}
		seen := map[uint]bool{}
		for _, session := range sessions {
			accountID := session.AccountID
			if accountID == 0 {
				var account SunnyAccount
				if s.db.Select("id").Where("LOWER(email) = ?", sunnyEmailKey(session.Email)).First(&account).Error == nil {
					accountID = account.ID
				}
			}
			if accountID != 0 && !seen[accountID] {
				seen[accountID] = true
				accountIDs = append(accountIDs, accountID)
			}
		}
	}
	if len(accountIDs) == 0 {
		return Task{}, fmt.Errorf("请选择需要换绑的账户")
	}
	body["account_ids"] = accountIDs
	body["session_ids"] = sessionIDs
	body["concurrency"] = s.sunnyRebindConcurrency()
	body = s.sunnyTaskProxySnapshot(body)
	nextBody, err := s.sunnyApplyCountriesToProxyPool(body, s.sunnyRebindProxyPoolForCountries)
	if err != nil {
		return Task{}, err
	}
	return s.createTask("sunny_rebind", "sunny", nextBody, len(accountIDs)), nil
}

// sunnyApplyCountriesToProxyPool pins the task's proxy pool to the requested
// countries when body["countries"] is present and non-empty. countryPoolFor
// returns the flattened pool, proxy ids, per-proxy countries (index-aligned
// with the pool) and the normalized country list for the selected countries.
// The worker rotates through payload["proxy_pool"], so filtering it here makes
// the task only use proxies of the chosen countries.
func (s *Server) sunnyApplyCountriesToProxyPool(body map[string]any, countryPoolFor func([]string) ([]string, []uint, []string, []string, error)) (map[string]any, error) {
	rawCountries, exists := body["countries"]
	if !exists {
		return body, nil
	}
	requested := stringSlice(rawCountries)
	if len(requested) == 0 {
		return body, nil
	}
	pool, ids, countries, proxyCountries, err := countryPoolFor(requested)
	if err != nil {
		return body, err
	}
	if len(pool) > 0 {
		body["proxy_pool"] = pool
		body["proxy_ids"] = ids
		body["proxy_countries"] = proxyCountries
		body["proxy_pool_size"] = len(pool)
		body["register_proxy"] = pool[0]
		body["proxy"] = pool[0]
	}
	body["countries"] = countries
	return body, nil
}

// sunnyPurposeProxyGroups returns the enabled proxies of the given purpose
// grouped by their validated country code. The country list is intentionally
// derived from the configured pool instead of being hard-coded in the UI or API.
func (s *Server) sunnyPurposeProxyGroups(purpose string, purposeLabel string) (map[string][]SunnyProxy, error) {
	var proxies []SunnyProxy
	purposeQuery := "(',' || replace(lower(coalesce(purpose_tags, '')), ' ', '') || ',') LIKE ?"
	if err := s.db.Where("status = ? AND enabled = ?", "enabled", true).
		Where(purposeQuery, "%,"+purpose+",%").Order("id asc").Find(&proxies).Error; err != nil {
		return nil, err
	}
	groups := map[string][]SunnyProxy{}
	for _, proxy := range proxies {
		country, err := normalizeSunnyProxyCountry(proxy.Country)
		if err == nil && normalizeSunnyProxyAddress(proxy.Address) != "" {
			groups[country] = append(groups[country], proxy)
		}
	}
	if len(groups) == 0 {
		return nil, fmt.Errorf("请先为%s用途配置至少一个已启用且国家代码有效的代理", purposeLabel)
	}
	return groups, nil
}

// sunnyRebindProxyGroups returns the enabled register-purpose proxies grouped
// by their validated country code. Rebind traffic uses the same register/login
// proxy pool as registration, so country selection is derived from it.
func (s *Server) sunnyRebindProxyGroups() (map[string][]SunnyProxy, error) {
	return s.sunnyPurposeProxyGroups(sunnyProxyPurposeRegister, "换绑")
}

func sunnyRebindProxyCountryList(groups map[string][]SunnyProxy) []string {
	countries := make([]string, 0, len(groups))
	for country := range groups {
		countries = append(countries, country)
	}
	sort.Strings(countries)
	return countries
}

// sunnyPurposeProxyPoolForCountries validates the requested countries against
// the proxy pool of the given purpose and returns the flattened proxy
// addresses, proxy ids, per-proxy countries (index-aligned with pool) and the
// normalized country list to pin a task to.
func (s *Server) sunnyPurposeProxyPoolForCountries(requested []string, purpose string, purposeLabel string) ([]string, []uint, []string, []string, error) {
	groups, err := s.sunnyPurposeProxyGroups(purpose, purposeLabel)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	seen := map[string]bool{}
	selected := make([]string, 0, len(requested))
	pool := make([]string, 0)
	ids := make([]uint, 0)
	countries := make([]string, 0)
	for _, value := range requested {
		country, err := normalizeSunnyProxyCountry(value)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		if seen[country] {
			continue
		}
		proxies := groups[country]
		if len(proxies) == 0 {
			return nil, nil, nil, nil, fmt.Errorf("国家 %s 没有已启用的%s代理", country, purposeLabel)
		}
		seen[country] = true
		selected = append(selected, country)
		for _, proxy := range proxies {
			address := normalizeSunnyProxyAddress(proxy.Address)
			if address != "" {
				pool = append(pool, address)
				ids = append(ids, proxy.ID)
				countries = append(countries, country)
			}
		}
	}
	if len(selected) == 0 {
		return nil, nil, nil, nil, fmt.Errorf("请至少选择一个%s国家", purposeLabel)
	}
	return pool, ids, selected, countries, nil
}

// sunnyRebindProxyPoolForCountries validates the requested countries against
// the register-purpose proxy pool and returns the flattened proxy addresses,
// proxy ids, per-proxy countries and the normalized country list to pin this
// rebind task to.
func (s *Server) sunnyRebindProxyPoolForCountries(requested []string) ([]string, []uint, []string, []string, error) {
	return s.sunnyPurposeProxyPoolForCountries(requested, sunnyProxyPurposeRegister, "换绑")
}
