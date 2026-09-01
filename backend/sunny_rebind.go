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
	if rawCountries, exists := body["countries"]; exists {
		requested := stringSlice(rawCountries)
		if len(requested) > 0 {
			pool, ids, countries, err := s.sunnyRebindProxyPoolForCountries(requested)
			if err != nil {
				return Task{}, err
			}
			if len(pool) > 0 {
				body["proxy_pool"] = pool
				body["proxy_ids"] = ids
				body["proxy_pool_size"] = len(pool)
				body["register_proxy"] = pool[0]
				body["proxy"] = pool[0]
			}
			body["countries"] = countries
		}
	}
	return s.createTask("sunny_rebind", "sunny", body, len(accountIDs)), nil
}

// sunnyRebindProxyGroups returns the enabled register-purpose proxies grouped
// by their validated country code. Rebind traffic uses the same register/login
// proxy pool as registration, so country selection is derived from it.
func (s *Server) sunnyRebindProxyGroups() (map[string][]SunnyProxy, error) {
	var proxies []SunnyProxy
	purposeQuery := "(',' || replace(lower(coalesce(purpose_tags, '')), ' ', '') || ',') LIKE ?"
	if err := s.db.Where("status = ? AND enabled = ?", "enabled", true).
		Where(purposeQuery, "%,"+sunnyProxyPurposeRegister+",%").Order("id asc").Find(&proxies).Error; err != nil {
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
		return nil, fmt.Errorf("请先为换绑用途配置至少一个已启用且国家代码有效的代理")
	}
	return groups, nil
}

func sunnyRebindProxyCountryList(groups map[string][]SunnyProxy) []string {
	countries := make([]string, 0, len(groups))
	for country := range groups {
		countries = append(countries, country)
	}
	sort.Strings(countries)
	return countries
}

// sunnyRebindProxyPoolForCountries validates the requested countries against
// the register-purpose proxy pool and returns the flattened proxy addresses,
// proxy ids and the normalized country list to pin this rebind task to.
func (s *Server) sunnyRebindProxyPoolForCountries(requested []string) ([]string, []uint, []string, error) {
	groups, err := s.sunnyRebindProxyGroups()
	if err != nil {
		return nil, nil, nil, err
	}
	seen := map[string]bool{}
	selected := make([]string, 0, len(requested))
	pool := make([]string, 0)
	ids := make([]uint, 0)
	for _, value := range requested {
		country, err := normalizeSunnyProxyCountry(value)
		if err != nil {
			return nil, nil, nil, err
		}
		if seen[country] {
			continue
		}
		proxies := groups[country]
		if len(proxies) == 0 {
			return nil, nil, nil, fmt.Errorf("国家 %s 没有已启用的换绑代理", country)
		}
		seen[country] = true
		selected = append(selected, country)
		for _, proxy := range proxies {
			address := normalizeSunnyProxyAddress(proxy.Address)
			if address != "" {
				pool = append(pool, address)
				ids = append(ids, proxy.ID)
			}
		}
	}
	if len(selected) == 0 {
		return nil, nil, nil, fmt.Errorf("请至少选择一个换绑国家")
	}
	return pool, ids, selected, nil
}
