package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func TestNormalizeSunnyProxyPurposes(t *testing.T) {
	got := normalizeSunnyProxyPurposes([]any{"trial", "register", "checkout", "payment", "unknown"})
	if strings.Join(got, ",") != "commerce,register,payment_probe" {
		t.Fatalf("purposes=%v", got)
	}
}

func TestSunnyProxyEmptyPurposeIsPersistedAndExcludedFromTasks(t *testing.T) {
	s := newSunnySessionTestServer(t)
	s.sunnySaveConfig(sunnyCfgProxy, mergeConfig(defaultProxyConfig(), map[string]any{"proxy_enabled": true}))
	unused := SunnyProxy{
		Address: "http://unused.example:8080", PurposeTags: sunnyProxyPurposeRegister,
		Status: "enabled", Enabled: true, LastCheckOK: true,
	}
	register := SunnyProxy{
		Address: "http://register.example:8080", PurposeTags: sunnyProxyPurposeRegister,
		Country: "JP", Status: "enabled", Enabled: true, LastCheckOK: true,
	}
	if err := s.db.Create(&[]*SunnyProxy{&unused, &register}).Error; err != nil {
		t.Fatalf("create proxies: %v", err)
	}

	id := strconv.FormatUint(uint64(unused.ID), 10)
	req := httptest.NewRequest(http.MethodPut, "/api/sunny/proxy-config/pool/"+id, strings.NewReader(`{"purpose_tags":[]}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.sunnyProxyPool(rec, req, []string{id})
	if rec.Code != http.StatusOK {
		t.Fatalf("clear purpose status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var response map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	tags, ok := response["purpose_tags"].([]any)
	if !ok || len(tags) != 0 {
		t.Fatalf("response purpose_tags = %#v", response["purpose_tags"])
	}
	if err := s.db.First(&unused, unused.ID).Error; err != nil {
		t.Fatalf("reload unused proxy: %v", err)
	}
	if unused.PurposeTags != "" {
		t.Fatalf("stored purpose_tags = %q", unused.PurposeTags)
	}

	snapshot := s.sunnyTaskProxySnapshot(map[string]any{})
	pool, ok := snapshot["proxy_pool"].([]string)
	if !ok || len(pool) != 1 || pool[0] != register.Address {
		t.Fatalf("task proxy_pool = %#v", snapshot["proxy_pool"])
	}
	ids, ok := snapshot["proxy_ids"].([]uint)
	if !ok || len(ids) != 1 || ids[0] != register.ID {
		t.Fatalf("task proxy_ids = %#v", snapshot["proxy_ids"])
	}
	proxyCountries, ok := snapshot["proxy_countries"].([]string)
	if !ok || len(proxyCountries) != 1 || proxyCountries[0] != "JP" {
		t.Fatalf("task proxy_countries = %#v", snapshot["proxy_countries"])
	}
}

func TestSunnyProxyCreatePreservesExplicitEmptyPurpose(t *testing.T) {
	s := newSunnySessionTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/sunny/proxy-config/pool", strings.NewReader(`{
		"addresses":["http://unused-new.example:8080"],
		"country":"US",
		"purpose_tags":[],
		"status":"停用",
		"enabled":false
	}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.sunnyProxyPool(rec, req, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("create empty-purpose proxy status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var response map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	tags, ok := response["purpose_tags"].([]any)
	if !ok || len(tags) != 0 {
		t.Fatalf("response purpose_tags = %#v", response["purpose_tags"])
	}
	var proxy SunnyProxy
	if err := s.db.First(&proxy, "address = ?", "http://unused-new.example:8080").Error; err != nil {
		t.Fatalf("reload proxy: %v", err)
	}
	if proxy.PurposeTags != "" {
		t.Fatalf("stored purpose_tags = %q", proxy.PurposeTags)
	}
}

func TestSunnyCommerceProxyURLPrefersCheckoutCountryAndPurpose(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:"+strings.ReplaceAll(t.Name(), "/", "-")+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&SunnyProxy{}); err != nil {
		t.Fatal(err)
	}
	rows := []SunnyProxy{
		{Address: "http://register.example:8080", Country: "US", PurposeTags: "register", Status: "enabled", Enabled: true, LastCheckOK: true},
		{Address: "http://commerce-de.example:8080", Country: "DE", PurposeTags: "commerce", Status: "enabled", Enabled: true, LastCheckOK: true},
		{Address: "http://commerce-us.example:8080", Country: "US", PurposeTags: "commerce", Status: "enabled", Enabled: true, LastCheckOK: true},
	}
	if err := db.Create(&rows).Error; err != nil {
		t.Fatal(err)
	}
	t.Setenv("SUNNY_CHECKOUT_COUNTRY", "US")
	server := &Server{db: db}
	if got := server.sunnyCommerceProxyURL("account@example.com"); got != "http://commerce-us.example:8080" {
		t.Fatalf("proxy=%q", got)
	}
	if got := server.sunnyRegisterProxyURL("account@example.com"); got != "http://register.example:8080" {
		t.Fatalf("register proxy=%q", got)
	}
}

func TestSunnyCommerceProbeRouteMatchesFallbackProxyCountry(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:"+strings.ReplaceAll(t.Name(), "/", "-")+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&SunnyProxy{}); err != nil {
		t.Fatal(err)
	}
	proxy := SunnyProxy{Address: "http://commerce-vn.example:8080", Country: "VN", PurposeTags: "commerce", Status: "enabled", Enabled: true, LastCheckOK: true}
	if err := db.Create(&proxy).Error; err != nil {
		t.Fatal(err)
	}
	t.Setenv("SUNNY_CHECKOUT_COUNTRY", "US")
	t.Setenv("SUNNY_CHECKOUT_CURRENCY", "USD")
	server := &Server{db: db}
	address, country, currency := server.sunnyCommerceProbeRoute("account@example.com")
	if address != proxy.Address || country != "VN" || currency != "VND" {
		t.Fatalf("route=%q %s/%s", address, country, currency)
	}
}
