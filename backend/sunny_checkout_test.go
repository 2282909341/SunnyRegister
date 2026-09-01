package main

import (
	"fmt"
	"strings"
	"testing"
)

func TestSplitCheckoutPoolNormalizesAndLimits(t *testing.T) {
	items, err := splitCheckoutPool("http://127.0.0.1:8000\nhttp://127.0.0.1:8000\n")
	if err != nil || len(items) != 1 || items[0] != "http://127.0.0.1:8000" {
		t.Fatalf("pool=%#v err=%v", items, err)
	}
	if _, err := splitCheckoutPool(""); err == nil {
		t.Fatal("empty pool should fail")
	}
	items, err = splitCheckoutPool("host:8080:user:pass\nuser:pass@host:8080\nsocks5://host:1080")
	if err != nil || len(items) != 2 || !strings.Contains(items[0], "http://user:pass@host:8080") {
		t.Fatalf("credential proxy normalization=%#v err=%v", items, err)
	}
}

func TestCheckoutProviderDefaultsIncludeAllCurrentPaths(t *testing.T) {
	if len(checkoutProviders) != 12 {
		t.Fatalf("providers=%d", len(checkoutProviders))
	}
	for _, value := range []string{"hosted", "ph_short", "paypal", "ideal", "twint", "upi", "pix", "momo", "gcash", "gopay", "blik", "kakao"} {
		country, currency := checkoutProviderDefaults(value)
		if country == "" || currency == "" {
			t.Fatalf("missing defaults for %s", value)
		}
	}
}

func TestBlikProviderDefaultsToPoland(t *testing.T) {
	country, currency := checkoutProviderDefaults("blik")
	if country != "PL" || currency != "PLN" {
		t.Fatalf("BLIK defaults=%s/%s", country, currency)
	}
}

func TestGoPayProviderDefaultsToIndonesia(t *testing.T) {
	country, currency := checkoutProviderDefaults("gopay")
	if country != "ID" || currency != "IDR" {
		t.Fatalf("GoPay defaults=%s/%s", country, currency)
	}
}

func TestNormalizeCheckoutPrecheckBillingUsesMomoRegion(t *testing.T) {
	country, currency, err := normalizeCheckoutPrecheckBilling("vn", "vnd")
	if err != nil || country != "VN" || currency != "VND" {
		t.Fatalf("MOMO precheck billing=%s/%s err=%v", country, currency, err)
	}
	if _, _, err := normalizeCheckoutPrecheckBilling("VN", "USD"); err == nil {
		t.Fatal("mismatched MOMO precheck currency should fail")
	}
}

func TestNormalizeGoPayRequestUsesIndonesiaCheckout(t *testing.T) {
	normalized, checkout, promotion, err := normalizeCheckoutRequest(sunnyCheckoutRequest{
		Plan:             "plus",
		LinkType:         "gopay",
		UsePromo:         true,
		Country:          "US",
		Currency:         "USD",
		CheckoutProxies:  "http://id-proxy.example:8080",
		PromotionProxies: "http://promo-proxy.example:8080",
	})
	if err != nil {
		t.Fatalf("normalize GoPay request: %v", err)
	}
	if normalized.Country != "ID" || normalized.Currency != "IDR" {
		t.Fatalf("unexpected GoPay region: %#v", normalized)
	}
	if len(checkout) != 1 || len(promotion) != 1 || checkout[0] == promotion[0] {
		t.Fatalf("checkout=%#v promotion=%#v", checkout, promotion)
	}
}

func TestNormalizeGCashRequestUsesSinglePHCheckoutPool(t *testing.T) {
	in := sunnyCheckoutRequest{
		Plan:             "plus",
		LinkType:         "gcash",
		Country:          "US",
		Currency:         "USD",
		CheckoutProxies:  "http://ph-proxy.example:8080",
		PromotionProxies: "http://vn-proxy.example:8080",
	}

	normalized, checkout, promotion, err := normalizeCheckoutRequest(in)
	if err != nil {
		t.Fatalf("normalize GCash request: %v", err)
	}
	if normalized.Country != "PH" || normalized.Currency != "PHP" || normalized.PromoCountry != "PH" {
		t.Fatalf("unexpected GCash region: %#v", normalized)
	}
	if len(checkout) != 1 || len(promotion) != 1 || checkout[0] != promotion[0] {
		t.Fatalf("checkout=%#v promotion=%#v", checkout, promotion)
	}
}

func TestNormalizeGCashRequestDoesNotRequirePromotionPool(t *testing.T) {
	_, checkout, promotion, err := normalizeCheckoutRequest(sunnyCheckoutRequest{
		Plan:            "plus",
		LinkType:        "gcash",
		CheckoutProxies: "http://ph-proxy.example:8080",
	})
	if err != nil {
		t.Fatalf("normalize GCash request without promotion pool: %v", err)
	}
	if len(checkout) != 1 || len(promotion) != 1 || checkout[0] != promotion[0] {
		t.Fatalf("checkout=%#v promotion=%#v", checkout, promotion)
	}
}

func TestNormalizeNoPromoRequestUsesCheckoutPoolForPromotion(t *testing.T) {
	normalized, checkout, promotion, err := normalizeCheckoutRequest(sunnyCheckoutRequest{
		Plan:            "plus",
		LinkType:        "momo",
		UsePromo:        false,
		CheckoutProxies: "http://vn-checkout-proxy.example:8080",
	})
	if err != nil {
		t.Fatalf("normalize no-promo MoMo request: %v", err)
	}
	if normalized.UsePromo {
		t.Fatal("no-promo request unexpectedly enabled promotion")
	}
	if len(checkout) != 1 || len(promotion) != 1 || checkout[0] != promotion[0] {
		t.Fatalf("checkout=%#v promotion=%#v", checkout, promotion)
	}
}

func TestNormalizePromoRequestStillRequiresPromotionPool(t *testing.T) {
	_, _, _, err := normalizeCheckoutRequest(sunnyCheckoutRequest{
		Plan:             "plus",
		LinkType:         "momo",
		UsePromo:         true,
		CheckoutProxies:  "http://vn-checkout-proxy.example:8080",
		PromotionProxies: "",
	})
	if err == nil || !strings.Contains(err.Error(), "Promotion 代理池") {
		t.Fatalf("expected promotion pool validation error, got %v", err)
	}
}

func TestParseCheckoutExternalAT(t *testing.T) {
	token, email := parseCheckoutExternalAT("eyJhbGciOiJub25lIn0.payload.signature user@example.com")
	if token == "" || email != "user@example.com" {
		t.Fatalf("token=%q email=%q", token, email)
	}
	token, email = parseCheckoutExternalAT(`{"access_token":"eyJabc.def.ghi","email":"json@example.com"}`)
	if token == "" || email != "json@example.com" {
		t.Fatalf("json token=%q email=%q", token, email)
	}
	if token, _ = parseCheckoutExternalAT("not-an-at"); token != "" {
		t.Fatalf("invalid token=%q", token)
	}
	if token, _ = parseCheckoutExternalAT(`{"access_token":"not.a.jwt"}`); token != "" {
		t.Fatalf("invalid JSON token=%q", token)
	}
	expired := "eyJhbGciOiJub25lIn0.eyJleHAiOjF9.signature user@example.com"
	if token, _ = parseCheckoutExternalAT(expired); token != "" {
		t.Fatal("expired JWT should be rejected")
	}
	expiredJSON := fmt.Sprintf(`{"access_token":%q,"email":"expired@example.com"}`, expired)
	if token, _ = parseCheckoutExternalAT(expiredJSON); token != "" {
		t.Fatal("expired JWT in JSON should be rejected")
	}
	profileToken := "eyJhbGciOiJub25lIn0.eyJodHRwczovL2FwaS5vcGVuYWkuY29tL3Byb2ZpbGUiOnsiZW1haWwiOiJwcm9maWxlQGV4YW1wbGUuY29tIn19.signature"
	if token, email = parseCheckoutExternalAT(profileToken); token == "" || email != "profile@example.com" {
		t.Fatalf("profile token=%q email=%q", token, email)
	}
}

func TestExtractSunnyCheckoutResult(t *testing.T) {
	result := extractSunnyCheckoutResult(map[string]any{"checkout_session_id": "cs_live_123", "redirect_url": "https://pay.example/approve", "qr_data": "upi://pay/x"}, "upi")
	if result["checkout_session_id"] != "cs_live_123" || result["payment_link"] != "https://pay.example/approve" || result["qr_data"] != "upi://pay/x" {
		t.Fatalf("result=%#v", result)
	}
}

func TestExtractSunnyCheckoutResultPrefersGoPayMidtransURL(t *testing.T) {
	midtrans := "https://app.midtrans.com/snap/v4/redirection/123e4567-e89b-12d3-a456-426614174000"
	result := extractSunnyCheckoutResult(map[string]any{
		"provider_redirect_url": midtrans,
		"verification_url":      "https://chatgpt.com/checkout/verify",
	}, "gopay")
	if result["payment_link"] != midtrans {
		t.Fatalf("result=%#v", result)
	}
	if isSunnyGopayMidtransURL("https://app.midtrans.com.evil.example/snap/v4/redirection/123e4567-e89b-12d3-a456-426614174000") {
		t.Fatal("lookalike Midtrans host must be rejected")
	}
}

func TestExtractSunnyCheckoutResultPrefersValidatedBlikURL(t *testing.T) {
	blikURL := "https://checkout.stripe.com/c/pay/cs_live_123#fidnandhYHdWcXxpYCc%2FJ2FgY2RwaXEn"
	result := extractSunnyCheckoutResult(map[string]any{
		"blik_payment_url": blikURL,
		"checkout_url":     "https://chatgpt.com/checkout/openai_ie/cs_live_123",
	}, "blik")
	if result["payment_link"] != blikURL {
		t.Fatalf("result=%#v", result)
	}
	if isSunnyBlikPaymentURL("https://chatgpt.com/checkout/openai_ie/cs_live_123") {
		t.Fatal("ordinary ChatGPT Checkout URL must not pass BLIK validation")
	}
	if isSunnyBlikPaymentURL("https://checkout.stripe.com/c/pay/cs_live_123?redirect_pm_type=blik&lid=generated&ui_mode=custom") {
		t.Fatal("legacy synthetic BLIK query parameters must be rejected")
	}
}

func TestRecordSunnyCheckoutResultPersistsPartialTaskItems(t *testing.T) {
	task := Task{Status: TaskRunning, ProgressTotal: 2, ResultJSON: "{}"}
	result := map[string]any{"requested": 2, "success": 0, "failed": 0, "items": []any{}}
	item := map[string]any{
		"email": "success@example.com", "status": "succeeded", "link_type": "paypal",
		"payment_link": "https://www.paypal.com/agreements/approve?ba_token=BA-test",
	}

	recordSunnyCheckoutResult(&task, result, item)

	serialized := serializeTask(task)
	partial := serialized["result"].(map[string]any)
	items := partial["items"].([]any)
	if len(items) != 1 || text(items[0].(map[string]any)["email"]) != "success@example.com" {
		t.Fatalf("partial task items=%#v", items)
	}
	if task.ProgressCurrent != 1 || task.SuccessCount != 1 || task.ErrorCount != 0 {
		t.Fatalf("task progress=%d success=%d failed=%d", task.ProgressCurrent, task.SuccessCount, task.ErrorCount)
	}
}
