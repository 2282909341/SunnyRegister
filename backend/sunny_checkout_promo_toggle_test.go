package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNormalizeCheckoutRequestNoPromoReusesCheckoutPool(t *testing.T) {
	_, checkout, promotion, err := normalizeCheckoutRequest(sunnyCheckoutRequest{
		Plan:            "plus",
		LinkType:        "momo",
		UsePromo:        false,
		CheckoutProxies: "http://vn-checkout.example:8080",
	})
	if err != nil {
		t.Fatalf("no-promo request should not require Promotion pool: %v", err)
	}
	if len(checkout) != 1 || len(promotion) != 1 || checkout[0] != promotion[0] {
		t.Fatalf("checkout=%#v promotion=%#v", checkout, promotion)
	}
}

func TestNormalizeCheckoutRequestPromoStillRequiresPromotionPool(t *testing.T) {
	_, _, _, err := normalizeCheckoutRequest(sunnyCheckoutRequest{
		Plan:            "plus",
		LinkType:        "momo",
		UsePromo:        true,
		CheckoutProxies: "http://vn-checkout.example:8080",
	})
	if err == nil || !strings.Contains(err.Error(), "Promotion 代理池") {
		t.Fatalf("expected Promotion pool validation error, got %v", err)
	}
}

func TestCheckSunnyCheckoutOnlySkipsPromotionProbe(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/checkout" {
			t.Fatalf("unexpected probe path %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"checkout_session":{"checkout_session_id":"oaics_probe_only","payment_method_types":["momo"]}}`))
	}))
	defer server.Close()
	previous := sunnyCheckoutEndpoint
	sunnyCheckoutEndpoint = server.URL + "/checkout"
	defer func() { sunnyCheckoutEndpoint = previous }()

	result := checkSunnyCheckoutOnly(context.Background(), "test-token", "")
	if result.CheckoutKind != "oaics" {
		t.Fatalf("checkout kind=%q, error=%q", result.CheckoutKind, result.CheckoutError)
	}
	if result.Eligibility != sunnyTrialUnknown {
		t.Fatalf("no-promo probe unexpectedly resolved eligibility=%q", result.Eligibility)
	}
	if len(result.PaymentMethods) != 1 || result.PaymentMethods[0] != "momo" {
		t.Fatalf("payment methods=%#v", result.PaymentMethods)
	}
}
