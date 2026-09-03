package main

import "testing"

func TestNormalizeSunnyProxyAddressUsesKookeeySocksProtocol(t *testing.T) {
	if got := normalizeSunnyProxyAddress("gate.kookeey.info:1000:user:password-DE-session"); got != "socks5h://user:password-DE-session@gate.kookeey.info:1000" {
		t.Fatalf("proxy = %q", got)
	}
}

func TestNormalizeSunnyProxyAddressRewritesKookeeyHTTPScheme(t *testing.T) {
	if got := normalizeSunnyProxyAddress("http://user:password-S@gate.kookeey.info:1086"); got != "socks5h://user:password-S@gate.kookeey.info:1086" {
		t.Fatalf("proxy = %q", got)
	}
}

func TestNormalizeSunnyProxyAddressKeepsKookeeyOtherPortHTTP(t *testing.T) {
	if got := normalizeSunnyProxyAddress("http://user:pass@gate.kookeey.info:8080"); got != "http://user:pass@gate.kookeey.info:8080" {
		t.Fatalf("proxy = %q", got)
	}
}

func TestNormalizeSunnyProxyAddressKeepsOrdinaryHTTPProtocol(t *testing.T) {
	if got := normalizeSunnyProxyAddress("proxy.example.com:8080:user:password"); got != "http://user:password@proxy.example.com:8080" {
		t.Fatalf("proxy = %q", got)
	}
}
