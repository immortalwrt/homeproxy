package main

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestParseHY2ShareLink(t *testing.T) {
	f := shareFeatures{WithQUIC: true, WithUTLS: true}
	link := "hy2://geriZ1312nudfw8vx@192.3.252.16:40020?insecure=1&sni=www.bing.com#supfam03"
	n := parseShareLink(link, f)
	if n == nil {
		t.Fatalf("expected parsed node, got nil")
	}
	if n.Options["type"] != "hysteria2" {
		t.Fatalf("unexpected type: %q", n.Options["type"])
	}
	if n.Options["address"] != "192.3.252.16" || n.Options["port"] != "40020" {
		t.Fatalf("unexpected address/port: %s:%s", n.Options["address"], n.Options["port"])
	}
	if n.Options["password"] != "geriZ1312nudfw8vx" {
		t.Fatalf("unexpected password: %q", n.Options["password"])
	}
	if n.Options["tls_sni"] != "www.bing.com" {
		t.Fatalf("unexpected tls_sni: %q", n.Options["tls_sni"])
	}
	if n.Options["tls_insecure"] != "1" {
		t.Fatalf("unexpected tls_insecure: %q", n.Options["tls_insecure"])
	}
	if n.Options["label"] != "supfam03" {
		t.Fatalf("unexpected label: %q", n.Options["label"])
	}
}

func TestParseVMessShareLink(t *testing.T) {
	f := shareFeatures{WithQUIC: true, WithUTLS: true}
	vm := map[string]any{
		"v":    "2",
		"ps":   "vmess-test",
		"add":  "1.2.3.4",
		"port": "443",
		"id":   "f47ac10b-58cc-4372-a567-0e02b2c3d479",
		"aid":  "0",
		"net":  "ws",
		"type": "none",
		"host": "example.com",
		"path": "/ws?ed=2048",
		"tls":  "tls",
		"sni":  "example.com",
	}
	raw, _ := json.Marshal(vm)
	link := "vmess://" + base64.StdEncoding.EncodeToString(raw)
	n := parseShareLink(link, f)
	if n == nil {
		t.Fatalf("expected parsed vmess node, got nil")
	}
	if n.Options["type"] != "vmess" {
		t.Fatalf("unexpected type: %q", n.Options["type"])
	}
	if n.Options["transport"] != "ws" {
		t.Fatalf("unexpected transport: %q", n.Options["transport"])
	}
	if n.Options["ws_path"] != "/ws" {
		t.Fatalf("unexpected ws_path: %q", n.Options["ws_path"])
	}
	if n.Options["websocket_early_data"] != "2048" {
		t.Fatalf("unexpected early data: %q", n.Options["websocket_early_data"])
	}
}

func TestLooksLikeSubscriptionURL(t *testing.T) {
	if !looksLikeSubscriptionURL("https://example.com/sub?token=abc") {
		t.Fatal("expected true for plain https subscription url")
	}
	if looksLikeSubscriptionURL("https://user:pass@example.com:8443#node1") {
		t.Fatal("expected false for http(s) share link with credentials/fragment")
	}
	if looksLikeSubscriptionURL("hy2://abc@1.2.3.4:443") {
		t.Fatal("expected false for non-http subscription url")
	}
}
