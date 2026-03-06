package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"homeproxy-cli/internal/system"
)

type shareFeatures struct {
	WithQUIC bool `json:"with_quic"`
	WithUTLS bool `json:"with_utls"`
}

type parsedNode struct {
	Options map[string]string
	Lists   map[string][]string
}

var ssEncryptMethods = map[string]bool{
	"none":                          true,
	"aes-128-gcm":                   true,
	"aes-192-gcm":                   true,
	"aes-256-gcm":                   true,
	"chacha20-ietf-poly1305":        true,
	"xchacha20-ietf-poly1305":       true,
	"2022-blake3-aes-128-gcm":       true,
	"2022-blake3-aes-256-gcm":       true,
	"2022-blake3-chacha20-poly1305": true,
	// Legacy stream ciphers accepted by UI.
	"aes-128-ctr":   true,
	"aes-192-ctr":   true,
	"aes-256-ctr":   true,
	"aes-128-cfb":   true,
	"aes-192-cfb":   true,
	"aes-256-cfb":   true,
	"chacha20":      true,
	"chacha20-ietf": true,
	"rc4-md5":       true,
}

func loadShareFeatures() shareFeatures {
	// Keep parser available even when ubus is temporarily unavailable.
	out := shareFeatures{WithQUIC: true, WithUTLS: true}
	raw, err := system.UBUSCall(system.RPCObject, "singbox_get_features", map[string]any{})
	if err != nil {
		return out
	}
	_ = json.Unmarshal([]byte(raw), &out)
	if !out.WithQUIC && !out.WithUTLS {
		// If unmarshal produced all-zero due to shape mismatch, keep permissive defaults.
		return shareFeatures{WithQUIC: true, WithUTLS: true}
	}
	return out
}

func newParsedNode() *parsedNode {
	return &parsedNode{
		Options: map[string]string{},
		Lists:   map[string][]string{},
	}
}

func (n *parsedNode) set(k, v string) {
	if strings.TrimSpace(v) == "" {
		return
	}
	n.Options[k] = v
}

func (n *parsedNode) setListCSV(k, v string) {
	if strings.TrimSpace(v) == "" {
		return
	}
	items := splitCSV(v)
	if len(items) > 0 {
		n.Lists[k] = items
	}
}

func (n *parsedNode) normalize() bool {
	addr := strings.TrimSpace(n.Options["address"])
	port := strings.TrimSpace(n.Options["port"])
	if addr == "" || port == "" {
		return false
	}
	addr = strings.TrimPrefix(strings.TrimSuffix(addr, "]"), "[")
	n.Options["address"] = addr
	if strings.TrimSpace(n.Options["label"]) == "" {
		n.Options["label"] = addr + ":" + port
	}
	return true
}

func parseShareLink(raw string, f shareFeatures) *parsedNode {
	raw = strings.TrimSpace(raw)
	parts := strings.SplitN(raw, "://", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return nil
	}

	scheme := strings.ToLower(parts[0])
	rest := parts[1]
	n := newParsedNode()

	parseAsHTTP := func(v string) (*url.URL, url.Values, bool) {
		u, err := url.Parse("http://" + v)
		if err != nil || u.Hostname() == "" {
			return nil, nil, false
		}
		return u, u.Query(), true
	}

	switch scheme {
	case "anytls":
		u, q, ok := parseAsHTTP(rest)
		if !ok || u.User == nil || decodeURIComponentSafe(u.User.Username()) == "" {
			return nil
		}
		n.set("label", decodeURIComponentSafe(u.Fragment))
		n.set("type", "anytls")
		n.set("address", u.Hostname())
		n.set("port", defaultPort(u.Port()))
		n.set("password", decodeURIComponentSafe(u.User.Username()))
		n.set("tls", "1")
		n.set("tls_sni", q.Get("sni"))
		if q.Get("insecure") == "1" {
			n.set("tls_insecure", "1")
		} else {
			n.set("tls_insecure", "0")
		}

	case "http", "https":
		u, _, ok := parseAsHTTP(rest)
		if !ok {
			return nil
		}
		n.set("label", decodeURIComponentSafe(u.Fragment))
		n.set("type", "http")
		n.set("address", u.Hostname())
		n.set("port", defaultPort(u.Port()))
		n.set("username", decodeURIComponentSafe(u.User.Username()))
		pw, _ := u.User.Password()
		n.set("password", decodeURIComponentSafe(pw))
		if scheme == "https" {
			n.set("tls", "1")
		} else {
			n.set("tls", "0")
		}

	case "hysteria":
		u, q, ok := parseAsHTTP(rest)
		if !ok || !f.WithQUIC {
			return nil
		}
		if p := q.Get("protocol"); p != "" && p != "udp" {
			return nil
		}
		n.set("label", decodeURIComponentSafe(u.Fragment))
		n.set("type", "hysteria")
		n.set("address", u.Hostname())
		n.set("port", defaultPort(u.Port()))
		n.set("hysteria_protocol", firstOr(q.Get("protocol"), "udp"))
		if q.Get("auth") != "" {
			n.set("hysteria_auth_type", "string")
		}
		n.set("hysteria_auth_payload", q.Get("auth"))
		n.set("hysteria_obfs_password", q.Get("obfsParam"))
		n.set("hysteria_down_mbps", q.Get("downmbps"))
		n.set("hysteria_up_mbps", q.Get("upmbps"))
		n.set("tls", "1")
		n.set("tls_sni", q.Get("peer"))
		n.setListCSV("tls_alpn", decodeURIComponentSafe(q.Get("alpn")))
		if q.Get("insecure") == "1" {
			n.set("tls_insecure", "1")
		} else {
			n.set("tls_insecure", "0")
		}

	case "hysteria2", "hy2":
		u, q, ok := parseAsHTTP(rest)
		if !ok || !f.WithQUIC {
			return nil
		}
		n.set("label", decodeURIComponentSafe(u.Fragment))
		n.set("type", "hysteria2")
		n.set("address", u.Hostname())
		n.set("port", defaultPort(u.Port()))
		if u.User != nil {
			user := decodeURIComponentSafe(u.User.Username())
			pw, hasPW := u.User.Password()
			if hasPW {
				n.set("password", user+":"+decodeURIComponentSafe(pw))
			} else {
				n.set("password", user)
			}
		}
		n.set("hysteria_obfs_type", q.Get("obfs"))
		n.set("hysteria_obfs_password", q.Get("obfs-password"))
		n.set("tls", "1")
		n.set("tls_sni", q.Get("sni"))
		if q.Get("insecure") != "" {
			n.set("tls_insecure", "1")
		} else {
			n.set("tls_insecure", "0")
		}

	case "socks", "socks4", "socks4a", "socsk5", "socks5h":
		u, _, ok := parseAsHTTP(rest)
		if !ok {
			return nil
		}
		n.set("label", decodeURIComponentSafe(u.Fragment))
		n.set("type", "socks")
		n.set("address", u.Hostname())
		n.set("port", defaultPort(u.Port()))
		n.set("username", decodeURIComponentSafe(u.User.Username()))
		pw, _ := u.User.Password()
		n.set("password", decodeURIComponentSafe(pw))
		if strings.Contains(scheme, "4") {
			n.set("socks_version", "4")
		} else {
			n.set("socks_version", "5")
		}

	case "ss":
		node := parseSSShareLink(rest)
		if node == nil {
			return nil
		}
		n = node

	case "trojan":
		u, q, ok := parseAsHTTP(rest)
		if !ok || u.User == nil || decodeURIComponentSafe(u.User.Username()) == "" {
			return nil
		}
		n.set("label", decodeURIComponentSafe(u.Fragment))
		n.set("type", "trojan")
		n.set("address", u.Hostname())
		n.set("port", defaultPort(u.Port()))
		n.set("password", decodeURIComponentSafe(u.User.Username()))
		transport := q.Get("type")
		if transport != "tcp" {
			n.set("transport", transport)
		}
		n.set("tls", "1")
		n.set("tls_sni", q.Get("sni"))
		switch transport {
		case "grpc":
			n.set("grpc_servicename", q.Get("serviceName"))
		case "ws":
			n.set("ws_host", decodeURIComponentSafe(q.Get("host")))
			wsPath := decodeURIComponentSafe(q.Get("path"))
			fillWSEarlyData(n, wsPath)
		}

	case "tuic":
		u, q, ok := parseAsHTTP(rest)
		if !ok || u.User == nil || u.User.Username() == "" {
			return nil
		}
		n.set("label", decodeURIComponentSafe(u.Fragment))
		n.set("type", "tuic")
		n.set("address", u.Hostname())
		n.set("port", defaultPort(u.Port()))
		n.set("uuid", u.User.Username())
		pw, _ := u.User.Password()
		n.set("password", decodeURIComponentSafe(pw))
		n.set("tuic_congestion_control", q.Get("congestion_control"))
		n.set("tuic_udp_relay_mode", q.Get("udp_relay_mode"))
		n.set("tls", "1")
		n.set("tls_sni", q.Get("sni"))
		n.setListCSV("tls_alpn", decodeURIComponentSafe(q.Get("alpn")))

	case "vless":
		u, q, ok := parseAsHTTP(rest)
		if !ok {
			return nil
		}
		transport := q.Get("type")
		security := q.Get("security")
		if transport == "kcp" {
			return nil
		}
		if transport == "quic" && ((q.Get("quicSecurity") != "" && q.Get("quicSecurity") != "none") || !f.WithQUIC) {
			return nil
		}
		if u.User == nil || u.User.Username() == "" || transport == "" {
			return nil
		}

		n.set("label", decodeURIComponentSafe(u.Fragment))
		n.set("type", "vless")
		n.set("address", u.Hostname())
		n.set("port", defaultPort(u.Port()))
		n.set("uuid", u.User.Username())
		if transport != "tcp" {
			n.set("transport", transport)
		}
		if security == "tls" || security == "xtls" || security == "reality" {
			n.set("tls", "1")
		} else {
			n.set("tls", "0")
		}
		n.set("tls_sni", q.Get("sni"))
		n.setListCSV("tls_alpn", decodeURIComponentSafe(q.Get("alpn")))
		if security == "reality" {
			n.set("tls_reality", "1")
		}
		n.set("tls_reality_public_key", decodeURIComponentSafe(q.Get("pbk")))
		n.set("tls_reality_short_id", q.Get("sid"))
		if f.WithUTLS {
			n.set("tls_utls", q.Get("fp"))
		}
		if security == "tls" || security == "reality" {
			n.set("vless_flow", q.Get("flow"))
		}
		switch transport {
		case "grpc":
			n.set("grpc_servicename", q.Get("serviceName"))
		case "http", "tcp":
			if transport == "http" || q.Get("headerType") == "http" {
				n.setListCSV("http_host", decodeURIComponentSafe(q.Get("host")))
				n.set("http_path", decodeURIComponentSafe(q.Get("path")))
			}
		case "httpupgrade":
			n.set("httpupgrade_host", decodeURIComponentSafe(q.Get("host")))
			n.set("http_path", decodeURIComponentSafe(q.Get("path")))
		case "ws":
			n.set("ws_host", decodeURIComponentSafe(q.Get("host")))
			wsPath := decodeURIComponentSafe(q.Get("path"))
			fillWSEarlyData(n, wsPath)
		}

	case "vmess":
		if strings.Contains(rest, "&") {
			return nil
		}
		vm, ok := parseVMessShare(rest, f)
		if !ok {
			return nil
		}
		n = vm
	default:
		return nil
	}

	if !n.normalize() {
		return nil
	}
	return n
}

func parseSSShareLink(rest string) *parsedNode {
	n := newParsedNode()
	working := rest

	// "Lovely" Shadowrocket format: base64(payload)#label
	if parts := strings.SplitN(working, "#", 2); len(parts) <= 2 {
		labelSuffix := ""
		if len(parts) == 2 {
			labelSuffix = "#" + parts[1]
		}
		if dec, err := decodeBase64URLSafe(parts[0]); err == nil {
			working = dec + labelSuffix
		}
	}

	if u, err := url.Parse("http://" + working); err == nil && u.Hostname() != "" {
		var method, password string
		if u.User != nil && u.User.Username() != "" {
			user := u.User.Username()
			pw, hasPW := u.User.Password()
			if hasPW {
				method = user
				password = decodeURIComponentSafe(pw)
			} else if dec, err := decodeBase64URLSafe(decodeURIComponentSafe(user)); err == nil {
				p := strings.Split(dec, ":")
				if len(p) > 1 {
					method = p[0]
					password = strings.Join(p[1:], ":")
				}
			}
		}
		if !ssEncryptMethods[method] {
			return nil
		}

		n.set("label", decodeURIComponentSafe(u.Fragment))
		n.set("type", "shadowsocks")
		n.set("address", u.Hostname())
		n.set("port", defaultPort(u.Port()))
		n.set("shadowsocks_encrypt_method", method)
		n.set("password", password)

		if pluginRaw := u.Query().Get("plugin"); pluginRaw != "" {
			pluginInfo := strings.Split(pluginRaw, ";")
			n.set("shadowsocks_plugin", pluginInfo[0])
			if len(pluginInfo) > 1 {
				n.set("shadowsocks_plugin_opts", strings.Join(pluginInfo[1:], ";"))
			}
		}
		return n
	}

	// Legacy format: method:password@server:port
	parts := strings.Split(working, "@")
	if len(parts) < 2 {
		return nil
	}
	if len(parts) > 2 {
		parts = []string{strings.Join(parts[:len(parts)-1], "@"), parts[len(parts)-1]}
	}
	host := strings.Split(parts[1], ":")
	if len(host) < 2 {
		return nil
	}
	methodPassword := strings.Split(parts[0], ":")
	if len(methodPassword) < 2 {
		return nil
	}
	method := methodPassword[0]
	if !ssEncryptMethods[method] {
		return nil
	}
	n.set("type", "shadowsocks")
	n.set("address", host[0])
	n.set("port", host[1])
	n.set("shadowsocks_encrypt_method", method)
	n.set("password", strings.Join(methodPassword[1:], ":"))
	return n
}

func parseVMessShare(rest string, f shareFeatures) (*parsedNode, bool) {
	payload, err := decodeBase64URLSafe(rest)
	if err != nil {
		return nil, false
	}

	var vm map[string]any
	if err := json.Unmarshal([]byte(payload), &vm); err != nil {
		return nil, false
	}

	get := func(k string) string {
		v, ok := vm[k]
		if !ok || v == nil {
			return ""
		}
		switch t := v.(type) {
		case string:
			return t
		case float64:
			if float64(int64(t)) == t {
				return fmt.Sprintf("%d", int64(t))
			}
			return fmt.Sprintf("%v", t)
		default:
			return fmt.Sprintf("%v", t)
		}
	}

	v := get("v")
	net := get("net")
	vtype := get("type")
	if v != "2" {
		return nil, false
	}
	if net == "kcp" {
		return nil, false
	}
	if net == "quic" && ((vtype != "" && vtype != "none") || !f.WithQUIC) {
		return nil, false
	}

	n := newParsedNode()
	n.set("label", get("ps"))
	n.set("type", "vmess")
	n.set("address", get("add"))
	n.set("port", get("port"))
	n.set("uuid", get("id"))
	n.set("vmess_alterid", get("aid"))
	n.set("vmess_encrypt", firstOr(get("scy"), "auto"))
	if net != "tcp" {
		n.set("transport", net)
	}
	if get("tls") == "tls" {
		n.set("tls", "1")
	} else {
		n.set("tls", "0")
	}
	n.set("tls_sni", firstOr(get("sni"), get("host")))
	n.setListCSV("tls_alpn", get("alpn"))
	if f.WithUTLS {
		n.set("tls_utls", get("fp"))
	}

	switch net {
	case "grpc":
		n.set("grpc_servicename", get("path"))
	case "h2", "tcp":
		if net == "h2" || vtype == "http" {
			n.set("transport", "http")
			n.setListCSV("http_host", get("host"))
			n.set("http_path", get("path"))
		}
	case "httpupgrade":
		n.set("httpupgrade_host", get("host"))
		n.set("http_path", get("path"))
	case "ws":
		n.set("ws_host", get("host"))
		fillWSEarlyData(n, get("path"))
	}
	return n, true
}

func decodeBase64URLSafe(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", fmt.Errorf("empty base64 input")
	}
	s = strings.ReplaceAll(s, "-", "+")
	s = strings.ReplaceAll(s, "_", "/")
	if m := len(s) % 4; m != 0 {
		s += strings.Repeat("=", 4-m)
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func decodeURIComponentSafe(s string) string {
	if s == "" {
		return ""
	}
	if v, err := url.QueryUnescape(s); err == nil {
		return v
	}
	return s
}

func firstOr(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

func defaultPort(v string) string {
	if strings.TrimSpace(v) == "" {
		return "80"
	}
	return v
}

func splitCSV(v string) []string {
	raw := strings.Split(v, ",")
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		t := strings.TrimSpace(item)
		if t != "" {
			out = append(out, t)
		}
	}
	return out
}

func fillWSEarlyData(n *parsedNode, wsPath string) {
	n.set("ws_path", wsPath)
	if wsPath == "" || !strings.Contains(wsPath, "?ed=") {
		return
	}
	parts := strings.SplitN(wsPath, "?ed=", 2)
	n.set("websocket_early_data_header", "Sec-WebSocket-Protocol")
	n.set("websocket_early_data", parts[1])
	n.set("ws_path", parts[0])
}

func parseImportLines(raw []string) []string {
	lines := make([]string, 0, len(raw))
	seen := map[string]bool{}
	for _, arg := range raw {
		for _, line := range strings.Split(arg, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || seen[line] {
				continue
			}
			seen[line] = true
			lines = append(lines, line)
		}
	}
	return lines
}

func looksLikeSubscriptionURL(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	if u.Host == "" {
		return false
	}
	// Keep old `node import <url>` behavior for typical subscription URLs.
	if u.User == nil && u.Fragment == "" {
		return true
	}
	return false
}

func applyParsedNodeToUCI(node *parsedNode) error {
	if err := system.UCIAdd("homeproxy", "node"); err != nil {
		return err
	}

	// deterministic order for reproducible writes
	keys := make([]string, 0, len(node.Options))
	for k := range node.Options {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if err := system.UCISet("homeproxy.@node[-1]."+k, node.Options[k]); err != nil {
			return err
		}
	}

	listKeys := make([]string, 0, len(node.Lists))
	for k := range node.Lists {
		listKeys = append(listKeys, k)
	}
	sort.Strings(listKeys)
	for _, k := range listKeys {
		for _, v := range node.Lists[k] {
			if err := system.UCIAddList("homeproxy.@node[-1]."+k, v); err != nil {
				return err
			}
		}
	}
	return nil
}
