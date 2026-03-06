package testutil

import (
	"encoding/json"
	"strings"
	"sync"
)

// MockRunner is a command runner that returns LuCI API contract responses.
// It records all calls for contract tests.
type MockRunner struct {
	mu     sync.Mutex
	Calls  []Call
	Status string // init.d status: "running" or ""
}

// Reset clears recorded calls.
func (m *MockRunner) Reset() {
	m.mu.Lock()
	m.Calls = nil
	m.mu.Unlock()
}

// FindUbusCall returns the first ubus call matching the method, or nil.
func (m *MockRunner) FindUbusCall(method string) *Call {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.Calls {
		c := &m.Calls[i]
		if c.Name == "ubus" && len(c.Args) >= 3 && c.Args[2] == method {
			return c
		}
	}
	return nil
}

// Call records one command invocation.
type Call struct {
	Name string
	Args []string
}

// Run implements the command runner signature and records each call.
func (m *MockRunner) Run(name string, args ...string) (string, error) {
	m.mu.Lock()
	m.Calls = append(m.Calls, Call{Name: name, Args: args})
	m.mu.Unlock()
	return m.response(name, args...)
}

func (m *MockRunner) response(name string, args ...string) (string, error) {
	switch name {
	case "/etc/init.d/homeproxy":
		if len(args) > 0 && args[0] == "status" {
			return m.Status, nil
		}
		return "", nil
	case "ubus":
		return m.ubusResponse(args)
	case "uci":
		return m.uciResponse(args)
	}
	return "", nil
}

func (m *MockRunner) ubusResponse(args []string) (string, error) {
	// ubus call luci.homeproxy <method> '<params>'
	if len(args) < 4 || args[0] != "call" || args[1] != "luci.homeproxy" {
		return "", nil
	}
	method := args[2]
	params := args[3]

	switch method {
	case "resources_get_version":
		return `{"version":"2024-01-01","error":null}`, nil
	case "resources_update":
		return `{"status":0}`, nil
	case "acllist_read":
		if strings.Contains(params, "direct_list") {
			return `{"content":"# direct list\n","error":""}`, nil
		}
		return `{"content":"# proxy list\n","error":""}`, nil
	case "connection_check":
		return `{"result":true}`, nil
	case "singbox_get_features":
		return `{"result":{"version":"1.9.0","with_quic":true,"with_grpc":true}}`, nil
	case "singbox_generator":
		var p struct {
			Type string `json:"type"`
		}
		_ = json.Unmarshal([]byte(params), &p)
		if p.Type == "uuid" {
			return `{"result":{"uuid":"xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"}}`, nil
		}
		return `{"result":{"private_key":"x","public_key":"y"}}`, nil
	case "log_clean":
		return `{"result":true}`, nil
	case "acllist_write":
		return `{"result":true}`, nil
	case "certificate_write":
		return `{"result":true}`, nil
	}
	return "", nil
}

func (m *MockRunner) uciResponse(args []string) (string, error) {
	if len(args) == 0 {
		return "", nil
	}
	switch args[0] {
	case "get":
		if len(args) < 2 {
			return "", nil
		}
		path := args[1]
		switch path {
		case "homeproxy.config.main_node":
			return "", nil
		case "homeproxy.config.routing_mode":
			return "bypass_mainland_china", nil
		case "homeproxy.@node[0].label":
			return "Test Node", nil
		}
		if strings.HasPrefix(path, "homeproxy.") && strings.Contains(path, ".label") {
			return "node1", nil
		}
		return "", nil
	case "show":
		if len(args) > 1 && args[1] == "homeproxy" {
			return `package homeproxy
config homeproxy 'config'
	option main_node ''
	option routing_mode 'bypass_mainland_china'
`, nil
		}
		return "", nil
	case "set", "add_list", "add", "delete", "commit":
		return "", nil
	}
	return "", nil
}
