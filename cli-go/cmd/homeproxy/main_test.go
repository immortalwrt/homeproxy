package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	"homeproxy-cli/internal/system"
	"homeproxy-cli/testutil"
)


func withMock(t *testing.T, mock *testutil.MockRunner, fn func()) {
	t.Helper()
	oldRun := system.RunCommandImpl
	oldCheck := system.CheckInstalledFunc
	defer func() {
		system.RunCommandImpl = oldRun
		system.CheckInstalledFunc = oldCheck
	}()
	system.RunCommandImpl = mock.Run
	system.CheckInstalledFunc = func() error { return nil }
	fn()
}

func captureOutput(fn func() error) (stdout, stderr string, err error) {
	rOut, wOut, _ := os.Pipe()
	rErr, wErr, _ := os.Pipe()
	oldOut, oldErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = wOut, wErr
	err = fn()
	wOut.Close()
	wErr.Close()
	var bufOut, bufErr bytes.Buffer
	io.Copy(&bufOut, rOut)
	io.Copy(&bufErr, rErr)
	os.Stdout, os.Stderr = oldOut, oldErr
	return bufOut.String(), bufErr.String(), err
}

func TestHelp(t *testing.T) {
	stdout, _, err := captureOutput(func() error { return run([]string{}) })
	if err != nil {
		t.Fatalf("run([]): %v", err)
	}
	if !strings.Contains(stdout, "HomeProxy CLI") {
		t.Errorf("expected help header, got: %s", stdout)
	}

	stdout, _, err = captureOutput(func() error { return run([]string{"help"}) })
	if err != nil {
		t.Fatalf("run(help): %v", err)
	}
	if !strings.Contains(stdout, "Usage: homeproxy") {
		t.Errorf("expected usage, got: %s", stdout)
	}

	stdout, _, err = captureOutput(func() error { return run([]string{"-h"}) })
	if err != nil {
		t.Fatalf("run(-h): %v", err)
	}
	if !strings.Contains(stdout, "HomeProxy CLI") {
		t.Errorf("expected help with -h, got: %s", stdout)
	}
}

func TestStatus(t *testing.T) {
	mock := &testutil.MockRunner{Status: "running"}
	withMock(t, mock, func() {
		stdout, stderr, err := captureOutput(func() error { return run([]string{"status"}) })
		if err != nil {
			t.Fatalf("status: %v", err)
		}
		combined := stdout + stderr
		if !strings.Contains(combined, "RUNNING") {
			t.Errorf("expected RUNNING in output, got: %s", combined)
		}
	})
}

func TestStatusJSON(t *testing.T) {
	mock := &testutil.MockRunner{Status: "running"}
	withMock(t, mock, func() {
		stdout, stderr, err := captureOutput(func() error { return run([]string{"status", "--json"}) })
		if err != nil {
			t.Fatalf("status --json: %v", err)
		}
		if stderr != "" {
			t.Errorf("expected no stderr for --json, got: %s", stderr)
		}
		if !strings.Contains(stdout, `"service":"running"`) {
			t.Errorf("expected service in JSON, got: %s", stdout)
		}
		if !strings.Contains(stdout, `"main_node"`) || !strings.Contains(stdout, `"routing"`) {
			t.Errorf("expected main_node and routing in JSON, got: %s", stdout)
		}
	})
}

func TestFeatures(t *testing.T) {
	mock := &testutil.MockRunner{}
	withMock(t, mock, func() {
		stdout, _, err := captureOutput(func() error { return run([]string{"features"}) })
		if err != nil {
			t.Fatalf("features: %v", err)
		}
		if !strings.Contains(stdout, "1.9.0") {
			t.Errorf("expected version 1.9.0 in output, got: %s", stdout)
		}
	})
}

func TestResourcesVersion(t *testing.T) {
	mock := &testutil.MockRunner{}
	withMock(t, mock, func() {
		stdout, _, err := captureOutput(func() error { return run([]string{"resources", "version", "china_ip4"}) })
		if err != nil {
			t.Fatalf("resources version: %v", err)
		}
		if !strings.Contains(stdout, "2024-01-01") {
			t.Errorf("expected version 2024-01-01, got: %s", stdout)
		}
	})
}

func TestACLList(t *testing.T) {
	mock := &testutil.MockRunner{}
	withMock(t, mock, func() {
		stdout, _, err := captureOutput(func() error { return run([]string{"acl", "list", "direct_list"}) })
		if err != nil {
			t.Fatalf("acl list: %v", err)
		}
		if !strings.Contains(stdout, "direct list") {
			t.Errorf("expected direct list content, got: %s", stdout)
		}
	})
}

func TestGeneratorUUID(t *testing.T) {
	mock := &testutil.MockRunner{}
	withMock(t, mock, func() {
		stdout, _, err := captureOutput(func() error { return run([]string{"generator", "uuid"}) })
		if err != nil {
			t.Fatalf("generator uuid: %v", err)
		}
		if !strings.Contains(stdout, "uuid") || !strings.Contains(stdout, "xxxx") {
			t.Errorf("expected uuid output, got: %s", stdout)
		}
	})
}

func TestNodeListJSON(t *testing.T) {
	mock := &testutil.MockRunner{}
	withMock(t, mock, func() {
		stdout, stderr, err := captureOutput(func() error { return run([]string{"node", "list", "--json"}) })
		if err != nil {
			t.Fatalf("node list --json: %v", err)
		}
		if stderr != "" {
			t.Errorf("expected no stderr for --json, got: %s", stderr)
		}
		var out struct {
			Nodes []struct {
				Name   string `json:"name"`
				Status string `json:"status"`
			} `json:"nodes"`
		}
		if err := json.Unmarshal([]byte(stdout), &out); err != nil {
			t.Fatalf("invalid JSON: %v\noutput: %s", err, stdout)
		}
		// Structure must be valid; mock may return empty nodes
		if out.Nodes == nil {
			t.Errorf("expected nodes field (can be empty slice), got nil")
		}
	})
}

func TestSubscriptionListJSON(t *testing.T) {
	mock := &testutil.MockRunner{}
	withMock(t, mock, func() {
		stdout, stderr, err := captureOutput(func() error { return run([]string{"subscription", "list", "--json"}) })
		if err != nil {
			t.Fatalf("subscription list --json: %v", err)
		}
		if stderr != "" {
			t.Errorf("expected no stderr for --json, got: %s", stderr)
		}
		var out struct {
			Subscriptions []string `json:"subscriptions"`
		}
		if err := json.Unmarshal([]byte(stdout), &out); err != nil {
			t.Fatalf("invalid JSON: %v\noutput: %s", err, stdout)
		}
		// Mock may return empty list; structure must be valid
		if out.Subscriptions == nil {
			t.Errorf("expected subscriptions field (can be empty slice), got nil")
		}
	})
}

func TestUnknownCommand(t *testing.T) {
	_, _, err := captureOutput(func() error { return run([]string{"unknown"}) })
	if err == nil {
		t.Fatal("expected error for unknown command")
	}
	if !strings.Contains(err.Error(), "unknown command") {
		t.Errorf("expected 'unknown command' in error, got: %v", err)
	}
}

// Contract tests: verify CLI invokes ubus/uci with params matching the LuCI API contract.
func TestContractResourcesVersion(t *testing.T) {
	mock := &testutil.MockRunner{}
	withMock(t, mock, func() {
		_ = run([]string{"resources", "version", "china_ip4"})
		c := mock.FindUbusCall("resources_get_version")
		if c == nil {
			t.Fatal("expected ubus call luci.homeproxy resources_get_version")
		}
		if len(c.Args) < 4 {
			t.Fatalf("expected ubus call args with params, got %v", c.Args)
		}
		params := c.Args[3]
		if !strings.Contains(params, `"type":"china_ip4"`) {
			t.Errorf("expected params with type=china_ip4, got %s", params)
		}
	})
}

func TestContractACLList(t *testing.T) {
	mock := &testutil.MockRunner{}
	withMock(t, mock, func() {
		_ = run([]string{"acl", "list", "direct_list"})
		c := mock.FindUbusCall("acllist_read")
		if c == nil {
			t.Fatal("expected ubus call luci.homeproxy acllist_read")
		}
		params := c.Args[3]
		if !strings.Contains(params, `"type":"direct_list"`) {
			t.Errorf("expected params with type=direct_list, got %s", params)
		}
	})
}

func TestContractLogClean(t *testing.T) {
	mock := &testutil.MockRunner{}
	withMock(t, mock, func() {
		_ = run([]string{"log", "clean", "sing-box-c"})
		c := mock.FindUbusCall("log_clean")
		if c == nil {
			t.Fatal("expected ubus call luci.homeproxy log_clean")
		}
		params := c.Args[3]
		if !strings.Contains(params, `"type":"sing-box-c"`) {
			t.Errorf("expected params with type=sing-box-c, got %s", params)
		}
	})
}

func TestContractGeneratorUUID(t *testing.T) {
	mock := &testutil.MockRunner{}
	withMock(t, mock, func() {
		_ = run([]string{"generator", "uuid"})
		c := mock.FindUbusCall("singbox_generator")
		if c == nil {
			t.Fatal("expected ubus call luci.homeproxy singbox_generator")
		}
		params := c.Args[3]
		if !strings.Contains(params, `"type":"uuid"`) {
			t.Errorf("expected params with type=uuid, got %s", params)
		}
	})
}
