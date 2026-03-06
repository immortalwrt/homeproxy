package main

import (
	"testing"
)

func TestParseFileFlag(t *testing.T) {
	tests := []struct {
		args       []string
		wantValue  string
		wantPath   string
	}{
		{[]string{}, "", ""},
		{[]string{"direct_list"}, "direct_list", ""},
		{[]string{"--file", "/tmp/foo"}, "", "/tmp/foo"},
		{[]string{"-f", "/tmp/bar"}, "", "/tmp/bar"},
		{[]string{"direct_list", "--file", "/tmp/foo"}, "direct_list", "/tmp/foo"},
		{[]string{"--file", "/tmp/foo", "direct_list"}, "direct_list", "/tmp/foo"},
		{[]string{"direct_list", "--file", "/path/to/file"}, "direct_list", "/path/to/file"},
	}
	for _, tt := range tests {
		value, path := parseFileFlag(tt.args)
		if value != tt.wantValue || path != tt.wantPath {
			t.Errorf("parseFileFlag(%v) = (%q, %q), want (%q, %q)", tt.args, value, path, tt.wantValue, tt.wantPath)
		}
	}
}

func TestContainsString(t *testing.T) {
	list := []string{"direct_list", "proxy_list"}
	if !containsString(list, "direct_list") {
		t.Error("containsString(direct_list) should be true")
	}
	if !containsString(list, "proxy_list") {
		t.Error("containsString(proxy_list) should be true")
	}
	if containsString(list, "other") {
		t.Error("containsString(other) should be false")
	}
	if containsString(nil, "x") {
		t.Error("containsString(nil, x) should be false")
	}
	if containsString([]string{}, "x") {
		t.Error("containsString([], x) should be false")
	}
}
