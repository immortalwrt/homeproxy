package main

import (
	"fmt"
	"os/exec"
	"strings"

	"homeproxy-cli/internal/system"
)

var dnsStrategies = map[string]bool{
	"prefer_ipv4": true, "prefer_ipv6": true, "ipv4_only": true, "ipv6_only": true,
}

func dnsCommand(args []string) error {
	if err := system.CheckInstalled(); err != nil {
		return err
	}

	if len(args) == 0 {
		return fmt.Errorf("usage: homeproxy dns <get|set|set-china|test|cache|strategy|status> [options]")
	}
	action := args[0]
	rest := args[1:]

	switch action {
	case "get":
		return dnsGet(rest)
	case "set":
		return dnsSet(rest)
	case "set-china":
		return dnsSetChina(rest)
	case "test":
		return dnsTest(rest)
	case "cache":
		return dnsCache(rest)
	case "strategy":
		return dnsStrategy(rest)
	case "status":
		return dnsStatus()
	default:
		return fmt.Errorf("unknown dns action: %s", action)
	}
}

type dnsGetJSON struct {
	DNSServer string `json:"dns_server"`
	ChinaDNS  string `json:"china_dns_server"`
	Strategy  string `json:"strategy"`
	Cache     string `json:"cache"`
}

func dnsGet(args []string) error {
	dns, _ := system.UCIGet("homeproxy.config.dns_server")
	chinaDNS, _ := system.UCIGet("homeproxy.config.china_dns_server")
	strategy, _ := system.UCIGet("homeproxy.dns.dns_strategy")
	disableCache, _ := system.UCIGet("homeproxy.dns.disable_cache")

	cacheStatus := "enabled"
	if disableCache == "1" {
		cacheStatus = "disabled"
	}

	_, useJSON := parseJSONFlag(args)
	if useJSON {
		out := dnsGetJSON{
			DNSServer: dns,
			ChinaDNS:  chinaDNS,
			Strategy:  strategy,
			Cache:     cacheStatus,
		}
		return writeJSON(out)
	}

	fmt.Println("DNS Server:", dns)
	fmt.Println("China DNS:", chinaDNS)
	fmt.Println("Strategy:", strategy)
	fmt.Println("Cache:", cacheStatus)
	return nil
}

func dnsSet(args []string) error {
	return dnsSetServer(args, "homeproxy.config.dns_server", "DNS server")
}

func dnsSetChina(args []string) error {
	return dnsSetServer(args, "homeproxy.config.china_dns_server", "China DNS server")
}

func dnsSetServer(args []string, uciPath, label string) error {
	if err := requireRoot(); err != nil {
		return err
	}
	if len(args) == 0 || args[0] == "" {
		return fmt.Errorf("%s required", label)
	}
	server := args[0]

	if err := system.UCISet(uciPath, server); err != nil {
		return err
	}
	if err := uciCommitAndReload(); err != nil {
		return err
	}
	logInfo(label + " set to: " + server)
	return nil
}

func dnsTest(args []string) error {
	domain := "google.com"
	dns := "8.8.8.8"
	if len(args) > 0 && args[0] != "" {
		domain = args[0]
	}
	if len(args) > 1 && args[1] != "" {
		dns = args[1]
	}

	logInfo("Testing DNS: " + domain + " via " + dns)

	// Try nslookup first
	if path, err := exec.LookPath("nslookup"); err == nil {
		out, err := exec.Command(path, domain, dns).CombinedOutput()
		if err == nil && strings.Contains(string(out), "Address:") {
			logInfo("DNS resolution: OK")
			lines := strings.Split(string(out), "\n")
			for i := len(lines) - 1; i >= 0; i-- {
				if strings.Contains(lines[i], "Address:") && !strings.Contains(lines[i], "127.0.0.1") {
					fmt.Println(strings.TrimSpace(lines[i]))
					return nil
				}
			}
			return nil
		}
	}

	// Try dig
	if path, err := exec.LookPath("dig"); err == nil {
		out, err := exec.Command(path, "+short", "@"+dns, domain).CombinedOutput()
		if err == nil && len(out) > 0 {
			logInfo("DNS resolution: OK")
			fmt.Println(strings.TrimSpace(string(out)))
			return nil
		}
	}

	logError("No DNS lookup tool available (nslookup, dig)")
	return nil
}

func dnsCache(args []string) error {
	if err := requireRoot(); err != nil {
		return err
	}
	if len(args) == 0 {
		return fmt.Errorf("usage: homeproxy dns cache <enable|disable>")
	}
	switch args[0] {
	case "enable":
		if err := system.UCISet("homeproxy.dns.disable_cache", "0"); err != nil {
			return err
		}
		logInfo("DNS cache enabled")
	case "disable":
		if err := system.UCISet("homeproxy.dns.disable_cache", "1"); err != nil {
			return err
		}
		logInfo("DNS cache disabled")
	default:
		return fmt.Errorf("usage: homeproxy dns cache <enable|disable>")
	}
	return uciCommitAndReload()
}

func dnsStrategy(args []string) error {
	if err := requireRoot(); err != nil {
		return err
	}
	if len(args) == 0 || args[0] == "" {
		current, _ := system.UCIGet("homeproxy.dns.dns_strategy")
		logInfo("Current: " + current)
		logInfo("Options: prefer_ipv4, prefer_ipv6, ipv4_only, ipv6_only")
		return nil
	}
	strategy := args[0]
	if !dnsStrategies[strategy] {
		return fmt.Errorf("invalid strategy: %s", strategy)
	}
	if err := system.UCISet("homeproxy.dns.dns_strategy", strategy); err != nil {
		return err
	}
	if err := uciCommitAndReload(); err != nil {
		return err
	}
	logInfo("DNS strategy set to: " + strategy)
	return nil
}

func dnsStatus() error {
	logInfo("DNS Status")
	fmt.Println("===========")
	dnsGet(nil)
	fmt.Println()
	logInfo("Testing DNS...")
	return dnsTest([]string{"google.com", "8.8.8.8"})
}
