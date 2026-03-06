package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"homeproxy-cli/internal/system"
)

const updateScript = "/etc/homeproxy/scripts/update_subscriptions.uc"

func subscriptionCommand(args []string) error {
	if err := system.CheckInstalled(); err != nil {
		return err
	}

	if len(args) == 0 {
		return fmt.Errorf("usage: homeproxy subscription <list|add|remove|update|auto-update|filter|status> [options]")
	}
	action := args[0]
	rest := args[1:]

	switch action {
	case "list":
		return subscriptionList(rest)
	case "add":
		return subscriptionAdd(rest)
	case "remove":
		return subscriptionRemove(rest)
	case "update":
		return subscriptionUpdate()
	case "auto-update":
		return subscriptionAutoUpdate(rest)
	case "filter":
		return subscriptionFilter(rest)
	case "status":
		return subscriptionStatus()
	default:
		return fmt.Errorf("unknown subscription action: %s", action)
	}
}

type subscriptionListJSON struct {
	Subscriptions []string `json:"subscriptions"`
	FilterKeywords []string `json:"filter_keywords,omitempty"`
}

func subscriptionList(args []string) error {
	urls, err := system.UCIGet("homeproxy.subscription.subscription_url")
	if err != nil {
		return err
	}

	_, useJSON := parseJSONFlag(args)
	urlList := strings.Fields(urls)
	filters, _ := system.UCIGet("homeproxy.subscription.filter_keywords")
	filterList := strings.Fields(filters)

	if useJSON {
		out := subscriptionListJSON{
			Subscriptions:  urlList,
			FilterKeywords: filterList,
		}
		return writeJSON(out)
	}

	if urls == "" {
		logWarn("No subscriptions configured")
		return nil
	}

	logInfo("Subscriptions:")
	for i, u := range urlList {
		fmt.Printf("  %d. %s\n", i+1, u)
	}

	if filters != "" {
		fmt.Println()
		logInfo("Filter keywords:")
		for i, f := range filterList {
			fmt.Printf("  %d. %s\n", i+1, f)
		}
	}
	return nil
}

func subscriptionAdd(args []string) error {
	if err := requireRoot(); err != nil {
		return err
	}
	if len(args) == 0 || args[0] == "" {
		return fmt.Errorf("subscription URL required")
	}
	url := args[0]
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		return fmt.Errorf("invalid URL: %s", url)
	}

	existing, _ := system.UCIGet("homeproxy.subscription.subscription_url")
	for _, u := range strings.Fields(existing) {
		if u == url {
			logWarn("Subscription already exists: " + url)
			return nil
		}
	}

	if err := system.UCIAddList("homeproxy.subscription.subscription_url", url); err != nil {
		return err
	}
	if err := uciCommitAndReload(); err != nil {
		return err
	}
	logInfo("Subscription added: " + url)
	return nil
}

func subscriptionRemove(args []string) error {
	if err := requireRoot(); err != nil {
		return err
	}

	if len(args) == 0 || args[0] == "" {
		logWarn("Removing all subscriptions...")
		if err := system.UCIDelete("homeproxy.subscription.subscription_url"); err != nil {
			return err
		}
	} else {
		url := args[0]
		existing, _ := system.UCIGet("homeproxy.subscription.subscription_url")
		var newURLs []string
		for _, u := range strings.Fields(existing) {
			if u != url {
				newURLs = append(newURLs, u)
			}
		}
		if err := system.UCIDelete("homeproxy.subscription.subscription_url"); err != nil {
			return err
		}
		for _, u := range newURLs {
			if err := system.UCIAddList("homeproxy.subscription.subscription_url", u); err != nil {
				return err
			}
		}
	}

	if err := uciCommitAndReload(); err != nil {
		return err
	}
	logInfo("Subscription removed")
	return nil
}

func subscriptionUpdate() error {
	if err := requireRoot(); err != nil {
		return err
	}

	if _, err := os.Stat(updateScript); os.IsNotExist(err) {
		return fmt.Errorf("update script not found: %s", updateScript)
	}

	logInfo("Updating subscriptions...")
	cmd := exec.Command(updateScript)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("update script failed: %w", err)
	}
	logInfo("Subscriptions updated")
	fmt.Println()
	logInfo("Imported nodes:")
	return nodeList(nil)
}

func subscriptionAutoUpdate(args []string) error {
	if err := requireRoot(); err != nil {
		return err
	}
	if len(args) == 0 {
		return fmt.Errorf("usage: homeproxy subscription auto-update <enable|disable>")
	}

	enable := false
	switch strings.ToLower(args[0]) {
	case "enable", "on", "1", "true":
		enable = true
	case "disable", "off", "0", "false":
		enable = false
	default:
		return fmt.Errorf("usage: homeproxy subscription auto-update <enable|disable>")
	}

	val := "0"
	if enable {
		val = "1"
	}
	if err := system.UCISet("homeproxy.subscription.auto_update", val); err != nil {
		return err
	}
	if err := uciCommitAndReload(); err != nil {
		return err
	}
	if enable {
		logInfo("Auto-update enabled")
	} else {
		logInfo("Auto-update disabled")
	}
	return nil
}

func subscriptionFilter(args []string) error {
	if err := requireRoot(); err != nil {
		return err
	}
	if len(args) == 0 {
		return fmt.Errorf("usage: homeproxy subscription filter <add|remove|list|clear> [keyword]")
	}

	action := args[0]
	rest := args[1:]
	keyword := strings.Join(rest, " ")

	switch action {
	case "add":
		if keyword == "" {
			return fmt.Errorf("keyword required")
		}
		if err := system.UCIAddList("homeproxy.subscription.filter_keywords", keyword); err != nil {
			return err
		}
		logInfo("Filter keyword added: " + keyword)
	case "remove":
		if keyword == "" {
			return fmt.Errorf("keyword required")
		}
		existing, _ := system.UCIGet("homeproxy.subscription.filter_keywords")
		var newFilters []string
		for _, f := range strings.Fields(existing) {
			if f != keyword {
				newFilters = append(newFilters, f)
			}
		}
		if err := system.UCIDelete("homeproxy.subscription.filter_keywords"); err != nil {
			return err
		}
		for _, f := range newFilters {
			if err := system.UCIAddList("homeproxy.subscription.filter_keywords", f); err != nil {
				return err
			}
		}
		logInfo("Filter keyword removed: " + keyword)
	case "list":
		filters, _ := system.UCIGet("homeproxy.subscription.filter_keywords")
		if filters == "" {
			logWarn("No filter keywords")
			return nil
		}
		for i, f := range strings.Fields(filters) {
			fmt.Printf("  %d. %s\n", i+1, f)
		}
		return nil
	case "clear":
		if err := system.UCIDelete("homeproxy.subscription.filter_keywords"); err != nil {
			return err
		}
		logInfo("Filter keywords cleared")
	default:
		return fmt.Errorf("usage: homeproxy subscription filter <add|remove|list|clear> [keyword]")
	}

	return uciCommitAndReload()
}

func subscriptionStatus() error {
	logInfo("Subscription Status")
	fmt.Println("=====================")

	autoUpdate, _ := system.UCIGet("homeproxy.subscription.auto_update")
	allowInsecure, _ := system.UCIGet("homeproxy.subscription.allow_insecure")
	updateTime, _ := system.UCIGet("homeproxy.subscription.auto_update_time")
	filterMode, _ := system.UCIGet("homeproxy.subscription.filter_nodes")

	au := "disabled"
	if autoUpdate == "1" {
		au = "enabled"
	}
	fmt.Println("Auto-update:", au)
	if updateTime != "" {
		fmt.Println("Update time:", updateTime+":00")
	}
	ai := "no"
	if allowInsecure == "1" {
		ai = "yes"
	}
	fmt.Println("Allow insecure:", ai)
	fmt.Println("Filter mode:", filterMode)

	fmt.Println()
	return subscriptionList(nil)
}
