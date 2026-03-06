package main

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"homeproxy-cli/internal/system"
)

var nodeTypes = map[string]string{
	"vmess": "VMess", "vless": "VLESS", "trojan": "Trojan",
	"shadowsocks": "Shadowsocks", "hysteria": "Hysteria", "hysteria2": "Hysteria2",
	"socks": "SOCKS", "http": "HTTP", "tuic": "TUIC", "wireguard": "WireGuard",
	"direct": "Direct",
}

func nodeTypeName(t string) string {
	if n, ok := nodeTypes[t]; ok {
		return n
	}
	return t
}

// getAllNodes parses uci show homeproxy for node section IDs.
func getAllNodes() ([]string, error) {
	out, err := system.UCIShow("homeproxy")
	if err != nil {
		return nil, err
	}
	// Lines like: homeproxy.cfg0abc123=node  or  homeproxy.@node[0]=node
	re := regexp.MustCompile(`^homeproxy\.([^.=]+)=node$`)
	seen := make(map[string]bool)
	var nodes []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		m := re.FindStringSubmatch(line)
		if m != nil {
			id := m[1]
			if !seen[id] {
				seen[id] = true
				nodes = append(nodes, id)
			}
		}
	}
	return nodes, nil
}

// findNodeByLabelOrID returns the UCI section ID (e.g. cfg0abc123) for a label or section ID.
func findNodeByLabelOrID(name string) (string, error) {
	nodes, err := getAllNodes()
	if err != nil {
		return "", err
	}
	for _, id := range nodes {
		if id == name {
			return id, nil
		}
		label, _ := system.UCIGet("homeproxy." + id + ".label")
		if label == name {
			return id, nil
		}
	}
	return "", fmt.Errorf("node not found: %s", name)
}

func nodeCommand(args []string) error {
	if err := system.CheckInstalled(); err != nil {
		return err
	}

	if len(args) == 0 {
		return fmt.Errorf("usage: homeproxy node <list|test|set-main|add|remove|edit|import|export> [options]")
	}
	action := args[0]
	rest := args[1:]

	switch action {
	case "list":
		return nodeList(rest)
	case "test":
		return nodeTest(rest)
	case "set-main":
		return nodeSetMain(rest)
	case "add":
		return nodeAdd(rest)
	case "remove":
		return nodeRemove(rest)
	case "edit":
		return nodeEdit(rest)
	case "import":
		return nodeImport(rest)
	case "export":
		return nodeExport(rest)
	default:
		return fmt.Errorf("unknown node action: %s", action)
	}
}

type nodeListJSON struct {
	Nodes []nodeEntry `json:"nodes"`
}

type nodeEntry struct {
	Name    string `json:"name"`
	Address string `json:"address"`
	Type    string `json:"type"`
	Status  string `json:"status"`
}

func nodeList(args []string) error {
	nodes, err := getAllNodes()
	if err != nil {
		return err
	}

	_, useJSON := parseJSONFlag(args)
	mainNode, _ := system.UCIGet("homeproxy.config.main_node")

	if useJSON {
		entries := make([]nodeEntry, 0, len(nodes))
		for _, id := range nodes {
			label, _ := system.UCIGet("homeproxy." + id + ".label")
			if label == "" {
				label = id
			}
			addr, _ := system.UCIGet("homeproxy." + id + ".address")
			if addr == "" {
				addr = "-"
			}
			port, _ := system.UCIGet("homeproxy." + id + ".port")
			if port == "" {
				port = "-"
			}
			typ, _ := system.UCIGet("homeproxy." + id + ".type")
			status := "inactive"
			if mainNode == id {
				status = "active"
			}
			entries = append(entries, nodeEntry{
				Name:    label,
				Address: addr + ":" + port,
				Type:    nodeTypeName(typ),
				Status:  status,
			})
		}
		out := nodeListJSON{Nodes: entries}
		return writeJSON(out)
	}

	if len(nodes) == 0 {
		logWarn("No nodes found")
		return nil
	}

	fmt.Printf("%-20s %-25s %-10s %s\n", "NAME", "ADDRESS", "TYPE", "STATUS")
	fmt.Printf("%-20s %-25s %-10s %s\n", "----", "-------", "----", "------")

	for _, id := range nodes {
		label, _ := system.UCIGet("homeproxy." + id + ".label")
		if label == "" {
			label = id
		}
		addr, _ := system.UCIGet("homeproxy." + id + ".address")
		if addr == "" {
			addr = "-"
		}
		port, _ := system.UCIGet("homeproxy." + id + ".port")
		if port == "" {
			port = "-"
		}
		typ, _ := system.UCIGet("homeproxy." + id + ".type")
		status := "[inactive]"
		if mainNode == id {
			status = "[active]"
		}
		fmt.Printf("%-20s %-25s %-10s %s\n", label, addr+":"+port, nodeTypeName(typ), status)
	}
	return nil
}

func nodeTest(args []string) error {
	var nodeName string
	if len(args) > 0 && args[0] != "" {
		nodeName = args[0]
	} else {
		mainNode, _ := system.UCIGet("homeproxy.config.main_node")
		if mainNode == "" || mainNode == "nil" {
			return fmt.Errorf("no main node configured")
		}
		nodeName = mainNode
	}

	id, err := findNodeByLabelOrID(nodeName)
	if err != nil {
		return err
	}
	logInfo("Testing connection for node: " + id)

	// Test Google
	raw, err := system.UBUSCall(system.RPCObject, "connection_check", map[string]string{"site": "google"})
	if err != nil {
		return err
	}
	if strings.Contains(raw, `"result":true`) {
		logInfo("Google: PASS")
	} else {
		logError("Google: FAIL")
	}

	raw, err = system.UBUSCall(system.RPCObject, "connection_check", map[string]string{"site": "baidu"})
	if err != nil {
		return err
	}
	if strings.Contains(raw, `"result":true`) {
		logInfo("Baidu: PASS")
	} else {
		logError("Baidu: FAIL")
	}
	return nil
}

func nodeSetMain(args []string) error {
	if err := requireRoot(); err != nil {
		return err
	}
	if len(args) == 0 || args[0] == "" {
		return fmt.Errorf("node name required")
	}

	id, err := findNodeByLabelOrID(args[0])
	if err != nil {
		return err
	}

	if err := system.UCISet("homeproxy.config.main_node", id); err != nil {
		return err
	}
	if err := uciCommitAndReload(); err != nil {
		return err
	}
	logInfo("Main node set to: " + args[0])
	return nil
}

func validatePort(port string) bool {
	p, err := strconv.Atoi(port)
	return err == nil && p >= 1 && p <= 65535
}

func nodeAdd(args []string) error {
	if err := requireRoot(); err != nil {
		return err
	}
	if len(args) < 3 {
		return fmt.Errorf("usage: homeproxy node add <type> <address> <port> [label]")
	}
	typ, addr, port := args[0], args[1], args[2]
	var label string
	if len(args) > 3 {
		label = strings.Join(args[3:], " ")
	}

	if _, ok := nodeTypes[typ]; !ok {
		return fmt.Errorf("invalid node type: %s", typ)
	}
	if !validatePort(port) {
		return fmt.Errorf("invalid port: %s", port)
	}

	if err := system.UCIAdd("homeproxy", "node"); err != nil {
		return err
	}

	if err := system.UCISet("homeproxy.@node[-1].type", typ); err != nil {
		return err
	}
	if err := system.UCISet("homeproxy.@node[-1].address", addr); err != nil {
		return err
	}
	if err := system.UCISet("homeproxy.@node[-1].port", port); err != nil {
		return err
	}
	if label != "" {
		if err := system.UCISet("homeproxy.@node[-1].label", label); err != nil {
			return err
		}
	} else {
		if err := system.UCISet("homeproxy.@node[-1].label", addr+":"+port); err != nil {
			return err
		}
	}

	if err := uciCommitAndReload(); err != nil {
		return err
	}
	logInfo(fmt.Sprintf("Node added (%s:%s). Use label or section ID with 'homeproxy node set-main' to activate.", addr, port))
	return nil
}

func nodeRemove(args []string) error {
	if err := requireRoot(); err != nil {
		return err
	}
	if len(args) == 0 || args[0] == "" {
		return fmt.Errorf("node name required")
	}

	id, err := findNodeByLabelOrID(args[0])
	if err != nil {
		return err
	}

	mainNode, _ := system.UCIGet("homeproxy.config.main_node")
	if mainNode == id {
		if err := system.UCISet("homeproxy.config.main_node", "nil"); err != nil {
			return err
		}
	}

	if err := system.UCIDelete("homeproxy." + id); err != nil {
		return err
	}
	if err := uciCommitAndReload(); err != nil {
		return err
	}
	logInfo("Node removed: " + args[0])
	return nil
}

func nodeEdit(args []string) error {
	if err := requireRoot(); err != nil {
		return err
	}
	if len(args) < 2 {
		return fmt.Errorf("usage: homeproxy node edit <name> <key> <value>")
	}

	id, err := findNodeByLabelOrID(args[0])
	if err != nil {
		return err
	}
	key := args[1]
	value := strings.Join(args[2:], " ")

	if err := system.UCISet("homeproxy."+id+"."+key, value); err != nil {
		return err
	}
	if err := uciCommitAndReload(); err != nil {
		return err
	}
	logInfo(fmt.Sprintf("Node %s updated: %s = %s", args[0], key, value))
	return nil
}

func nodeImport(args []string) error {
	if err := requireRoot(); err != nil {
		return err
	}
	if len(args) == 0 {
		return fmt.Errorf("usage: homeproxy node import <share-link|url> [more links...]")
	}

	lines := parseImportLines(args)
	if len(lines) == 0 {
		return fmt.Errorf("no valid input links")
	}

	allowInsecure, _ := system.UCIGet("homeproxy.subscription.allow_insecure")
	packetEncoding, _ := system.UCIGet("homeproxy.subscription.packet_encoding")
	features := loadShareFeatures()

	importedNodes := 0
	addedSubscriptions := 0
	invalidLinks := 0

	for _, line := range lines {
		if looksLikeSubscriptionURL(line) {
			if err := system.UCIAddList("homeproxy.subscription.subscription_url", line); err != nil {
				return err
			}
			addedSubscriptions++
			continue
		}

		node := parseShareLink(line, features)
		if node == nil {
			invalidLinks++
			continue
		}

		if node.Options["tls"] == "1" && allowInsecure == "1" {
			node.Options["tls_insecure"] = "1"
		}
		switch node.Options["type"] {
		case "vless", "vmess":
			if packetEncoding != "" {
				node.Options["packet_encoding"] = packetEncoding
			}
		}

		if err := applyParsedNodeToUCI(node); err != nil {
			return err
		}
		importedNodes++
	}

	if importedNodes == 0 && addedSubscriptions == 0 {
		return fmt.Errorf("no valid share link or subscription URL found")
	}

	if err := uciCommitAndReload(); err != nil {
		return err
	}

	total := len(lines)
	if importedNodes > 0 {
		logInfo(fmt.Sprintf("Successfully imported %d nodes of total %d.", importedNodes, total))
	}
	if addedSubscriptions > 0 {
		logInfo(fmt.Sprintf("Added %d subscription URL(s). Run 'homeproxy subscription update' to import nodes.", addedSubscriptions))
	}
	if invalidLinks > 0 {
		logWarn(fmt.Sprintf("Skipped %d invalid link(s).", invalidLinks))
	}
	return nil
}

func nodeExport(args []string) error {
	if len(args) == 0 {
		nodes, err := getAllNodes()
		if err != nil {
			return err
		}
		for _, id := range nodes {
			label, _ := system.UCIGet("homeproxy." + id + ".label")
			if label == "" {
				label = id
			}
			fmt.Println(label)
		}
		return nil
	}

	id, err := findNodeByLabelOrID(args[0])
	if err != nil {
		return err
	}
	out, err := system.UCIShow("homeproxy." + id)
	if err != nil {
		return err
	}
	// UCIShow returns full package output; we only want this section
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "homeproxy."+id) {
			fmt.Println(line)
		}
	}
	return nil
}
