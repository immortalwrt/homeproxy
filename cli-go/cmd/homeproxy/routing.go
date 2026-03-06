package main

import (
	"fmt"

	"homeproxy-cli/internal/system"
)

var routingModes = map[string]bool{
	"bypass_mainland_china": true, "proxy_mainland_china": true,
	"proxy_all": true, "direct_all": true, "custom": true,
}

func routingCommand(args []string) error {
	if err := system.CheckInstalled(); err != nil {
		return err
	}

	if len(args) == 0 {
		return fmt.Errorf("usage: homeproxy routing <get|set|set-node|rules|status> [options]")
	}
	action := args[0]
	rest := args[1:]

	switch action {
	case "get":
		return routingGet(rest)
	case "set":
		return routingSet(rest)
	case "set-node":
		return routingSetNode(rest)
	case "rules":
		return routingRules()
	case "status":
		return routingStatus()
	default:
		return fmt.Errorf("unknown routing action: %s", action)
	}
}

type routingGetJSON struct {
	RoutingMode string `json:"routing_mode"`
	RoutingPort string `json:"routing_port"`
	ProxyMode   string `json:"proxy_mode"`
}

func routingGet(args []string) error {
	mode, _ := system.UCIGet("homeproxy.config.routing_mode")
	port, _ := system.UCIGet("homeproxy.config.routing_port")
	proxyMode, _ := system.UCIGet("homeproxy.config.proxy_mode")

	_, useJSON := parseJSONFlag(args)
	if useJSON {
		out := routingGetJSON{
			RoutingMode: mode,
			RoutingPort: port,
			ProxyMode:   proxyMode,
		}
		return writeJSON(out)
	}

	fmt.Println("Routing Mode:", mode)
	fmt.Println("Routing Port:", port)
	fmt.Println("Proxy Mode:", proxyMode)
	return nil
}

func routingSet(args []string) error {
	if err := requireRoot(); err != nil {
		return err
	}
	if len(args) == 0 || args[0] == "" {
		return fmt.Errorf("mode required. Available: bypass_mainland_china, proxy_mainland_china, proxy_all, direct_all, custom")
	}
	mode := args[0]
	if !routingModes[mode] {
		return fmt.Errorf("invalid routing mode: %s", mode)
	}

	if err := system.UCISet("homeproxy.config.routing_mode", mode); err != nil {
		return err
	}
	if err := uciCommitAndReload(); err != nil {
		return err
	}
	logInfo("Routing mode set to: " + mode)
	return nil
}

func routingSetNode(args []string) error {
	if err := requireRoot(); err != nil {
		return err
	}
	if len(args) < 2 {
		return fmt.Errorf("usage: homeproxy routing set-node <main|udp> <node_name>")
	}
	nodeType, nodeName := args[0], args[1]

	id, err := findNodeByLabelOrID(nodeName)
	if err != nil {
		return err
	}

	switch nodeType {
	case "main":
		if err := system.UCISet("homeproxy.config.main_node", id); err != nil {
			return err
		}
	case "udp":
		if err := system.UCISet("homeproxy.config.main_udp_node", id); err != nil {
			return err
		}
	default:
		return fmt.Errorf("invalid node type: %s (use: main or udp)", nodeType)
	}

	if err := uciCommitAndReload(); err != nil {
		return err
	}
	logInfo("Routing node set: " + nodeType + " = " + nodeName)
	return nil
}

func routingRules() error {
	logInfo("Routing Rules")
	fmt.Println("==============")
	defaultOut, _ := system.UCIGet("homeproxy.routing.default_outbound")
	defaultDNS, _ := system.UCIGet("homeproxy.routing.default_outbound_dns")
	sniffOverride, _ := system.UCIGet("homeproxy.routing.sniff_override")
	fmt.Println("Default Outbound:", defaultOut)
	fmt.Println("Default Outbound DNS:", defaultDNS)
	fmt.Println("Sniff Override:", sniffOverride)
	return nil
}

func routingStatus() error {
	logInfo("Routing Status")
	fmt.Println("===============")
	routingGet(nil)
	fmt.Println()
	mainNode, _ := system.UCIGet("homeproxy.config.main_node")
	udpNode, _ := system.UCIGet("homeproxy.config.main_udp_node")
	fmt.Println("Main Node:", mainNode)
	fmt.Println("UDP Node:", udpNode)
	return nil
}
