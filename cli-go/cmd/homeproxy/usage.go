package main

// CmdSpec describes a top-level command and its actions.
type CmdSpec struct {
	Name    string   // "node"
	Summary string   // "Node management"
	Actions []Action // sub-actions; empty for leaf commands
}

// Action describes a sub-action under a command.
type Action struct {
	Usage string // "list" or "add <type> <addr> <port> [label]"
	Desc  string // "List all nodes"
}

// allCommands is the single source of truth for CLI help and docs.
var allCommands = []CmdSpec{
	{
		Name:    "node",
		Summary: "Node management",
		Actions: []Action{
			{"list", "List all nodes"},
			{"test [name]", "Test node connection"},
			{"set-main <name>", "Set main node"},
			{"add <type> <addr> <port> [label]", "Add new node"},
			{"remove <name>", "Remove node"},
			{"edit <name> <key> <value>", "Edit node"},
			{"import <share-link|url> [more links...]", "Import share links or subscription URLs"},
			{"export [name]", "Export nodes"},
		},
	},
	{
		Name:    "routing",
		Summary: "Routing management",
		Actions: []Action{
			{"get", "Get current routing mode"},
			{"set <mode>", "Set routing mode"},
			{"set-node <type> <name>", "Set routing node"},
			{"rules", "Show routing rules"},
			{"status", "Show routing status"},
		},
	},
	{
		Name:    "dns",
		Summary: "DNS management",
		Actions: []Action{
			{"get", "Get DNS servers"},
			{"set <server>", "Set DNS server"},
			{"set-china <server>", "Set China DNS server"},
			{"test [domain]", "Test DNS resolution"},
			{"cache <enable|disable>", "DNS cache control"},
			{"strategy [mode]", "DNS strategy"},
			{"status", "Show DNS status"},
		},
	},
	{
		Name:    "subscription",
		Summary: "Subscription management",
		Actions: []Action{
			{"list", "List subscriptions"},
			{"add <url>", "Add subscription"},
			{"remove [url]", "Remove subscription(s)"},
			{"update", "Update subscriptions"},
			{"auto-update <on|off>", "Toggle auto-update"},
			{"filter <action>", "Manage filter keywords"},
			{"status", "Show subscription status"},
		},
	},
	{
		Name:    "status",
		Summary: "Show HomeProxy status",
		Actions: nil,
	},
	{
		Name:    "log",
		Summary: "Show logs (homeproxy|sing-box-c|sing-box-s)",
		Actions: []Action{
			{"[type]", "Show logs"},
			{"clean [type]", "Clear log file"},
		},
	},
	{
		Name:    "control",
		Summary: "Service control",
		Actions: []Action{
			{"start", "Start HomeProxy"},
			{"stop", "Stop HomeProxy"},
			{"restart", "Restart HomeProxy"},
			{"status", "Show service status"},
		},
	},
	{
		Name:    "features",
		Summary: "Show sing-box features",
		Actions: nil,
	},
	{
		Name:    "resources",
		Summary: "Resource management",
		Actions: []Action{
			{"version [type]", "Show resource version (china_ip4, china_ip6, china_list, gfw_list)"},
			{"update <type>", "Update resource"},
		},
	},
	{
		Name:    "acl",
		Summary: "ACL list management",
		Actions: []Action{
			{"list <type>", "List direct_list or proxy_list content"},
			{"write <type> --file <path>", "Write ACL from file"},
		},
	},
	{
		Name:    "cert",
		Summary: "Write certificate (client_ca, server_publickey, server_privatekey)",
		Actions: []Action{
			{"write <filename> --file <path>", "Write certificate"},
		},
	},
	{
		Name:    "generator",
		Summary: "Generate keys (uuid, reality-keypair, wg-keypair, vapid-keypair, ech-keypair)",
		Actions: []Action{
			{"<type> [params]", "Generate keys"},
		},
	},
	{
		Name:    "completion",
		Summary: "Output bash completion script",
		Actions: []Action{
			{"bash", "Bash completion script"},
		},
	},
	{
		Name:    "docs",
		Summary: "Generate Markdown reference (from-first-src)",
		Actions: []Action{
			{"[--out <file>]", "Output Markdown to stdout or file"},
		},
	},
}
