package main

import (
	"fmt"
	"os"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		printUsage()
		return nil
	}

	if len(args) == 1 && (args[0] == "-h" || args[0] == "--help" || args[0] == "help") {
		printUsage()
		return nil
	}

	command := args[0]
	subArgs := args[1:]

	switch command {
	case "status":
		return statusCommand(subArgs)
	case "node":
		return nodeCommand(subArgs)
	case "routing":
		return routingCommand(subArgs)
	case "dns":
		return dnsCommand(subArgs)
	case "subscription":
		return subscriptionCommand(subArgs)
	case "control":
		return controlCommand(subArgs)
	case "log":
		return logCommand(subArgs)
	case "features":
		return featuresCommand()
	case "resources":
		return resourcesCommand(subArgs)
	case "acl":
		return aclCommand(subArgs)
	case "cert":
		return certCommand(subArgs)
	case "generator":
		return generatorCommand(subArgs)
	case "completion":
		return completionCommand(subArgs)
	case "docs":
		return docsCommand(subArgs)
	default:
		printUsage()
		return fmt.Errorf("unknown command: %s", command)
	}
}

func printUsage() {
	fmt.Println("HomeProxy CLI - Command line interface for HomeProxy")
	fmt.Println()
	fmt.Println("Usage: homeproxy <command> [options]")
	fmt.Println()
	fmt.Println("Commands:")
	for _, cmd := range allCommands {
		if len(cmd.Actions) > 0 {
			fmt.Printf("    %s <action>        %s\n", cmd.Name, cmd.Summary)
			for _, a := range cmd.Actions {
				fmt.Printf("        %-24s %s\n", a.Usage, a.Desc)
			}
			fmt.Println()
		} else {
			fmt.Printf("    %-18s %s\n", cmd.Name, cmd.Summary)
			fmt.Println()
		}
	}
	fmt.Println("Options:")
	fmt.Println("    -h, --help           Show this help")
	fmt.Println("    --json               Machine-readable JSON output (status, node list, subscription list, routing get, dns get)")
}

