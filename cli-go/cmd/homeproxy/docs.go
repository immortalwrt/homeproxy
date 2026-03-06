package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func docsCommand(args []string) error {
	fs := flag.NewFlagSet("docs", flag.ContinueOnError)
	out := fs.String("out", "", "output file (default: stdout)")
	if err := fs.Parse(args); err != nil {
		return nil // flag.Parse prints usage on -h
	}

	md := genMarkdown()
	if *out == "" {
		fmt.Print(md)
		return nil
	}
	dir := filepath.Dir(*out)
	if dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}
	return os.WriteFile(*out, []byte(md), 0644)
}

func genMarkdown() string {
	var b strings.Builder
	b.WriteString("# HomeProxy CLI Reference\n\n")
	b.WriteString("Generated from source (from-first-src).\n\n")
	b.WriteString("## Usage\n\n")
	b.WriteString("```\nhomeproxy <command> [options]\n```\n\n")
	b.WriteString("## Commands\n\n")

	for _, cmd := range allCommands {
		b.WriteString("### ")
		b.WriteString(cmd.Name)
		b.WriteString("\n\n")
		b.WriteString(cmd.Summary)
		b.WriteString("\n\n")

		if len(cmd.Actions) > 0 {
			b.WriteString("| Action | Description |\n")
			b.WriteString("|--------|-------------|\n")
			for _, a := range cmd.Actions {
				usageEsc := strings.ReplaceAll(a.Usage, "|", "\\|")
				descEsc := strings.ReplaceAll(a.Desc, "|", "\\|")
				b.WriteString("| ")
				b.WriteString(usageEsc)
				b.WriteString(" | ")
				b.WriteString(descEsc)
				b.WriteString(" |\n")
			}
			b.WriteString("\n**Examples:**\n\n")
			b.WriteString("```\nhomeproxy ")
			b.WriteString(cmd.Name)
			b.WriteString(" <action> [options]\n```\n\n")
		} else {
			b.WriteString("```\nhomeproxy ")
			b.WriteString(cmd.Name)
			b.WriteString("\n```\n\n")
		}
	}

	b.WriteString("## Options\n\n")
	b.WriteString("| Option | Description |\n")
	b.WriteString("|--------|-------------|\n")
	b.WriteString("| `-h`, `--help` | Show help |\n")

	return b.String()
}
