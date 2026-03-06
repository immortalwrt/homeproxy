package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"homeproxy-cli/internal/system"
)

const defaultLogLines = 50

var validLogTypes = map[string]bool{
	"homeproxy": true, "sing-box-c": true, "sing-box-s": true,
}

func logCommand(args []string) error {
	if err := system.CheckInstalled(); err != nil {
		return err
	}

	if len(args) > 0 && args[0] == "clean" {
		return logClean(args[1:])
	}

	logType := "homeproxy"
	if len(args) > 0 && args[0] != "" {
		logType = args[0]
	}
	if !validLogTypes[logType] {
		return fmt.Errorf("invalid log type: %s (use: homeproxy, sing-box-c, sing-box-s)", logType)
	}

	path := system.LogFile(logType)
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("log file not found: %s", path)
	}
	defer file.Close()

	lines := make([]string, 0, defaultLogLines)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("failed to read log file: %w", err)
	}

	start := 0
	if len(lines) > defaultLogLines {
		start = len(lines) - defaultLogLines
	}

	for _, line := range lines[start:] {
		fmt.Println(line)
	}

	return nil
}

func logClean(args []string) error {
	logType := "homeproxy"
	if len(args) > 0 && args[0] != "" {
		logType = args[0]
	}
	if !validLogTypes[logType] {
		return fmt.Errorf("invalid log type: %s (use: homeproxy, sing-box-c, sing-box-s)", logType)
	}

	raw, err := system.UBUSCall(system.RPCObject, "log_clean", map[string]string{"type": logType})
	if err != nil {
		return err
	}
	if strings.Contains(raw, `"result":false`) || strings.Contains(raw, `"error"`) {
		return fmt.Errorf("log clean failed: %s", raw)
	}
	logInfo("Log cleared: " + logType)
	return nil
}


