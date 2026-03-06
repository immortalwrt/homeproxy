package main

// parseJSONFlag strips --json from args and returns (remaining args, true if --json was present).
func parseJSONFlag(args []string) (rest []string, useJSON bool) {
	for _, a := range args {
		if a == "--json" {
			useJSON = true
			continue
		}
		rest = append(rest, a)
	}
	return rest, useJSON
}

// parseFileFlag parses args for [value] [--file path] or [--file path] [value].
// Returns the first non-flag arg and the path from --file/-f.
func parseFileFlag(args []string) (value, filePath string) {
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--file", "-f":
			if i+1 < len(args) {
				filePath = args[i+1]
			}
			i++
		default:
			if value == "" {
				value = args[i]
			}
		}
	}
	return value, filePath
}

// containsString returns true if s is in list.
func containsString(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
