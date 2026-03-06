package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"homeproxy-cli/internal/system"
)

var generatorTypes = []string{"uuid", "reality-keypair", "wg-keypair", "vapid-keypair", "ech-keypair"}

func generatorCommand(args []string) error {
	if err := system.CheckInstalled(); err != nil {
		return err
	}

	if len(args) == 0 || args[0] == "" {
		return fmt.Errorf("usage: homeproxy generator <type> [params] (uuid, reality-keypair, wg-keypair, vapid-keypair, ech-keypair)")
	}
	typ := args[0]
	if err := validateOneOf(typ, generatorTypes, "type"); err != nil {
		return err
	}
	params := ""
	if len(args) > 1 {
		params = strings.Join(args[1:], " ")
	}

	raw, err := system.UBUSCall(system.RPCObject, "singbox_generator", map[string]any{
		"type":   typ,
		"params": params,
	})
	if err != nil {
		return err
	}

	var out struct {
		Result map[string]any `json:"result"`
		Error  string         `json:"error"`
	}
	if json.Unmarshal([]byte(raw), &out) != nil {
		fmt.Println(strings.TrimSpace(raw))
		return nil
	}
	if out.Error != "" {
		return fmt.Errorf("generator failed: %s", out.Error)
	}
	keys := make([]string, 0, len(out.Result))
	for k := range out.Result {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := out.Result[k]
		if s, ok := v.(string); ok {
			fmt.Printf("%s: %s\n", k, s)
		} else {
			fmt.Printf("%s: %v\n", k, v)
		}
	}
	return nil
}
