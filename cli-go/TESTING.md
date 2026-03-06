# Testing the Go CLI

## Unit and contract tests (default)

All tests run with `go test` without requiring root, uci, ubus, or OpenWrt. They use mocks to simulate the LuCI API contract.

```bash
cd cli-go && go test ./...
```

- **Unit tests**: help, status, features, resources version, acl list, generator uuid, parseFileFlag, containsString, JSON 输出格式 (`--json`)
- **Contract tests**: assert the CLI invokes ubus/uci with the expected arguments based on command implementations under `cmd/homeproxy/*.go`
- No host state is modified (no apply, no singbox, no routing, no UCI writes)

## Integration tests (optional)

For full integration against real uci/ubus in an OpenWrt container:

```bash
go test -tags=integration ./...
```

These tests require Docker and an OpenWrt base image. Skip them if not implemented.
