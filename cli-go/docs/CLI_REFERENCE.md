# HomeProxy CLI Reference

Generated from source (from-first-src).

## Usage

```
homeproxy <command> [options]
```

## Commands

### node

Node management

| Action | Description |
|--------|-------------|
| list | List all nodes |
| test [name] | Test node connection |
| set-main <name> | Set main node |
| add <type> <addr> <port> [label] | Add new node |
| remove <name> | Remove node |
| edit <name> <key> <value> | Edit node |
| import <share-link\|url> [more links...] | Import share links or subscription URLs |
| export [name] | Export nodes |

**Examples:**

```
homeproxy node <action> [options]
```

### routing

Routing management

| Action | Description |
|--------|-------------|
| get | Get current routing mode |
| set <mode> | Set routing mode |
| set-node <type> <name> | Set routing node |
| rules | Show routing rules |
| status | Show routing status |

**Examples:**

```
homeproxy routing <action> [options]
```

### dns

DNS management

| Action | Description |
|--------|-------------|
| get | Get DNS servers |
| set <server> | Set DNS server |
| set-china <server> | Set China DNS server |
| test [domain] | Test DNS resolution |
| cache <enable\|disable> | DNS cache control |
| strategy [mode] | DNS strategy |
| status | Show DNS status |

**Examples:**

```
homeproxy dns <action> [options]
```

### subscription

Subscription management

| Action | Description |
|--------|-------------|
| list | List subscriptions |
| add <url> | Add subscription |
| remove [url] | Remove subscription(s) |
| update | Update subscriptions |
| auto-update <on\|off> | Toggle auto-update |
| filter <action> | Manage filter keywords |
| status | Show subscription status |

**Examples:**

```
homeproxy subscription <action> [options]
```

### status

Show HomeProxy status

```
homeproxy status
```

### log

Show logs (homeproxy|sing-box-c|sing-box-s)

| Action | Description |
|--------|-------------|
| [type] | Show logs |
| clean [type] | Clear log file |

**Examples:**

```
homeproxy log <action> [options]
```

### control

Service control

| Action | Description |
|--------|-------------|
| start | Start HomeProxy |
| stop | Stop HomeProxy |
| restart | Restart HomeProxy |
| status | Show service status |

**Examples:**

```
homeproxy control <action> [options]
```

### features

Show sing-box features

```
homeproxy features
```

### resources

Resource management

| Action | Description |
|--------|-------------|
| version [type] | Show resource version (china_ip4, china_ip6, china_list, gfw_list) |
| update <type> | Update resource |

**Examples:**

```
homeproxy resources <action> [options]
```

### acl

ACL list management

| Action | Description |
|--------|-------------|
| list <type> | List direct_list or proxy_list content |
| write <type> --file <path> | Write ACL from file |

**Examples:**

```
homeproxy acl <action> [options]
```

### cert

Write certificate (client_ca, server_publickey, server_privatekey)

| Action | Description |
|--------|-------------|
| write <filename> --file <path> | Write certificate |

**Examples:**

```
homeproxy cert <action> [options]
```

### generator

Generate keys (uuid, reality-keypair, wg-keypair, vapid-keypair, ech-keypair)

| Action | Description |
|--------|-------------|
| <type> [params] | Generate keys |

**Examples:**

```
homeproxy generator <action> [options]
```

### completion

Output bash completion script

| Action | Description |
|--------|-------------|
| bash | Bash completion script |

**Examples:**

```
homeproxy completion <action> [options]
```

### docs

Generate Markdown reference (from-first-src)

| Action | Description |
|--------|-------------|
| [--out <file>] | Output Markdown to stdout or file |

**Examples:**

```
homeproxy docs <action> [options]
```

## Options

| Option | Description |
|--------|-------------|
| `-h`, `--help` | Show help |
