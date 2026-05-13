# HomeProxy-hiddify

A modern ImmortalWrt proxy platform powered by [hiddify-core](https://github.com/hiddify/hiddify-core).

## Overview

HomeProxy Hiddify is a feature-rich proxy management system built on the ImmortalWrt platform. 
Multi-Protocol Support: Naive, Mieru, Hysteria, SOCKS, Shadowsocks, ShadowTLS, Tor, Trojan, VLess, VMess, WireGuard, SSH and more.

## Key Features

- **Modern Web Interface** - Clean and responsive UI for easy proxy management (TBD)
- **Multi-Protocol Support** - Support for various proxy protocols via hiddify-core
- **Node Management** - Efficiently manage multiple proxy nodes (TBD)
- **ACL (Access Control Lists)** - Advanced traffic routing and filtering rules (TBD)
- **NFT Rules** - Network filter table rule management for fine-grained traffic control (TBD)
- **Subscription Support** - Built-in subscription management for proxy nodes (TBD)

## ⚠️ Early Stage Project

This project is currently in an **early stage of development**. The web UI configuration is still being developed and will be improved in future versions. 
For now, configuration should be done through the core configuration file.


## Prerequisites

- OpenWRT router/system - 24.10 or higher

## Installation

### 1. Install the package

Download the latest `.ipk` from [Releases](https://github.com/1andrevich/homeproxy-hiddify/releases) and install it on your router:

```sh
opkg install luci-app-homeproxy-hiddify_*.ipk
```

Or install directly:

```sh
curl -Lo /tmp/homeproxy.ipk \
  https://github.com/1andrevich/homeproxy-hiddify/releases/latest/download/luci-app-homeproxy_latest_all.ipk
opkg install /tmp/homeproxy.ipk
```

### 2. Install hiddify-core binary

Download the appropriate binary for your router architecture from [hiddify-core releases](https://github.com/hiddify/hiddify-core/releases): \
`For OpenWRT - musl only`

```sh
# Example for aarch64 (ARM64 routers)
curl -Lo /tmp/hiddify-core.tar.gz \
  https://github.com/hiddify/hiddify-core/releases/download/v4.1.0/hiddify-core-linux-arm64-musl.tar.gz
tar -zxvf /tmp/hiddify-core.tar.gz -C /tmp
mv /tmp/hiddify-core /usr/bin/hiddify-core
chmod +x /usr/bin/hiddify-core
rm /tmp/hiddify-core.tar.gz
```

Check your architecture with `uname -m`and `opkg print-architecture` .

### 3. Add your proxy config

Place your sing-box compatible JSON config at `/etc/homeproxy/hiddify-c.json`.

> **Required:** add `"default_mark": 100` inside the `"route": {}` section to prevent tproxy routing loops:
>
> ```json
> "route": {
>     "default_mark": 100,
>     ...
> }
> ```

Also add (or merge) the following sections into your config:

**Log:**
```json
"log": {
    "disabled": false,
    "level": "warn",
    "output": "/var/run/homeproxy/hiddify-c.log",
    "timestamp": true
}
```

**Inbounds:**
```json
"inbounds": [
    {
        "type": "direct",
        "tag": "dns-in",
        "listen": "::",
        "listen_port": 5333
    },
    {
        "type": "mixed",
        "tag": "mixed-in",
        "listen": "::",
        "listen_port": 5330,
        "udp_timeout": "300s",
        "sniff": true,
        "sniff_override_destination": true,
        "set_system_proxy": false
    },
    {
        "type": "redirect",
        "tag": "redirect-in",
        "listen": "::",
        "listen_port": 5331,
        "sniff": true,
        "sniff_override_destination": true
    },
    {
        "type": "tproxy",
        "tag": "tproxy-in",
        "listen": "::",
        "listen_port": 5332,
        "network": "udp",
        "udp_timeout": "300s",
        "sniff": true,
        "sniff_override_destination": true
    }
]
```

### 4. Start the service

```sh
/etc/init.d/homeproxy start
```

The service will auto-start on boot. Monitor logs at **Services → HomeProxy → Status**.
