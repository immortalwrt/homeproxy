# luci-app-unison

A modern OpenWrt proxy platform for ARM64/AMD64, built as a LuCI frontend for [sing-box](https://github.com/SagerNet/sing-box).

## Features

- **Multiple proxy modes** — Redirect TCP, TProxy UDP, TUN (TCP/UDP)
- **Routing modes** — Bypass mainland China, Global, Custom
- **Subscription management** — Import nodes via URL, auto-update on schedule, filter by keyword blacklist/whitelist
- **Wide protocol support** — VMess, VLESS, Trojan, Shadowsocks, Hysteria, Hysteria2, TUIC, AnyTLS, HTTP/HTTPS, SOCKS5
- **Transport support** — TCP, WebSocket, HTTP/2, gRPC, HTTPUpgrade
- **DNS management** — Dual-stack DNS with China/overseas split, optional cache, IPv6 strategy
- **Per-LAN-device policy** — Selectively proxy or bypass individual devices on the LAN
- **Geo-data** — Bundled China IP lists (IPv4/IPv6), China domain list, and GFW list with auto-update via cron
- **Inbound server mode** — Accept connections from other devices
- **Real-time status** — Live log viewer and connection health check
- **IPv6 support**
- **nftables-based firewall rules** (requires firewall4 + kmod-nft-tproxy)
- **i18n** — English and Simplified Chinese

## Dependencies

| Package | Purpose |
|---|---|
| `sing-box` | Proxy core |
| `firewall4` | nftables firewall integration |
| `kmod-nft-tproxy` | Kernel TProxy support |
| `ucode-mod-digest` | Config hashing |

## Installation

### Pre-built IPK

Download the latest `.ipk` from the [Releases](../../releases) page and install it:

```sh
opkg install luci-app-unison_*.ipk
```

### Build from source

In your OpenWrt buildroot:

```sh
# Add as a feed or drop the package directory under package/
make package/luci-app-unison/compile V=s
```

The package is built automatically via GitHub Actions on every push to `master`/`dev` and on each release.

## Configuration

After installation, navigate to **Services → Unison** in the LuCI web interface.

1. **Node / Subscription** — Add proxy nodes manually or via a subscription URL.
2. **Client** — Select your main node, routing mode, proxy mode, and DNS settings.
3. **Server** *(optional)* — Enable the inbound listener for other devices to connect through this router.
4. **Status** — Check live logs and test connectivity.

Key UCI config file: `/etc/config/unison`

## Persistent files

The following paths are preserved across package upgrades:

```
/etc/config/unison
/etc/unison/certs/
/etc/unison/ruleset/
/etc/unison/resources/direct_list.txt
/etc/unison/resources/proxy_list.txt
```

## License

GPL-2.0-only © 2022–2025 [ImmortalWrt.org](https://immortalwrt.org)
