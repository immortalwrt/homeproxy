# Go CLI 如何控制 HomeProxy —— 分层架构

## 一、为什么 Go CLI 能控制 HomeProxy？

Go CLI **不直接**操作 sing-box 或 HomeProxy 核心，而是作为 **OpenWrt 系统接口的客户端** 间接控制。
与 LuCI Web 共用同一套底层通道（`uci`、`ubus`、`/etc/init.d/homeproxy`），未改动 HomeProxy 底层实现，只做了 Go 封装。

---

## 二、四层架构

自上而下：**Go CLI 层 → OpenWrt 层 → HomeProxy 执行层 → OS 层**。

```
┌─────────────────────────────────────────────────────────────────────────┐
│  L1: Go CLI 层                                                           │
│  homeproxy 二进制、main.go、命令处理、internal/system                     │
└──────────────────────────────────────┬──────────────────────────────────┘
                                       │ os/exec (uci, ubus, init.d)
                                       ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  L2: OpenWrt 层                                                          │
│  uci / ubus / rpcd / init.d（OpenWrt 系统工具与服务）                     │
└──────────────────────────────────────┬──────────────────────────────────┘
                                       │ 配置读写 / RPC 调用 / 进程控制
                                       ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  L3: HomeProxy 执行层                                                    │
│  /etc/config/homeproxy | luci.homeproxy RPC | /etc/init.d/homeproxy     │
│  配置、脚本、ucode 后端                                                  │
└──────────────────────────────────────┬──────────────────────────────────┘
                                       │ 读写文件 / 起停进程
                                       ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  L4: OS 层                                                               │
│  /etc/config/homeproxy、/var/run/homeproxy/*.log、sing-box 进程          │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 三、各层职责

### L1: Go CLI 层

| 组件 | 职责 |
|------|------|
| `cmd/homeproxy/*.go` | 命令路由、参数解析、调用 system 适配 |
| `helpers.go` | 统一的 JSON 输出（`writeJSON`）、root 权限校验等 CLI 辅助逻辑 |
| `args.go` | 通用参数解析（如 `--json` 等全局选项） |
| `sharelink.go` | 分享链接解析（`hy2/ss/trojan/vmess/vless/...`）与导入写入逻辑 |
| `internal/system` | UCIGet/UCISet/UBUSCall/Service*，封装 `os/exec` |
| `runCommand` | 执行 `uci`、`ubus`、`/etc/init.d/homeproxy` |

### L2: OpenWrt 层

| 工具/服务 | 职责 |
|-----------|------|
| `uci` | 读写 UCI 配置（get/set/show/add/delete/commit） |
| `ubus` | 调用 RPC（`ubus call luci.homeproxy <method> '<params>'`） |
| `rpcd` | 承载 `luci.homeproxy` 的 ucode 后端 |
| `init.d` | 管理 procd 服务（start/stop/restart/reload/status） |

### L3: HomeProxy 执行层

| 组件 | 路径/对象 | 职责 |
|------|-----------|------|
| UCI 配置 | `/etc/config/homeproxy` | 节点、路由、DNS、订阅等配置 |
| RPC 后端 | `luci.homeproxy` | 资源、ACL、证书、连接检测、密钥生成、日志清理 |
| 服务脚本 | `/etc/init.d/homeproxy` | 生成 sing-box 配置，控制 sing-box 进程，防火墙规则 |

### L4: OS 层

| 资源 | 职责 |
|------|------|
| `/etc/config/homeproxy` | 配置持久化 |
| `/var/run/homeproxy/*.log` | 日志文件 |
| sing-box 进程 | 代理核心，由 init.d 起停 |
| `/tmp`、`/usr/bin` 等 | 临时文件、二进制路径 |

---

## 四、调用链示例

| CLI 命令 | L1 → L2 → L3 → L4 |
|----------|-------------------|
| `homeproxy status` | Go CLI → `uci get` + `init.d status` + `ubus singbox_get_features` → 配置/状态/RPC → 文件/进程 |
| `homeproxy control start` | Go CLI → `/etc/init.d/homeproxy start` → init.d → 启动 sing-box |
| `homeproxy node set-main X` | Go CLI → `uci set` + `uci commit` + `init.d reload` → UCI → 写配置并重载 sing-box |
| `homeproxy node import <share-link|url>` | Go CLI 先在 L1 解析分享链接；有效节点走 `uci add/set/add_list`；订阅 URL 走 `uci add_list subscription_url`；最后 `uci commit` + `init.d reload` |
| `homeproxy log [type]` | Go CLI → `os.ReadFile` → 直接读 `/var/run/homeproxy/<type>.log`（跳过 L2/L3） |
| `homeproxy features` | Go CLI → `ubus call luci.homeproxy singbox_get_features` → rpcd → ucode 后端 |

---

## 五、目录与接口映射

### Go CLI 目录结构

```
cli-go/
├── cmd/homeproxy/      # L1 命令实现
├── internal/system/    # L1→L2 适配（runCommand 封装）
└── testutil/mock.go    # 测试时 mock L2 调用
```

### CLI 命令到接口映射

| CLI 命令 | 主要使用 L2 接口 |
|----------|------------------|
| status | init.d status, uci get, ubus singbox_get_features |
| control | init.d |
| log [type] | 直接读文件（L4） |
| log clean | ubus log_clean |
| features | ubus singbox_get_features |
| resources | ubus resources_get_version / resources_update |
| acl | ubus acllist_read / acllist_write |
| cert | 文件 + ubus certificate_write |
| generator | ubus singbox_generator |
| node | `uci`（节点增删改查、share-link 导入）+ `ubus connection_check`（test） |
| routing | uci |
| dns | uci |
| subscription | uci (+ 更新脚本) |
| completion / docs | 纯 L1，本地输出，不调用 L2 |

---

## 六、总结

- **分层**：Go CLI → OpenWrt（uci/ubus/init.d）→ HomeProxy（配置 + RPC + init 脚本）→ OS（文件、进程）
- **控制链路**：`Go CLI → os/exec → uci | ubus | init.d → 配置/RPC/sing-box`
- **设计原则**：薄适配层、显式 shell 调用、可 mock 测试
- **机器友好输出**：统一的 `writeJSON` helper 负责 JSON 编码，便于脚本和 LLM 消费。
