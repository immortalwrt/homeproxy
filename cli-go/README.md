# HomeProxy Go CLI

Go 实现的 HomeProxy 命令行工具，无 shell 依赖。只二次封装 openwrt-luci 层，对 homeproxy 底层无改动。

## 构建

```bash
go build -o bin/homeproxy ./cmd/homeproxy
```

## 安装

```bash
go install ./cmd/homeproxy
# 或复制到系统路径（需 root）
go build -o bin/homeproxy ./cmd/homeproxy && sudo cp bin/homeproxy /usr/bin/
```

## OpenWrt 独立包分发

CI 会单独产出 `homeproxy-cli` 包（与 `luci-app-homeproxy` 分离），用于直接在 OpenWrt 安装：

```bash
opkg install /tmp/homeproxy-cli_*.ipk
```

## Bash 补全

```bash
homeproxy completion bash | sudo tee /etc/bash_completion.d/homeproxy
# 或当前会话
source <(homeproxy completion bash)
```

## 文档生成

```bash
# 输出到 stdout
homeproxy docs

# 写入文件（目录不存在时会自动创建）
homeproxy docs --out docs/CLI_REFERENCE.md
```

帮助与 Markdown 文档均从源码元数据生成（from-first-src），无需手写。

## 分享链接导入

`node import` 支持导入分享链接（如 `hy2://`、`ss://`、`trojan://`、`vmess://`、`vless://` 等）和订阅 URL：

```bash
homeproxy node import 'hy2://password@1.2.3.4:443?sni=example.com#node-a'
homeproxy node import 'https://example.com/subscription-url'
```

## 机器 / LLM 友好输出

部分命令支持 `--json`，方便脚本和 LLM 消费：

```bash
homeproxy status --json
homeproxy node list --json
homeproxy subscription list --json
homeproxy routing get --json
homeproxy dns get --json
```

JSON 输出写到 stdout，字段稳定且不会转义 HTML 字符，适合被 `jq`、自动化脚本或 LLM 直接解析。

## 测试

```bash
go test ./...
```

详见 [TESTING.md](TESTING.md)。
