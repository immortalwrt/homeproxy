
可以概括成一句话：

> **复用 LuCI 层，是因为复杂逻辑都在那里；Go CLI 负责做一层对 LLM agent 友好的薄客户端。**

关键区别：**人类手点 LuCI 网页** vs **agent 接近全自动调 CLI 来第一次初始化配置和启动homeproxy的透明代理**——同一套底层能力，两种操作入口。

有 LuCI 时，人类可先在 LuCI 上做首次配置，与 agent 协作好后，后续可自行选择：用 **Go CLI** 或进 **LuCI Web** 修改，二者共享同一套 UCI 配置。

---

## 1. 复杂逻辑已经实现在 LuCI 层

| 能力                                       | 实现位置                                   | 若自己重写                               |
| ------------------------------------------ | ------------------------------------------ | ---------------------------------------- |
| 订阅解析（多协议、编码、过滤）             | `update_subscriptions.uc` + luci.homeproxy | 需要实现整套订阅解析与 UCI 同步          |
| 规则集拉取与更新（china_ip4、gfw_list 等） | `resources_update`                         | 需要拉取、校验、写文件                   |
| 节点连通性测试                             | `connection_check`                         | 需要与 sing-box 能力对接                 |
| ACL 读写、证书写入、密钥生成               | luci.homeproxy 各 RPC                      | 需要逐个实现并保证与 sing-box 一致       |
| 配置生成（UCI → sing-box JSON）            | `generate_client.uc`                       | 逻辑复杂、易出错，且与 UCI schema 强绑定 |

这些逻辑已经在 luci-app-homeproxy 里实现并验证过，单独用 Go 再实现一遍成本高、易偏离上游。

---

## 2. Go CLI 的定位：薄客户端 + 入口

Go CLI 的职责是：

- 提供**非交互、可脚本化**的命令行入口
- 保持**稳定、可解析**的输出（便于 agent 解析）
- 统一通过 `os/exec` 调用 `uci`、`ubus`、`/etc/init.d/homeproxy`

逻辑上，它把「人类手点 LuCI 网页」换成「agent 接近全自动调 CLI」，底层仍由 LuCI 和 ucode 完成实际工作。

---

## 3. 为什么不做「绕过 LuCI 的纯 Go 实现」？

- 若完全绕过 LuCI：订阅、规则集、测试、ACL、证书、密钥等都要在 Go 中重做，等同于重写一整套 HomeProxy 业务逻辑，维护和与上游同步都会很重。
- 若复用 LuCI 层：只需要实现一层调用 `uci` / `ubus` / init.d 的薄客户端，就能利用现有能力，保持与 LuCI Web 同一套数据和行为。

因此选择的是「复用 LuCI 层」，而不是「替代 LuCI 层」。

---

## 4. 总结

- **LLM agent friendly**：Go CLI 提供清晰的、非交互的、输出稳定的 CLI，适合 agent 调用。
- **复用 LuCI 层**：把复杂业务（订阅、规则集、测试、ACL、证书等）交给已有的 luci.homeproxy + ucode，Go CLI 只做调用与展示。
- **结果**：以较小实现成本，既得到对 agent 友好的接口，又复用上游实现，并保持与 LuCI Web 同一套配置和行为。
- **核心对比**：人类手点 LuCI 网页（适合人工运维） vs agent 接近全自动调 CLI（适合脚本、CI、LLM 流水线）。
- **协作方式**：人类可先在 LuCI 完成首次配置、与 agent 协作好后，后续自行选择 Go CLI 或 LuCI Web 修改，二者共用同一 UCI。