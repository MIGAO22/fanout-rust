# fanout-rust

[fanout](https://github.com/MIGAO22/fanout) 的 Rust 全量重构版：把 VPN Gate 的公共 OpenVPN 节点转换成本地 SOCKS5 出口，并可选择叠加 Cloudflare WARP。前端、工作目录和主要操作方式与 Go 版保持兼容。

稳定版：[v1.1.1](https://github.com/MIGAO22/fanout-rust/releases/tag/v1.1.1)

历史测试版：[Releases](https://github.com/MIGAO22/fanout-rust/releases)

## 功能

- 每条出口独立运行在 Linux network namespace 中，母机上网不受影响。
- 一条出口对应一个本地 SOCKS5 端口，支持 TCP CONNECT、UDP ASSOCIATE 和 DNS。
- 自动拉取、评分和缓存 VPN Gate 节点；主接口限流时通过 curl 或在线出口兜底。
- 健康检查、失败候选轮换、退避重连、节点超时替换和旧 WARP 账号清理。
- 可选的 Cloudflare WARP 中转：注册、WireGuard 握手、分流路由和超时自动替换。
- 出口组：单一出口、轮询出口、负载均衡、并发出口。
- 出口组自动补位、首选国家、60% 国家配额、在线出口复用和全局 20 台上限。
- 实时出口指标：探活延迟、抖动、丢包、SOCKS 吞吐、重连与失败时间线。
- 智能选路：EWMA 质量评分、失败节点隔离、最短驻留、切换冷却和出口组自动策略。
- WARP 账号池：槽位租约隔离、有界注册队列、后台预热、失败轮换和清理审计。
- 3x-ui、自建 Xray、xray-cf-lite 三种节点链接后端。
- 内嵌 Web 管理界面、订阅链接、客户端管理、主机负载和自更新。
- amd64 / arm64 双架构 Release，提供 SHA256 校验和。

## 架构

```text
浏览器 / 订阅客户端
        │
        ▼
Axum Web API ────────────────┐
        │                    │
        ▼                    ▼
Manager              PoolService / WarpService
        │                    │
        ▼                    ▼
LinuxTunnelRuntime ◄─── 策略与账号状态
        │
        ├── network namespace + veth + NAT
        ├── OpenVPN / WireGuard 子进程
        ├── 本地 SOCKS5 TCP / UDP relay
        └── DNS cache / exit-IP 健康检查

PanelManager
        ├── 3x-ui API
        ├── native Xray
        └── xray-cf-lite
```

- `Manager` 负责出口生命周期、节点选择、重连和健康检查。
- `PoolService` 负责出口组监听、四种选路策略、探测和自动补位。
- `NodeHealthStore` 汇总探活、连接和 WARP 握手历史，为候选排序与隔离提供动态评分。
- `ObservabilityStore` 保存有界指标与健康时间线，并渲染 Prometheus 文本。
- `WarpService` 负责 Cloudflare 账号、注册限流、握手和分流；账号池模式额外管理租约、预热与审计。
- `PanelManager` 统一管理三种节点链接后端，切换模式时保留同一套出口状态。
- Web 静态资源通过 `rust-embed` 编入二进制，不需要额外部署前端文件。

## 为什么用 Rust

- **内存与并发安全**：所有权、借用检查和 `Send/Sync` 在编译期拦截数据竞争与释放后使用。
- **异步 I/O**：Tokio 用少量线程处理大量 SOCKS 连接、DNS、面板请求和子进程事件。
- **可预测的资源回收**：`Drop`、`CancellationToken`、`JoinSet` 和 generation 机制统一清理连接、进程、netns 与旧任务。
- **低开销**：无 GC、无虚拟机，release 启用 ThinLTO、单 codegen unit 和符号剥离。
- **单二进制交付**：前端嵌入二进制，安装、升级和回滚路径更短。
- **可测试性**：策略、路由、解析、更新和生命周期核心均有单元测试，CI 同时验证 amd64 与 arm64。

## 环境要求

- Linux，root 运行。
- 内核支持 `network namespace`、`TUN/TAP`、`veth`、策略路由和 NAT。
- `iproute2`、`iptables` 或 `nftables`、`curl`、`ca-certificates`、`tar`。
- OpenVPN 出口需要 `openvpn`；WARP 需要 `wireguard-tools`。
- `systemd` 或 OpenRC。
- 3x-ui 模式需要本机已安装并可访问 3x-ui；native 模式需要 Xray 二进制。

Ubuntu / Debian 常见依赖：

```bash
apt update
apt install -y openvpn wireguard-tools iproute2 iptables curl ca-certificates tar
```

## 安装

### 一键安装

```bash
REPO=MIGAO22/fanout-rust bash <(curl -fsSL https://raw.githubusercontent.com/MIGAO22/fanout-rust/main/install.sh)
```

可选环境变量：

```bash
WORK_DIR=/var/lib/fanout WEB_PORT=8899 REPO=MIGAO22/fanout-rust bash <(curl -fsSL https://raw.githubusercontent.com/MIGAO22/fanout-rust/main/install.sh)
```

安装脚本会：

1. 下载最新 Release 和 `checksums.txt`，强制校验 SHA256。
2. 对二进制执行版本自检。
3. 备份旧二进制和服务文件。
4. 安装 `fanout-rust`、服务单元和管理菜单 `f`。
5. 启动服务并检查运行状态；失败时通过 EXIT trap 回滚。

### 手动运行

```bash
fanout-rust -dir /var/lib/fanout -web 8899
```

### 从源码构建

需要 Rust 1.85+：

```bash
cargo build --release --target x86_64-unknown-linux-gnu
```

产物：

```text
target/x86_64-unknown-linux-gnu/release/fanout-rust
```

arm64：

```bash
rustup target add aarch64-unknown-linux-gnu
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
  cargo build --release --target aarch64-unknown-linux-gnu
```

## 命令行参数

| 参数 | 说明 |
| --- | --- |
| `-dir <目录>` | 工作目录，默认 `/var/lib/fanout` |
| `-web <端口>` | 显式覆盖管理端口；不传时读取 `settings.json` |
| `-max <数量>` | 最大出口数，默认 20，硬上限 20 |
| `-panel <模式>` | `3x-ui`、`native`、`xray-cf-lite` |
| `-ip <地址>` | 覆盖母机公网 IPv4，用于分享链接 |
| `-version` | 显示版本 |
| `-h` | 显示帮助 |

## 首次启动与登录

首次启动会在工作目录生成：

```text
password       管理口令
basepath       Web 访问路径
settings.json  Web 与连接参数
state.json     出口状态
pools.json     出口组
warp.json      WARP 账号
```

假设端口为 `8899`、路径为 `migao`：

```text
http://服务器IP:8899/migao/
```

请使用带尾斜线的地址。口令和访问路径不要提交到 Git 或发到公开渠道。

## Web 功能

- **出口总览**：新建、停止、换节点、重置 SOCKS 凭据、查看出口 IP 和 WARP 状态。
- **出口组**：创建/编辑组、选择策略、首选国家、维持条数和自动补位。
- **节点链接**：查看 3x-ui/native 入站、绑定出口、解绑回直连、管理客户端和订阅。
- **设置与连接**：管理端口、监听地址、住宅节点过滤、健康检查、退避、节点缓存和 WARP 握手超时。
- **内置客户端**：Xray、OpenVPN、WARP 版本检查与升级。
- **主机负载**：CPU、内存、磁盘、网络速率、socket 和 FD 使用情况。

## 出口组策略

| 界面名称 | 内部模式 | 行为 |
| --- | --- | --- |
| 单一出口 | `single` | 固定使用一条，失败后按顺序尝试下一条 |
| 轮询出口 | `roundrobin` | 每 N 个新目标切换一次出口 |
| 负载均衡 | `latency` | 在延迟接近的最快出口之间轮换，避免单条过载 |
| 并发出口 | `race` | 同时向多条出口拨号，使用最先成功的一条 |

自动补位：

- 优先复用在线空闲出口，其次复用其他组共享的在线出口。
- 首选国家不足时，会优先从首选国家新建；没有可用首选节点时允许其他国家补足，避免整组停摆。
- 默认目标为首选国家至少占维持条数的 60%。
- 全局最多 20 条出口，并保留槽位余量防止补位打满。
- 失败节点进入冷却，成功后清理 avoidance 和失败账本。

## 智能选路与防抖

- 动态评分使用探活延迟、应用层丢包、WARP 握手成功率和连续失败历史；没有样本的节点保持中性。
- 连续失败达到阈值后节点进入隔离，候选排序会暂时跳过；成功探活会解除隔离。
- 自动切换遵守最短驻留和切换冷却，OpenVPN 进程退出等硬故障仍立即重连。
- 出口组可开启“自动调整策略”：根据成员数量、延迟差、冷却比例和样本量在单一、轮询、均衡、并发之间选择，并带当前策略偏好避免来回抖动。

## WARP 中转

WARP 开启后，流量路径为：

```text
客户端 → fanout SOCKS5 → WARP/WireGuard → VPN Gate 出口 → 目标
```

- 注册并发限制为 2，遇到 HTTP 429 按 `Retry-After` 和指数退避重试。
- 新账号注册并落盘成功后才注销旧账号。
- 握手预检超时为 15 秒；已连通出口持续未握手，或新建出口最终失败，都会按「WARP 握手超时」计时，超时后自动换节点重连。
- 自动换节点保留原槽位、SOCKS5 端口和凭据，并先清理旧 WARP 注册，避免失败出口永久滞留。
- 停止的槽位会清理远端 WARP 账号，避免账号和密钥无限增长。
- 分流路由失败会拒绝把流量暴露为直连。

### WARP 账号池

账号池默认关闭，开启后每个槽位只租用一个账号：

- 新出口优先使用 `Ready` 预热账号，注册并发仍限制为 2，队列满时明确返回背压。
- 连续握手失败达到设置次数后，账号退出租约并进入轮换/清理流程。
- 预热账号带有效期，过期或客户端版本变化后会被替换。
- 租约、注册、预热、轮换和清理都会写入审计；审计不记录 token 或私钥。

## 可观测性

- 出口卡片显示探活延迟、抖动、最近丢包比例、SOCKS 上行/下行速率、重连和失败次数。
- 管理页提供有界健康时间线：默认折叠，标题行显示最新事件，展开后为单行紧凑列表并支持滚动。
- `GET /metrics` 输出 Prometheus 文本；本机回环地址可直接访问，远程访问需在设置中配置 Bearer 令牌。
- 设置 `FANOUT_LOG_FORMAT=json` 后，服务日志切换为结构化 JSON。

## 节点链接后端

### 3x-ui

通过本机 3x-ui HTTP API 读取入站、修改路由和重载 Xray。fanout 会：

- 复用 HTTP 连接、设置 TCP_NODELAY 和连接超时。
- 合并读取入站列表与 Xray 配置。
- 批量绑定多个入站并只保存/重载一次。
- 配置未变化时跳过写入和重启。
- 凭据、出口组或隧道变化后重新同步 outbound。

### native

fanout 自己管理 Xray 配置和进程。配置先校验，再原子替换并重启；启动失败会恢复旧配置和旧状态。失效绑定会 block，不会静默回落直连。

### xray-cf-lite

接管现有 xray-cf-lite 配置，只维护 fanout 所需的路由和 outbound。

## SOCKS5、UDP 与 DNS

- 每条出口默认监听 `0.0.0.0:<随机端口>`，使用用户名/口令认证。
- TCP relay 使用 32 KiB 缓冲、`TCP_NODELAY` 和双向背压。
- UDP ASSOCIATE：
  - relay 仅绑定实际本地地址；
  - 校验 UDP 源地址，未指定客户端端点时回退到 TCP peer；
  - 每个控制连接最多 256 个 UDP 会话；
  - 控制连接仅在 EOF 或错误时结束，普通控制字节不会中断关联；
  - 空闲 60 秒自动清理。
- DNS 缓存键包含 `(network namespace, hostname, port)`，TTL 60 秒。
- 同一个 DNS key 的并发解析使用 single-flight，避免缓存击穿。
- 目标解析和拨号保留在对应 netns 内，避免 DNS 泄漏和跨命名空间复用。

## 常用配置

`settings.json` 示例：

```json
{
  "port": 8899,
  "listen_addr": "0.0.0.0",
  "residential_only": true,
  "metrics_token": "",
  "warp": {
    "enabled": true,
    "client_version": "2026.8.2115.0",
    "pool": {
      "enabled": false,
      "prewarm": false,
      "size": 4,
      "prewarm_ttl_secs": 1800,
      "rotate_after_failures": 3
    }
  },
  "conn": {
    "health_interval": 10,
    "health_failures": 3,
    "health_timeout": 6,
    "backoff_min": 5,
    "backoff_max": 60,
    "connect_budget": 35,
    "max_tries": 6,
    "panel_debounce": 1500,
    "node_ttl": 600,
    "score_mode": "balanced",
    "reconnect_limit": 2,
    "warp_handshake_timeout": 5,
    "aead_only": false,
    "smart_selection": true,
    "min_dwell_secs": 60,
    "switch_cooldown_secs": 30,
    "node_quarantine_secs": 120
  }
}
```

| 配置 | 默认 | 说明 |
| --- | ---: | --- |
| `health_interval` | 10 | 健康检查间隔，秒 |
| `health_failures` | 3 | 判定掉线所需连续失败次数 |
| `health_timeout` | 6 | 单次出口 IP 探测超时，秒 |
| `backoff_min` / `backoff_max` | 5 / 60 | 重连退避范围，秒 |
| `connect_budget` | 35 | 单次节点连接预算，秒 |
| `max_tries` | 6 | 每轮尝试候选节点数 |
| `node_ttl` | 600 | 节点缓存有效期，秒 |
| `score_mode` | `balanced` | `balanced` / `speed` / `idle` / `ping` |
| `reconnect_limit` | 2 | 重连候选限制 |
| `warp_handshake_timeout` | 5 | WARP 连续未握手或出口最终失败后，自动清除并换节点重连的分钟数 |
| `aead_only` | false | 对支持 AEAD 的节点关闭非 AEAD 数据通道 |
| `smart_selection` | true | 按实时健康评分排序候选节点 |
| `min_dwell_secs` | 60 | 自动切换前的最短驻留时间，秒 |
| `switch_cooldown_secs` | 30 | 两次自动切换之间的冷却时间，秒 |
| `node_quarantine_secs` | 120 | 连续失败节点的初始隔离时间，秒 |

## 更新与回滚

### Web 或 `f` 菜单更新

- 必须存在 `checksums.txt`，否则拒绝更新。
- 校验压缩包 SHA256。
- 只解包 `fanout-rust` 二进制。
- 执行 `-version` 自检并核对版本。
- 替换前保留 `.prev` 备份。
- 检查服务重启结果；`f` 菜单还会比较 PID 和实际运行版本，失败自动回滚。

### 手动回滚

```bash
systemctl stop fanout-rust
cp -p /usr/local/bin/fanout-rust.prev /usr/local/bin/fanout-rust.rollback
mv -f /usr/local/bin/fanout-rust.rollback /usr/local/bin/fanout-rust
systemctl start fanout-rust
```

## 安全建议

- VPN Gate 是公共、无 SLA 的免费节点，不应视为可信网络或匿名保证。
- SOCKS5 端口默认对外监听，请用防火墙限制来源。
- 管理端口不要直接暴露到公网；需要远程管理时使用 SSH 隧道或反向代理。
- 不要在 URL、日志或命令行中传递 SOCKS 口令。
- 定期更新系统和 OpenVPN/WireGuard/Xray。
- WARP 账号 token 和私钥保存在 `warp.json`，文件权限为 `0600`。

## 压力测试

测试环境：Ubuntu VPS，fanout-rust `v0.0.28` / `v0.0.29`，真实 VPN Gate 出口与 Cloudflare WARP。

| 项目 | 结果 |
| --- | --- |
| Rust 单元测试 | 285 项通过 |
| CI 架构 | amd64、arm64 均构建通过 |
| 出口组 5 MB 下载 | 约 47 Mbps |
| 40 路并发连接 | 40/40 成功 |
| 5 分钟 32 路 soak | 13,087 次请求，7 次上游失败（约 0.053%） |
| soak 延迟 | 中位数约 176 ms，P95 约 469 ms |
| UDP DNS | 成功，单次约 80–182 ms |
| API 读取 | 隧道中位数约 0.6 ms；入站约 5–7 ms |
| 资源回收 | soak 结束后 FD 回到约 39，RSS 约 18 MiB |
| UDP 安全 | 伪造源被拒绝、指定端点兼容、控制字节不中断关联 |

说明：公共 VPN 节点本身会波动。单出口长测可能出现约 1% 的失败；出口组通过多成员竞速和失败冷却，把 5 分钟 soak 失败率降到约 0.05%。吞吐取决于当时节点、WARP 和目标服务器，不代表固定 SLA。

## 故障排查

### 服务无法启动

```bash
systemctl status fanout-rust -l
journalctl -u fanout-rust -n 100 --no-pager
fanout-rust -version
```

### 端口无法访问

```bash
ss -ltnp | grep fanout
curl -v http://127.0.0.1:8899/你的basepath/
```

### WARP 一直握手失败

- 检查 `wireguard-tools` 是否安装。
- 检查母机 UDP 出站是否被防火墙阻断。
- 查看 `warp.json` 和日志中的 429、握手超时或路由错误。
- 调低 `warp_handshake_timeout` 可更快触发自动替换。

### OpenVPN 失败

```bash
journalctl -u fanout-rust | grep -E 'openvpn|tun0|redirect-gateway'
```

### 3x-ui 绑定不生效

- 确认 3x-ui API token 可访问。
- 检查入站 `tag` 是否变化。
- 确认绑定目标出口或出口组仍在运行。
- fanout 会拒绝把失效绑定改成直连。

## 开发与测试

```bash
cargo fmt --all -- --check
cargo check --all-targets
cargo test --all -- --test-threads=1
bash -n f.sh install.sh
node --check web/app.js
```

CI 工作流：

- `test`：格式、类型、单测、amd64 与 arm64 构建。
- `release`：先通过测试，再构建双架构包、生成校验和并发布 Release。

## License

MIT
