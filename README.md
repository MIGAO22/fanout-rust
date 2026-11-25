# fanout-rust

[fanout](https://github.com/MIGAO22/fanout) 的 Rust 重构版：把 VPN Gate 公共节点变成本地 SOCKS5 出口，保留原版 Web 界面与操作方式。

当前处于逐模块迁移阶段，可运行版本以 [Releases](https://github.com/MIGAO22/fanout-rust/releases) 为准；版本号从 `v0.0.1` 开始，按实际跑通的里程碑递增。

## 构建

需要 Rust 1.85+：

```bash
cargo build --release --target x86_64-unknown-linux-gnu
```

产物：`target/x86_64-unknown-linux-gnu/release/fanout-rust`。

## 运行

```bash
fanout-rust -dir /var/lib/fanout -web 8899
```

参数与 Go 版一致：`-dir`、`-web`、`-max`、`-panel`、`-ip`、`-version`。工作目录仍使用 `/var/lib/fanout`，可读取原版状态文件；前端文件原样嵌入二进制。

## 安装

```bash
REPO=MIGAO22/fanout-rust bash <(curl -fsSL https://raw.githubusercontent.com/MIGAO22/fanout-rust/main/install.sh)
```

服务名为 `fanout-rust`，管理菜单仍为 `f`。
