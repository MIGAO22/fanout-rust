#!/usr/bin/env bash
# fanout-rust 安装脚本：装二进制、装服务（systemd 或 OpenRC）、开机自启。
#
# Alpine 默认不带 bash，先装再跑：
#   apk add bash && bash <(curl -fsSL .../install.sh)

set -euo pipefail

# 记下用户是否显式给了 WEB_PORT：重装时只有显式指定才覆盖已保存的端口
WEB_PORT_EXPLICIT="${WEB_PORT:+1}"
WEB_PORT="${WEB_PORT:-8899}"
WORK_DIR="${WORK_DIR:-/var/lib/fanout}"
BIN=/usr/local/bin/fanout-rust

if [[ $EUID -ne 0 ]]; then
  echo "需要 root 权限（要创建 netns 和改 iptables）" >&2
  exit 1
fi

# ── init 系统抽象：systemd 与 OpenRC 两套 ────────────────
INIT_SYS=""
if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
  INIT_SYS=systemd
elif command -v rc-service >/dev/null 2>&1; then
  INIT_SYS=openrc
else
  echo "不认识的 init 系统（需要 systemd 或 OpenRC）" >&2
  exit 1
fi

# seed_settings 把端口落进 settings.json —— 程序、f 菜单、Web 界面都以它为准。
#
# 重装时不覆盖用户已经改过的端口：除非这次显式指定了 WEB_PORT，
# 否则沿用原值，免得重装一次把人家改好的端口打回默认。
seed_settings() {
  local f="${WORK_DIR}/settings.json"
  if [[ -f "$f" ]] && [[ -z "${WEB_PORT_EXPLICIT:-}" ]]; then
    local cur
    cur=$(sed -n 's/.*"port"[[:space:]]*:[[:space:]]*\([0-9]*\).*/\1/p' "$f" | head -1)
    [[ -n $cur ]] && { WEB_PORT="$cur"; return; }
  fi
  printf '{\n  "port": %s,\n  "listen_addr": ""\n}\n' "$WEB_PORT" > "$f"
  chmod 600 "$f"
}

svc_install() {
  if [[ "$INIT_SYS" == systemd ]]; then
    # 端口不写进服务文件：它由 ${WORK_DIR}/settings.json 决定（见 seed_settings），
    # 两处都写会互相拽回旧值——界面改完重启失效，或 f 改完被配置覆盖。
    # 老版本模板里可能还带 -web，一并去掉。
    sed "s#-web [0-9]* ##; s#-dir /var/lib/fanout#-dir ${WORK_DIR}#" fanout-rust.service \
      > /etc/systemd/system/fanout-rust.service
    systemctl daemon-reload
  else
    # OpenRC 没有 systemd 那套单元文件，直接写 init script。
    # supervise-daemon 负责守护与重启，等价于 Restart=on-failure。
    cat > /etc/init.d/fanout-rust <<INITEOF
#!/sbin/openrc-run
name="fanout-rust"
description="fanout-rust - VPN Gate 出口扇出网关"
command="${BIN}"
command_args="-dir ${WORK_DIR}"
command_background=true
pidfile="/run/fanout-rust.pid"
output_log="/var/log/fanout-rust.log"
error_log="/var/log/fanout-rust.log"
respawn_delay=5
respawn_max=0
supervisor=supervise-daemon
start_pre() { ulimit -n 65536 2>/dev/null || true; }
depend() { need net; after firewall; }
INITEOF
    chmod +x /etc/init.d/fanout-rust
  fi
}

svc_enable_start() {
  if [[ "$INIT_SYS" == systemd ]]; then
    # enable --now 对「已经 active」的单元是空操作。重装/升级时服务通常正在跑，
    # 于是新二进制躺在磁盘上、老进程还在服务老界面，看着就像装错了版本。
    # 这里显式 restart，让磁盘上的那份真正接管。
    systemctl enable fanout-rust >/dev/null 2>&1 || true
    systemctl restart fanout-rust
  else
    rc-update add fanout-rust default >/dev/null 2>&1 || true
    rc-service fanout-rust restart
  fi
}

svc_is_active() {
  if [[ "$INIT_SYS" == systemd ]]; then
    systemctl is-active --quiet fanout-rust
  else
    rc-service fanout-rust status >/dev/null 2>&1
  fi
}

svc_logs_hint() {
  [[ "$INIT_SYS" == systemd ]] && echo "journalctl -u fanout-rust -n 30" || echo "cat /var/log/fanout-rust.log"
}

echo "[1/6] 检查依赖"

# 同一个命令在各发行版里的包名并不一致，按包管理器分别给出。
pkg_for() {
  local cmd="$1" mgr="$2"
  case "$cmd" in
    openvpn)  echo openvpn ;;
    curl)     echo curl ;;
    openssl)  echo openssl ;;
    tar)      echo tar ;;
    ip)       case "$mgr" in apk) echo iproute2 ;; pacman) echo iproute2 ;; *) echo iproute ;; esac ;;
    iptables) echo iptables ;;
    unzip)    echo unzip ;;
  esac
}

detect_mgr() {
  for m in apt-get dnf yum pacman apk zypper; do
    command -v "$m" >/dev/null && { echo "$m"; return; }
  done
  echo ""
}

install_pkgs() {
  local mgr="$1"; shift
  case "$mgr" in
    apt-get)
      apt-get update -qq
      DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@"
      ;;
    dnf)    dnf install -y -q "$@" ;;
    yum)    yum install -y -q "$@" ;;
    pacman) pacman -Sy --noconfirm --needed "$@" ;;
    apk)    apk add --no-cache "$@" ;;
    zypper) zypper --non-interactive install -y "$@" ;;
  esac
}

MGR=$(detect_mgr)
# Debian/Ubuntu 的 iproute2 与 RHEL 系的 iproute 是同一个东西，名字不同
[[ "$MGR" == "apt-get" ]] && iproute_pkg=iproute2 || iproute_pkg=iproute

need_cmd=()
for c in openvpn curl openssl tar iptables; do
  command -v "$c" >/dev/null || need_cmd+=("$c")
done
command -v ip >/dev/null || need_cmd+=(ip)

if [[ ${#need_cmd[@]} -gt 0 ]]; then
  echo "      缺少: ${need_cmd[*]}"
  if [[ -z "$MGR" ]]; then
    echo "      不认识的包管理器，请手动安装后重试" >&2
    exit 1
  fi
  pkgs=()
  for c in "${need_cmd[@]}"; do
    if [[ "$c" == "ip" ]]; then pkgs+=("$iproute_pkg"); else pkgs+=("$(pkg_for "$c" "$MGR")"); fi
  done
  echo "      安装: ${pkgs[*]}"
  install_pkgs "$MGR" "${pkgs[@]}" || {
    echo "      自动安装失败，请手动安装: ${pkgs[*]}" >&2
    exit 1
  }
fi

# wireguard-tools 是可选依赖：只有把出口总览页的「WARP 中转」拨开才用得上
# （判据就是有没有 wg 这条命令，见 warpProbeDeps）。装不上不该让整次安装失败，
# 但现在也不用它兜底了——拨开关时 fanout-rust 自己会用包管理器补装（见 warpEnsureTools），
# 这里顺手装上只是让人少等那几十秒。
if ! command -v wg >/dev/null; then
  if [[ -n "$MGR" ]]; then
    echo "      WARP 中转要用 wireguard-tools，顺手装上（不开中转可以不管它）"
    install_pkgs "$MGR" wireguard-tools \
      || echo "      wireguard-tools 没装上：拨开中转开关时程序会自己再试一次，其它功能不受影响"
  else
    echo "      没有 wg：拨开 WARP 中转开关时程序会试着装；这台机器认不出包管理器，"
    echo "      自动装大概率也会失败，届时请手动安装 wireguard-tools"
  fi
fi

echo "[2/6] 获取程序"
# SELF_REPO 是本仓库自己的身份，REPO 决定「去哪拿预编译包」和「以后从哪自更新」。
# 认不出来源时必须停手，绝不能退回上游：上游二进制没有这里的界面重写和连接层加固，
# 静默装上就等于把原版部署上去，而且界面长得像、版本号也像，装完根本发现不了。
SELF_REPO="MIGAO22/fanout-rust"
REPO_EXPLICIT="${REPO:+1}"
if [[ -z "${REPO:-}" ]]; then
  origin_url=$(git remote get-url origin 2>/dev/null || true)
  REPO=$(printf '%s' "$origin_url" | sed -E 's#.*github\.com[:/]##; s#\.git$##')
fi
if [[ -z "$REPO" ]]; then
  echo "      认不出该从哪个仓库装：不在 git clone 里，也没有 REPO=" >&2
  echo "      装本仓库请显式指定：REPO=${SELF_REPO} bash install.sh" >&2
  exit 1
fi
if [[ "$REPO" != "$SELF_REPO" && -z "$REPO_EXPLICIT" ]]; then
  echo "      推断出的来源是 ${REPO}，与本仓库 ${SELF_REPO} 不一致，已停手。" >&2
  echo "      真要装 ${REPO} 的版本，请显式加 REPO=${REPO}" >&2
  echo "      （那个版本没有本仓库的界面重写与连接层加固）" >&2
  exit 1
fi
echo "      来源仓库：${REPO}"
ARCH=$(uname -m)
case "$ARCH" in
  x86_64)  GOARCH=amd64 ;;
  aarch64|arm64) GOARCH=arm64 ;;
  *) echo "      不支持的架构: $ARCH" >&2; exit 1 ;;
esac

echo "      下载预编译版本 (${GOARCH})"
TMP=$(mktemp -d)
URL="https://github.com/${REPO}/releases/latest/download/fanout-rust-linux-${GOARCH}.tar.gz"
if ! curl -fsSL "$URL" -o "$TMP/f.tar.gz" \
   || ! curl -fsSL "https://github.com/${REPO}/releases/latest/download/checksums.txt" -o "$TMP/checksums.txt"; then
  echo "      下载失败: $URL" >&2
  echo "      该仓库没有 v* 的 Release 时这条地址就是 404；请先发布 Release 再重试" >&2
  exit 1
fi
if ! (cd "$TMP" && grep -F "fanout-rust-linux-${GOARCH}.tar.gz" checksums.txt | sha256sum -c -); then
  echo "      校验和失败，拒绝安装" >&2
  exit 1
fi
tar xzf "$TMP/f.tar.gz" -C "$TMP"
"$TMP/fanout-rust" -version >/dev/null
if [[ -f "$BIN" ]]; then
  cp -p "$BIN" "$BIN.prev"
fi
install -m 755 "$TMP/fanout-rust" "$BIN.new"
mv -f "$BIN.new" "$BIN"
if [[ ! -f fanout-rust.service ]]; then
  if [[ -f "$TMP/fanout-rust.service" ]]; then
    cp "$TMP/fanout-rust.service" .
  else
    curl -fsSL "https://raw.githubusercontent.com/${REPO}/main/fanout-rust.service" -o fanout-rust.service
  fi
fi
if [[ -f "$TMP/f.sh" ]]; then
  install -m 755 "$TMP/f.sh" /usr/local/bin/f
fi
rm -rf "$TMP"

# 装完直接验界面特征：rust-embed 有没有把新 index.html 打进去、拿到的包
# 是不是本仓库构建的，一眼就能定死，不用等部署完对着旧界面发懵。
# kpiRing 是重设计版独有的元素，改前端时别把它删了。
# 只在来源确实是本仓库时才断言——显式指定别的仓库时，人家界面长什么样我们说了不算。
if [[ "$REPO" == "$SELF_REPO" ]] && ! grep -aq -- 'kpiRing' "$BIN"; then
  echo "      装好的二进制里没有本仓库的界面特征，说明拿到的不是本仓库构建的版本。" >&2
  echo "      来源是 ${REPO}，请确认该仓库的 Release 确实由本仓库代码产出。" >&2
  exit 1
fi
echo "      已装：$("$BIN" -version 2>/dev/null || echo '版本未知')"

echo "[3/6] 准备 Xray"
# 没有现成面板接管时 fanout-rust 自己跑 Xray，需要一份二进制。
# 装到 WORK_DIR/bin 下而不是 /usr/local/bin，避免和机器上别人的 xray 抢版本。
mkdir -p "${WORK_DIR}/bin"
if command -v /usr/local/x-ui/x-ui >/dev/null 2>&1 || [[ -x /usr/bin/x-ui ]]; then
  echo "      检测到 3x-ui，入站交给面板管，跳过"
elif [[ -d /etc/xray-cf-lite && -f /usr/local/etc/xray/config.json ]]; then
  echo "      检测到 xray-cf-lite，入站交给它管，跳过"
elif [[ -x "${WORK_DIR}/bin/xray" ]]; then
  echo "      已有 $("${WORK_DIR}/bin/xray" version 2>/dev/null | head -1)"
else
  case "$GOARCH" in
    amd64) XRAY_ASSET=Xray-linux-64.zip ;;
    arm64) XRAY_ASSET=Xray-linux-arm64-v8a.zip ;;
  esac
  echo "      下载 Xray (${XRAY_ASSET})"
  XT=$(mktemp -d)
  XURL="https://github.com/XTLS/Xray-core/releases/latest/download/${XRAY_ASSET}"
  if curl -fsSL "$XURL" -o "$XT/x.zip"; then
    # 只为解一个 zip 装 unzip 有点重，busybox 环境常自带
    if command -v unzip >/dev/null; then
      unzip -qo "$XT/x.zip" -d "$XT"
    elif command -v busybox >/dev/null && busybox unzip -h >/dev/null 2>&1; then
      busybox unzip -qo "$XT/x.zip" -d "$XT"
    else
      [[ -n "$MGR" ]] && install_pkgs "$MGR" unzip >/dev/null 2>&1 || true
      command -v unzip >/dev/null && unzip -qo "$XT/x.zip" -d "$XT"
    fi
    if [[ -f "$XT/xray" ]]; then
      install -m 755 "$XT/xray" "${WORK_DIR}/bin/xray"
      echo "      $("${WORK_DIR}/bin/xray" version 2>/dev/null | head -1)"
    else
      echo "      解压失败，自建模式不可用（装了 3x-ui 则不受影响）" >&2
    fi
  else
    echo "      下载失败，自建模式不可用（装了 3x-ui 则不受影响）" >&2
  fi
  rm -rf "$XT"
fi

echo "[4/6] 放行转发"
sysctl -qw net.ipv4.ip_forward=1
grep -q '^net.ipv4.ip_forward=1' /etc/sysctl.conf 2>/dev/null \
  || echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
# FORWARD 链常有兜底 REJECT，fanout-rust 用的网段要插到最前面
if ! iptables -C FORWARD -s 10.99.0.0/16 -j ACCEPT 2>/dev/null; then
  iptables -I FORWARD 1 -s 10.99.0.0/16 -j ACCEPT
fi
if ! iptables -C FORWARD -d 10.99.0.0/16 -j ACCEPT 2>/dev/null; then
  iptables -I FORWARD 1 -d 10.99.0.0/16 -j ACCEPT
fi
command -v netfilter-persistent >/dev/null && netfilter-persistent save >/dev/null 2>&1 || true

echo "[5/6] 安装服务"
# 管理菜单
if [[ -f f.sh ]]; then
  install -m 755 f.sh /usr/local/bin/f
else
  if ! curl -fsSL "https://raw.githubusercontent.com/${REPO}/main/f.sh" -o /usr/local/bin/f; then
    echo "      管理菜单下载失败: https://raw.githubusercontent.com/${REPO}/main/f.sh" >&2
    exit 1
  fi
  chmod 755 /usr/local/bin/f
fi
mkdir -p "$WORK_DIR"
chmod 700 "$WORK_DIR"
seed_settings
svc_install
svc_enable_start

echo "[6/6] 就绪"
sleep 3
svc_is_active && echo "      服务运行中（${INIT_SYS}）" || {
  echo "      服务启动失败，看 $(svc_logs_hint)" >&2
  exit 1
}

# 口令与访问路径由 fanout-rust 首次启动时生成，等它写出来
for _ in $(seq 1 10); do
  [[ -s "${WORK_DIR}/password" && -s "${WORK_DIR}/basepath" ]] && break
  sleep 1
done

IP=$(curl -s --max-time 8 http://api.ipify.org || echo "<本机IP>")
BP=$(cat "${WORK_DIR}/basepath" 2>/dev/null || true)
# 以配置里的实际端口为准报地址，别让提示和真实监听对不上
ACTUAL_PORT=$(sed -n 's/.*"port"[[:space:]]*:[[:space:]]*\([0-9]*\).*/\1/p' \
  "${WORK_DIR}/settings.json" 2>/dev/null | head -1)
[[ -n $ACTUAL_PORT ]] && WEB_PORT="$ACTUAL_PORT"
echo
echo "  管理界面  http://${IP}:${WEB_PORT}/${BP}/"
echo "  访问口令  $(cat "${WORK_DIR}/password" 2>/dev/null || echo "见 ${WORK_DIR}/password")"
echo
echo "  路径和口令都是随机生成的，也可以随时查看："
echo "    cat ${WORK_DIR}/basepath"
echo "    cat ${WORK_DIR}/password"
echo
echo "  输入 f 打开管理菜单"
echo
echo "  ────────────────────────────────"
echo "  项目/更新来源  https://github.com/MIGAO22/fanout-rust"
echo
