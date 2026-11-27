#!/usr/bin/env bash
# fanout-rust 管理菜单
set -uo pipefail

WORK_DIR=/var/lib/fanout
SERVICE=fanout-rust
BIN=/usr/local/bin/fanout-rust
# 本仓库构建的更新来源。绝不能默认指向上游：菜单里一次「更新」就会把
# 界面重写和连接层加固整个覆盖回原版。要换源请显式带 REPO=owner/repo。
REPO="${REPO:-MIGAO22/fanout-rust}"

G='\033[0;32m'; R='\033[0;31m'; Y='\033[0;33m'; B='\033[0;36m'; D='\033[2m'; N='\033[0m'

need_root() {
  [[ $EUID -eq 0 ]] || { echo -e "${R}需要 root${N}"; exit 1; }
}

# ── init 系统抽象：systemd 与 OpenRC ────────────────────
if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
  INIT_SYS=systemd
  UNIT=/etc/systemd/system/${SERVICE}.service
else
  INIT_SYS=openrc
  UNIT=/etc/init.d/${SERVICE}
fi

svc_start()   { [[ $INIT_SYS == systemd ]] && systemctl start "$SERVICE"   || rc-service "$SERVICE" start; }
svc_stop()    { [[ $INIT_SYS == systemd ]] && systemctl stop "$SERVICE"    || rc-service "$SERVICE" stop; }
svc_restart() { [[ $INIT_SYS == systemd ]] && systemctl restart "$SERVICE" || rc-service "$SERVICE" restart; }
svc_reload()  { [[ $INIT_SYS == systemd ]] && systemctl daemon-reload || true; }
svc_enable()  { [[ $INIT_SYS == systemd ]] && systemctl enable "$SERVICE" >/dev/null 2>&1 || rc-update add "$SERVICE" default >/dev/null 2>&1; }
svc_disable() { [[ $INIT_SYS == systemd ]] && systemctl disable "$SERVICE" >/dev/null 2>&1 || rc-update del "$SERVICE" default >/dev/null 2>&1; }

svc_is_enabled() {
  if [[ $INIT_SYS == systemd ]]; then
    systemctl is-enabled --quiet "$SERVICE"
  else
    rc-update show default 2>/dev/null | grep -q "^ *${SERVICE} "
  fi
}

svc_enabled_text() {
  svc_is_enabled && echo enabled || echo disabled
}

svc_status_page() {
  if [[ $INIT_SYS == systemd ]]; then
    systemctl status "$SERVICE" --no-pager
  else
    rc-service "$SERVICE" status
  fi
}

svc_logs() {
  if [[ $INIT_SYS == systemd ]]; then
    journalctl -u "$SERVICE" -n "${1:-50}" --no-pager
  else
    tail -n "${1:-50}" /var/log/${SERVICE}.log 2>/dev/null || echo "  暂无日志"
  fi
}

svc_logs_follow() {
  if [[ $INIT_SYS == systemd ]]; then
    journalctl -u "$SERVICE" -f
  else
    tail -f /var/log/${SERVICE}.log
  fi
}

svc_state() {
  if [[ $INIT_SYS == systemd ]]; then
    systemctl is-active --quiet "$SERVICE" && echo running || echo stopped
  else
    rc-service "$SERVICE" status >/dev/null 2>&1 && echo running || echo stopped
  fi
}

# 端口以 settings.json 为准。老版本把 -web 写死在服务文件里，
# 两处各改各的会互相拽回旧值，所以这里只认工作目录下的配置。
web_port() {
  local p
  p=$(sed -n 's/.*"port"[[:space:]]*:[[:space:]]*\([0-9]*\).*/\1/p' \
        "$WORK_DIR/settings.json" 2>/dev/null | head -1)
  [[ -n $p ]] && { echo "$p"; return; }
  # 兼容老安装：settings.json 还没生成时退回读服务文件
  grep -oE '\-web [0-9]+' "$UNIT" 2>/dev/null \
    | grep -oE '[0-9]+' | head -1 || echo 8899
}

public_ip() {
  local ip
  ip=$(ip -4 -o route get 1.1.1.1 2>/dev/null \
    | sed -n 's/.*src \([0-9.][0-9.]*\).*/\1/p' | head -1)
  if [[ -n $ip ]]; then
    echo "$ip"
    return
  fi
  ip=$(curl -s --connect-timeout 1 --max-time 2 http://api.ipify.org 2>/dev/null || true)
  echo "${ip:-<本机IP>}"
}

web_ready() {
  local port=$1 bp=$2 password=${3:-} base code
  bp=${bp#/}; bp=${bp%/}
  base="http://127.0.0.1:${port}"
  [[ -n $bp ]] && base+="/${bp}"
  for _ in $(seq 1 30); do
    if [[ -n $password ]]; then
      code=$(curl -sS -o /dev/null -w '%{http_code}' \
        --connect-timeout 1 --max-time 2 \
        --data-urlencode "password=$password" "$base/login" 2>/dev/null || true)
    else
      code=$(curl -sS -o /dev/null -w '%{http_code}' \
        --connect-timeout 1 --max-time 2 "$base/login" 2>/dev/null || true)
    fi
    [[ $code == 200 ]] && return 0
    sleep 1
  done
  return 1
}

pause() {
  echo
  read -rp "回车返回菜单..." _
}

show_info() {
  local state port bp pw ip
  state=$(svc_state); port=$(web_port)
  bp=$(cat "$WORK_DIR/basepath" 2>/dev/null || echo "-")
  pw=$(cat "$WORK_DIR/password" 2>/dev/null || echo "-")
  ip=$(public_ip)

  echo
  if [[ $state == running ]]; then
    echo -e "  状态      ${G}运行中${N}"
  else
    echo -e "  状态      ${R}已停止${N}"
  fi
  echo -e "  版本      $("$BIN" -version 2>/dev/null || echo '-')"
  echo -e "  开机自启  $(svc_enabled_text)"
  echo
  echo -e "  ${B}管理地址  http://${ip}:${port}/${bp}/${N}"
  echo -e "  ${B}访问口令  ${pw}${N}"
  echo

  local n
  n=$(ls -d /var/run/netns/fo* 2>/dev/null | wc -l | tr -d ' ')
  echo -e "  ${D}运行中的隧道: ${n}${N}"
}

list_tunnels() {
  local port bp pw ck
  port=$(web_port)
  bp=$(cat "$WORK_DIR/basepath" 2>/dev/null)
  pw=$(cat "$WORK_DIR/password" 2>/dev/null)
  ck=$(mktemp)

  curl -s --max-time 10 -c "$ck" -X POST --data-urlencode "password=${pw}" \
    "http://127.0.0.1:${port}/${bp}/login" -o /dev/null
  echo
  curl -s --max-time 10 -b "$ck" "http://127.0.0.1:${port}/${bp}/api/tunnels" \
    > "$ck.json" 2>/dev/null
  rm -f "$ck"

  # 用 awk 而不是 python3/jq：Alpine 最小安装两者都没有。
  # 一次扫描完成字段提取，避免每条隧道为每个字段再启动一个进程。
  if [[ ! -s "$ck.json" ]] || ! grep -q '"port"' "$ck.json" 2>/dev/null; then
    echo "  还没有隧道，去网页里添加"
  else
    printf "  %-10s%-11s%-18s%s\n" "端口" "状态" "出口 IP" "节点"
    awk '
      function value(pattern, line, text) {
        if (!match(line, pattern)) return "-"
        text = substr(line, RSTART, RLENGTH)
        sub(/^[^:]*:/, "", text)
        gsub(/^"|"$/, "", text)
        return text
      }
      BEGIN { RS = "\\{\"slot\""; OFS = "\t" }
      {
        port = value("\"port\":[0-9]+", $0)
        if (port == "-" || port == "") next
        status = value("\"status\":\"[^\"]*\"", $0)
        exit_ip = value("\"exit_ip\":\"[^\"]*\"", $0)
        hostname = value("\"hostname\":\"[^\"]*\"", $0)
        print port, status, exit_ip, hostname
      }
    ' "$ck.json" | while IFS=$'\t' read -r p st ip hn; do
      printf "  %-10s%-11s%-18s%s\n" "$p" "${st:--}" "${ip:--}" "${hn:--}"
    done
  fi
  rm -f "$ck.json"
}

change_port() {
  local cur new
  cur=$(web_port)
  echo
  read -rp "  新端口 (当前 ${cur}): " new
  [[ -z $new ]] && { echo "  未修改"; return; }
  if ! [[ $new =~ ^[0-9]+$ ]] || (( new < 1 || new > 65535 )); then
    echo -e "  ${R}端口不合法${N}"; return
  fi
  if ss -H -ltn "sport = :${new}" 2>/dev/null | grep -q .; then
    echo -e "  ${R}端口 ${new} 已被占用${N}"; return
  fi
  # 写 settings.json（权威来源），并把服务文件里可能残留的 -web 一并同步，
  # 免得老安装重启后又被写死的旧端口拽回去。
  if [[ -f "$WORK_DIR/settings.json" ]]; then
    sed -i "s/\"port\"[[:space:]]*:[[:space:]]*[0-9]*/\"port\": ${new}/" "$WORK_DIR/settings.json"
  else
    printf '{\n  "port": %s,\n  "listen_addr": ""\n}\n' "$new" > "$WORK_DIR/settings.json"
    chmod 600 "$WORK_DIR/settings.json"
  fi
  sed -i "s/-web ${cur}/-web ${new}/" "$UNIT" 2>/dev/null
  svc_reload
  svc_restart
  local bp
  bp=$(cat "$WORK_DIR/basepath" 2>/dev/null)
  echo "  等待 Web 服务就绪..."
  if web_ready "$new" "$bp"; then
    echo -e "  ${G}已改为 ${new}，Web 已就绪${N}"
  else
    echo -e "  ${R}配置已写入，但等待 Web 就绪超时${N}"
    svc_logs 20
  fi
}

reset_password() {
  local pw
  echo
  read -rp "  新口令 (留空则随机生成): " pw
  if [[ -z $pw ]]; then
    pw=$(head -c 9 /dev/urandom | od -An -tx1 | tr -d ' \n')
  fi
  umask 077
  echo "$pw" > "$WORK_DIR/password"
  svc_restart
  local port bp
  port=$(web_port)
  bp=$(cat "$WORK_DIR/basepath" 2>/dev/null)
  echo "  等待 Web 服务并验证新口令..."
  if web_ready "$port" "$bp" "$pw"; then
    echo -e "  ${G}新口令已生效: ${pw}${N}"
  else
    echo -e "  ${R}配置已写入，但新口令未通过登录验证${N}"
    svc_logs 20
  fi
}

reset_basepath() {
  local bp port
  echo
  read -rp "  新访问路径 (留空则随机生成): " bp
  if [[ -n $bp ]]; then
    bp=${bp#/}; bp=${bp%/}
    if ! [[ $bp =~ ^[A-Za-z0-9_-]*$ ]]; then
      echo -e "  ${R}访问路径只能用字母、数字、- 和 _${N}"; return
    fi
    umask 077
    echo "$bp" > "$WORK_DIR/basepath"
  else
    rm -f "$WORK_DIR/basepath"
  fi
  svc_restart
  if [[ -z $bp ]]; then
    for _ in $(seq 1 20); do
      [[ -s "$WORK_DIR/basepath" ]] && break
      sleep 1
    done
    bp=$(cat "$WORK_DIR/basepath" 2>/dev/null)
    if [[ -z $bp ]]; then
      echo -e "  ${R}服务没有生成新的访问路径${N}"
      svc_logs 20
      return
    fi
  fi
  port=$(web_port)
  echo "  等待 Web 服务就绪..."
  if web_ready "$port" "$bp"; then
    echo -e "  ${G}新路径已生效: /${bp}/${N}"
  else
    echo -e "  ${R}配置已写入，但等待 Web 就绪超时${N}"
    svc_logs 20
  fi
}

ipv6_state() {
  local a d
  a=$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null || echo 0)
  d=$(sysctl -n net.ipv6.conf.default.disable_ipv6 2>/dev/null || echo 0)
  [[ "$a" == 1 && "$d" == 1 ]] && echo disabled || echo enabled
}

toggle_ipv6() {
  local conf=/etc/sysctl.d/99-fanout-ipv6.conf
  echo
  if [[ $(ipv6_state) == disabled ]]; then
    read -rp "  当前已禁用 IPv6，要重新启用吗？[y/N]: " yes
    [[ ${yes,,} == y ]] || { echo "  已取消"; return; }
    rm -f "$conf"
    sysctl -qw net.ipv6.conf.all.disable_ipv6=0
    sysctl -qw net.ipv6.conf.default.disable_ipv6=0
    sysctl -qw net.ipv6.conf.lo.disable_ipv6=0
    echo -e "  ${G}已重新启用 IPv6${N}"
    return
  fi

  echo -e "  ${D}母机有全局 IPv6 时，没走隧道的流量可能从 IPv6 出去，暴露真实地址。${N}"
  read -rp "  确认禁用整机 IPv6？[y/N]: " yes
  [[ ${yes,,} == y ]] || { echo "  已取消"; return; }

  cat > "$conf" <<EOF
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF
  sysctl -qw net.ipv6.conf.all.disable_ipv6=1
  sysctl -qw net.ipv6.conf.default.disable_ipv6=1
  sysctl -qw net.ipv6.conf.lo.disable_ipv6=1
  svc_restart >/dev/null 2>&1
  echo -e "  ${G}已禁用 IPv6（重启后依然生效）${N}"
}

# 老版本把 -web 写死在服务文件里，和 settings.json 互相拽回旧值。
# 更新时把端口搬进配置再从服务文件里摘掉，之后只认一处。
migrate_port_to_settings() {
  local unit_port
  unit_port=$(grep -oE '\-web [0-9]+' "$UNIT" 2>/dev/null | grep -oE '[0-9]+' | head -1)
  [[ -z $unit_port ]] && return

  if [[ ! -f "$WORK_DIR/settings.json" ]]; then
    printf '{\n  "port": %s,\n  "listen_addr": ""\n}\n' "$unit_port" > "$WORK_DIR/settings.json"
    chmod 600 "$WORK_DIR/settings.json"
  fi
  sed -i "s/-web ${unit_port} //" "$UNIT"
  svc_reload
  echo "  已把端口 ${unit_port} 迁移到 settings.json"
}

do_update() {
  local arch goarch tmp port bp had_bin=0 had_unit=0
  arch=$(uname -m)
  case "$arch" in
    x86_64) goarch=amd64 ;;
    aarch64|arm64) goarch=arm64 ;;
    *) echo -e "  ${R}不支持的架构 ${arch}${N}"; return ;;
  esac

  echo -e "\n  当前 $("$BIN" -version 2>/dev/null || echo '-')  来源 ${REPO}"
  tmp=$(mktemp -d) || return
  echo "  正在下载最新版与校验和..."
  if ! curl -fsSL "https://github.com/${REPO}/releases/latest/download/checksums.txt" -o "$tmp/checksums.txt" \
     || ! curl -fsSL "https://github.com/${REPO}/releases/latest/download/fanout-rust-linux-${goarch}.tar.gz" -o "$tmp/f.tar.gz"; then
    echo -e "  ${R}下载失败${N}"; rm -rf "$tmp"; return
  fi
  if ! (cd "$tmp" && grep -F "fanout-rust-linux-${goarch}.tar.gz" checksums.txt | sha256sum -c -); then
    echo -e "  ${R}校验和失败，已放弃更新${N}"; rm -rf "$tmp"; return
  fi
  if ! tar xzf "$tmp/f.tar.gz" -C "$tmp" || ! "$tmp/fanout-rust" -version >/dev/null 2>&1; then
    echo -e "  ${R}新版解包或自检失败，已放弃更新${N}"; rm -rf "$tmp"; return
  fi

  if [[ -f "$BIN" ]]; then
    cp -p "$BIN" "$BIN.prev" || { echo -e "  ${R}备份旧版失败${N}"; rm -rf "$tmp"; return; }
    had_bin=1
  fi
  if [[ -f "$UNIT" ]]; then
    cp -p "$UNIT" "$tmp/unit.prev" || { echo -e "  ${R}备份服务文件失败${N}"; rm -rf "$tmp"; return; }
    had_unit=1
  fi

  svc_stop
  if ! install -m 755 "$tmp/fanout-rust" "$BIN.new.$$" || ! mv -f "$BIN.new.$$" "$BIN"; then
    echo -e "  ${R}替换二进制失败${N}"
    [[ $had_bin == 1 ]] && cp -p "$BIN.prev" "$BIN"
    rm -rf "$tmp"; svc_start; return
  fi
  if [[ $INIT_SYS == systemd && -f "$tmp/fanout-rust.service" ]]; then
    sed "s#-web [0-9]* ##; s#-dir /var/lib/fanout#-dir ${WORK_DIR}#" \
      "$tmp/fanout-rust.service" > "$UNIT.new.$$"
    mv -f "$UNIT.new.$$" "$UNIT"
    svc_reload
  fi
  migrate_port_to_settings
  svc_start
  port=$(web_port)
  bp=$(cat "$WORK_DIR/basepath" 2>/dev/null)
  echo "  等待 Web 服务就绪..."
  if ! web_ready "$port" "$bp"; then
    echo -e "  ${R}新版未就绪，正在回滚${N}"
    [[ $had_bin == 1 ]] && cp -p "$BIN.prev" "$BIN"
    if [[ $had_unit == 1 ]]; then
      cp -p "$tmp/unit.prev" "$UNIT"
      svc_reload
    fi
    svc_start
    rm -rf "$tmp"
    return
  fi

  if [[ ! -f "$tmp/f.sh" ]]; then
    curl -fsSL "https://raw.githubusercontent.com/${REPO}/main/f.sh" -o "$tmp/f.sh" || true
  fi
  if [[ -f "$tmp/f.sh" ]]; then
    install -m 755 "$tmp/f.sh" /usr/local/bin/f.new.$$ \
      && mv -f /usr/local/bin/f.new.$$ /usr/local/bin/f \
      && echo "  菜单脚本已同步，下次运行 f 生效"
  fi
  rm -rf "$tmp"
  echo -e "  ${G}已更新到 $("$BIN" -version 2>/dev/null)${N}"
}

do_uninstall() {
  local yes
  echo
  read -rp "  确认卸载？隧道和配置都会删除 [y/N]: " yes
  [[ ${yes,,} == y ]] || { echo "  已取消"; return; }

  svc_stop >/dev/null 2>&1
  svc_disable
  # 清掉残留的 netns 与 veth
  for ns in $(ip netns list 2>/dev/null | awk '{print $1}' | grep '^fo[0-9]'); do
    ip netns del "$ns" 2>/dev/null
  done
  for l in $(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | grep '^fov[0-9]'); do
    ip link del "$l" 2>/dev/null
  done
  rm -f "$UNIT" "$BIN" /usr/local/bin/f
  rm -rf "$WORK_DIR"
  svc_reload
  echo -e "  ${G}已卸载${N}"
  exit 0
}

menu() {
  while true; do
    clear
    echo -e "${B}  fanout-rust${N}  ${D}VPN Gate 出口扇出网关${N}"
    show_info
    echo -e "${D}  ─────────────────────────────${N}"
    echo "   1) 启动          2) 停止"
    echo "   3) 重启          4) 查看日志"
    echo
    echo "   5) 隧道列表      6) 连接信息"
    echo
    echo "   7) 改端口        8) 改口令"
    echo "   9) 改访问路径   10) 开机自启开关"
    echo
    echo "  11) 更新         12) 卸载"
    echo "   0) 退出"
    echo -e "${D}  ─────────────────────────────${N}"
    read -rp "  选择: " choice

    case "$choice" in
      1) svc_start   && echo -e "\n  ${G}已启动${N}"; pause ;;
      2) svc_stop    && echo -e "\n  ${Y}已停止${N}"; pause ;;
      3) svc_restart && echo -e "\n  ${G}已重启${N}"; pause ;;
      4) echo; svc_logs 40; pause ;;
      5) list_tunnels; pause ;;
      6) show_info; pause ;;
      7) change_port; pause ;;
      8) reset_password; pause ;;
      9) reset_basepath; pause ;;
      10)
        if svc_is_enabled; then
          svc_disable
          echo -e "\n  ${Y}已关闭开机自启${N}"
        else
          svc_enable
          echo -e "\n  ${G}已开启开机自启${N}"
        fi
        pause ;;
      11) do_update; pause ;;
      12) do_uninstall; pause ;;
      0) exit 0 ;;
      *) ;;
    esac
  done
}

need_root

# 带参数时当普通命令用，不进菜单
case "${1:-}" in
  start)    svc_start ;;
  stop)     svc_stop ;;
  restart)  svc_restart ;;
  status)   svc_status_page ;;
  log)      svc_logs_follow ;;
  info)     show_info ;;
  list)     list_tunnels ;;
  update)   do_update ;;
  uninstall) do_uninstall ;;
  "")       menu ;;
  *)
    echo "用法: f [start|stop|restart|status|log|info|list|update|uninstall]"
    echo "不带参数进入交互菜单"
    ;;
esac
