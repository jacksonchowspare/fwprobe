#!/usr/bin/env bash
# ============================================================================
#  iProbe agent 安装脚本
#
#    curl -fsSL https://status.example.com/install-agent.sh | sudo bash -s -- \
#         --token <节点token> [--server https://status.example.com] [--as-user fwprobe]
#
#  参数：
#    --token T      节点令牌（首次安装必填；已装过的机器留空会自动沿用本机 token）
#    --server URL   中心地址（默认由中心下发时自动填好）
#    --interval N   上报间隔秒，默认 30（最小 10）
#    --name N       节点备注名（仅本地记录，中心以别名为准）
#    --as-user [U]  低权限模式：用专用系统用户跑（默认 fwprobe），只保留 CAP_NET_RAW 给 ICMP；
#                   不给这个参数就是 root 模式（老行为）
#    --uninstall    卸载 agent（停服务、删文件；低权限模式记得带上 --as-user）
# 说明：
#    * agent 只往外上报，不监听任何端口，不需要放行入站
#    * 安装后立即上报一次，可直接在中心看到该节点
#    * 低权限模式下自升级/自卸载靠 /etc/sudoers.d/fwprobe-agent 里两条精确授权
# ============================================================================
set -Eeuo pipefail

AGENT_DIR="/usr/local/lib/fwprobe-agent"
AGENT_ETC="/etc/fwprobe-agent"
AGENT_STATE="/var/lib/fwprobe-agent"
UNIT="/etc/systemd/system/fwprobe-agent.service"
SUDOERS="/etc/sudoers.d/fwprobe-agent"
HELPER="/usr/local/sbin/fwprobe-agent-uninstall.sh"
SERVICE="fwprobe-agent"

SERVER=""
TOKEN=""
TOKEN_ARG=""
INTERVAL="30"
NAME=""
AGENT_USER="root"
DO_UNINSTALL=0

while [ $# -gt 0 ]; do
  case "$1" in
    --token)     TOKEN="${2:-}"; TOKEN_ARG="$TOKEN"; shift ;;
    --server)    SERVER="${2:-}"; shift ;;
    --interval)  INTERVAL="${2:-30}"; shift ;;
    --name)      NAME="${2:-}"; shift ;;
    --as-user)   AGENT_USER="${2:-fwprobe}"; shift ;;
    --as-user=*) AGENT_USER="${1#*=}" ;;
    --uninstall) DO_UNINSTALL=1 ;;
    -h|--help)   sed -n '2,25p' "$0"; exit 0 ;;
    *) echo "未知参数: $1" >&2; exit 2 ;;
  esac
  shift
done

USER_MODE=0
if [ "$AGENT_USER" != "root" ]; then USER_MODE=1; fi

say()  { printf '%s\n' "$*"; }
step() { printf '\n\033[1;36m── %s\033[0m\n' "$*"; }
ok()   { printf '   \033[32m✓\033[0m %s\n' "$*"; }
warn() { printf '   \033[33m!\033[0m %s\n' "$*"; }
die()  { printf '\033[31m✗ %s\033[0m\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "请用 root 运行：curl -fsSL <中心>/install-agent.sh | sudo bash -s -- --token <节点token>"
if [ "$USER_MODE" = 1 ]; then
  [[ "$AGENT_USER" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || die "用户名不合法：$AGENT_USER"
fi

if [ "$DO_UNINSTALL" = 1 ]; then
  step "卸载 iProbe agent"
  systemctl disable --now "$SERVICE" 2>/dev/null || true
  rm -f "$UNIT" "$SUDOERS" "$HELPER"
  systemctl daemon-reload 2>/dev/null || true
  rm -rf "$AGENT_DIR" "$AGENT_ETC" "$AGENT_STATE"
  if [ "$USER_MODE" = 1 ] && id "$AGENT_USER" >/dev/null 2>&1; then
    if userdel "$AGENT_USER" 2>/dev/null; then ok "已删除系统用户 $AGENT_USER"
    else warn "用户 $AGENT_USER 没删掉（可能还有进程在用）"; fi
  fi
  ok "已卸载（中心侧节点记录还在，可在后台删除）"
  exit 0
fi

# 已装过的机器：不给 --token 就沿用本机配置（换运行身份时不用重新生成 token）
if [ -z "$TOKEN" ] && [ -f "$AGENT_ETC/config.json" ]; then
  _cfg="$(python3 - "$AGENT_ETC/config.json" <<'PY' 2>/dev/null || true
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
print((d.get("token") or "") + "\t" + (d.get("server") or ""))
PY
)"
  if [ -n "$_cfg" ]; then
    TOKEN="${_cfg%%$'\t'*}"
    if [ -z "$SERVER" ]; then SERVER="${_cfg#*$'\t'}"; fi
    if [ -n "$TOKEN" ]; then ok "沿用本机已有 token（不用重新生成），配置里的三网目标也会保留"; fi
  fi
fi

[ -n "$TOKEN" ] || die "缺少 --token（在中心后台「添加节点」处生成；已装过的机器会自动沿用本机 token）"
if ! [[ "$INTERVAL" =~ ^[0-9]+$ ]] || [ "$INTERVAL" -lt 10 ]; then
  die "--interval 必须是 ≥10 的整数"
fi

step "1. 环境检查"
command -v curl >/dev/null 2>&1 || die "缺少 curl（apt-get install -y curl）"
command -v python3 >/dev/null 2>&1 || die "缺少 python3"
say "   python3 : $(python3 -V 2>&1)"
say "   系统    : $(. /etc/os-release 2>/dev/null && echo "${PRETTY_NAME:-unknown}" || echo unknown)"
[ -n "$SERVER" ] || die "缺少 --server（中心地址，例如 https://status.example.com）"
SERVER="${SERVER%/}"
case "$SERVER" in
  http://*|https://*) ;;
  *) die "--server 需要以 http:// 或 https:// 开头" ;;
esac

step "2. 下载 agent"
mkdir -p "$AGENT_DIR" "$AGENT_ETC" "$AGENT_STATE/spool"
tmp="$(mktemp)"
if curl -fsSL --connect-timeout 10 --max-time 60 -o "$tmp" "$SERVER/agent.py"; then
  install -m 755 "$tmp" "$AGENT_DIR/agent.py"
  ok "已下载（$("$AGENT_DIR/agent.py" --help >/dev/null 2>&1 && echo ok || echo 已保存)）"
else
  rm -f "$tmp"
  die "下载失败：$SERVER/agent.py —— 检查中心地址是否可达"
fi
rm -f "$tmp"

step "3. 运行用户"
if [ "$USER_MODE" = 1 ]; then
  if id "$AGENT_USER" >/dev/null 2>&1; then
    ok "系统用户 $AGENT_USER 已存在，直接复用"
  else
    useradd --system --no-create-home --shell /usr/sbin/nologin "$AGENT_USER"
    ok "已创建系统用户 $AGENT_USER（不能登录、没有家目录）"
  fi
  chown -R "$AGENT_USER:$AGENT_USER" "$AGENT_DIR" "$AGENT_ETC" "$AGENT_STATE"
  ok "agent 目录归属已交给 $AGENT_USER（自升级要能写自己）"
else
  ok "root 模式：服务以 root 运行（ICMP / 自升级 / 自卸载都直接可用）"
fi

step "4. 写入配置"
if [ -n "$TOKEN_ARG" ]; then
python3 - "$AGENT_ETC/config.json" "$SERVER" "$TOKEN" "$INTERVAL" "$NAME" <<'PY'
import json, sys
path, server, token, interval, name = sys.argv[1:6]
cfg = {
    "server": server.rstrip("/"),
    "token": token,
    "interval": int(interval),
    "check_interval": max(60, int(interval) * 2),
    "disk_mount": "/",
    "name": name,
    "targets": [
        {"name": "上海电信", "proto": "tcp", "host": "sh-ct-v4.ip.zstaticcdn.com", "port": 80, "family": "auto", "enabled": True},
        {"name": "上海联通", "proto": "tcp", "host": "sh-cu-v4.ip.zstaticcdn.com", "port": 80, "family": "auto", "enabled": True},
        {"name": "上海移动", "proto": "tcp", "host": "sh-cm-v4.ip.zstaticcdn.com", "port": 80, "family": "auto", "enabled": True},
        {"name": "上海电信v6", "proto": "tcp", "host": "sh-ct-v6.ip.zstaticcdn.com", "port": 80, "family": "6", "enabled": False},
        {"name": "上海联通v6", "proto": "tcp", "host": "sh-cu-v6.ip.zstaticcdn.com", "port": 80, "family": "6", "enabled": False},
        {"name": "上海移动v6", "proto": "tcp", "host": "sh-cm-v6.ip.zstaticcdn.com", "port": 80, "family": "6", "enabled": False},
    ],
}
with open(path, "w", encoding="utf-8") as fh:
    json.dump(cfg, fh, ensure_ascii=False, indent=2)
PY
  ok "配置写入 $AGENT_ETC/config.json"
else
  ok "沿用已有配置（token 与三网目标保持不变）"
fi
chmod 600 "$AGENT_ETC/config.json"      # 里面有 token
if [ "$USER_MODE" = 1 ]; then chown "$AGENT_USER:$AGENT_USER" "$AGENT_ETC/config.json"; fi
ok "配置权限 600"

step "5. 注册 systemd 服务"
if [ "$USER_MODE" = 1 ]; then
  # 先写 sudoers 并实测（Ubuntu 25.10+ 默认换成 sudo-rs，visudo 有的版本不认 -c -f，
  # 所以校验失败要分辨"语法错"和"这版 visudo 不支持该参数"，不能一刀切退出）
  cat > "$SUDOERS" <<EOF
# iProbe agent 低权限模式：仅放行这两条，别往里加别的
$AGENT_USER ALL=(root) NOPASSWD: /bin/systemctl restart $SERVICE
$AGENT_USER ALL=(root) NOPASSWD: $HELPER
EOF
  chmod 440 "$SUDOERS"
  chown root:root "$SUDOERS"
  if command -v visudo >/dev/null 2>&1; then
    if out="$(visudo -cf "$SUDOERS" 2>&1)"; then
      ok "sudoers 语法校验通过"
    elif printf '%s' "$out" | grep -qiE 'usage|unexpected|unknown option|invalid option|not supported|extra operand'; then
      warn "这版 visudo 不支持 -c -f（多半是 sudo-rs），跳过语法校验，直接用 sudo -l 实测"
    else
      warn "visudo 报错：$(printf '%s' "$out" | head -2 | tr '\n' ' ')"
    fi
  fi
  # 真正的验收：先问"能不能执行这条"；有的 sudo-rs 不让 -l 带命令参数，就直接试跑一次
  SUDO_OK=0
  if sudo -u "$AGENT_USER" sudo -n -l /bin/systemctl restart "$SERVICE" >/dev/null 2>&1; then
    SUDO_OK=1
  elif sudo -u "$AGENT_USER" sudo -n /bin/systemctl restart "$SERVICE" >/dev/null 2>&1; then
    SUDO_OK=1
  fi
  if [ "$SUDO_OK" = 1 ]; then
    ok "已确认 $AGENT_USER 可以用 sudo 重启服务（自升级不会卡住）"
  else
    warn "$AGENT_USER 的 sudo 授权没生效 → 本次按 root 模式安装（不影响上报，只是没降权）"
    warn "排查：sudo --version | head -1；cat $SUDOERS"
    rm -f "$SUDOERS"
    USER_MODE=0
  fi
fi

if [ "$USER_MODE" = 1 ]; then
  cat > "$HELPER" <<EOF
#!/bin/sh
# iProbe agent 自卸载（agent 通过 sudo 调用）：root 持有，agent 用户不可改
systemctl stop $SERVICE 2>/dev/null || true
systemctl disable $SERVICE 2>/dev/null || true
rm -f /etc/systemd/system/$SERVICE.service
systemctl daemon-reload 2>/dev/null || true
rm -rf $AGENT_DIR $AGENT_ETC $AGENT_STATE
rm -f $SUDOERS
userdel $AGENT_USER 2>/dev/null || true
EOF
  chmod 755 "$HELPER"
  chown root:root "$HELPER"
  ok "已装自卸载脚本（$HELPER，root 持有）"
  cat > "$UNIT" <<EOF
[Unit]
Description=iProbe agent (VPS probe collector)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 $AGENT_DIR/agent.py
Restart=always
RestartSec=10
Nice=10
# 低权限模式：专用用户 + 只保留 CAP_NET_RAW（ICMP 探测用），其余能力全部丢弃
User=$AGENT_USER
Group=$AGENT_USER
AmbientCapabilities=CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_RAW
# 系统目录保持只读，只放开 agent 自己的三个目录（自升级要能写自己）
ProtectSystem=full
ReadWritePaths=$AGENT_DIR $AGENT_ETC $AGENT_STATE
ProtectHome=read-only
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
EOF
else
  rm -f "$SUDOERS" "$HELPER" 2>/dev/null || true
  cat > "$UNIT" <<EOF
[Unit]
Description=iProbe agent (VPS probe collector)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 $AGENT_DIR/agent.py
Restart=always
RestartSec=10
Nice=10
# 采集只读 /proc 与本地网络，不需要额外权限；ICMP 目标需要 root 或 CAP_NET_RAW
User=root

[Install]
WantedBy=multi-user.target
EOF
fi
systemctl daemon-reload
# ⚠ enable --now 对已在运行的服务是空操作：重装/换 token 后进程仍拿旧配置（实测 403 一直刷）
#   所以先 enable，再无条件 restart，保证新配置/新 agent.py 真正生效
systemctl enable "$SERVICE" >/dev/null 2>&1 || true
systemctl restart "$SERVICE" >/dev/null 2>&1 || true

step "6. 首次上报自检"
sleep 3
if systemctl is-active --quiet "$SERVICE"; then
  ok "服务运行中（$SERVICE）"
  PID="$(systemctl show -p MainPID --value "$SERVICE" 2>/dev/null || echo 0)"
  RUNUSER="$(ps -o user= -p "${PID:-0}" 2>/dev/null | tr -d ' ' || true)"
  if [ -n "${RUNUSER:-}" ]; then
    if [ "$USER_MODE" = 1 ] && [ "$RUNUSER" = "$AGENT_USER" ]; then
      ok "实际运行身份：$RUNUSER（低权限已生效）"
    elif [ "$USER_MODE" = 1 ]; then
      warn "实际运行身份是 $RUNUSER，不是 $AGENT_USER —— 看 sudo journalctl -u $SERVICE -n 30"
    else
      ok "实际运行身份：$RUNUSER"
    fi
  fi
else
  warn "服务没起来，看日志：journalctl -u $SERVICE -n 30 --no-pager"
fi
if [ "$USER_MODE" = 1 ]; then
  if out="$(sudo -u "$AGENT_USER" -H python3 "$AGENT_DIR/agent.py" --once 2>&1)"; then
    ok "首次上报成功（以 $AGENT_USER 身份）：$out"
  else
    warn "首次上报失败：$out"
    warn "如果是 401/403，请确认 token 与中心上该节点的 token 一致"
  fi
else
  if out="$(python3 "$AGENT_DIR/agent.py" --once 2>&1)"; then
    ok "首次上报成功：$out"
  else
    warn "首次上报失败：$out"
    warn "如果是 401/403，请确认 token 与中心上该节点的 token 一致"
  fi
fi

say ""
say "------------------------------------------------------------------"
say "  探针 agent 安装完成"
say "  中心地址 : $SERVER"
if [ "$USER_MODE" = 1 ]; then
  say "  运行用户 : $AGENT_USER（低权限：仅 CAP_NET_RAW，可做 ICMP）"
else
  say "  运行用户 : root（root 模式）"
fi
say "  采集间隔 : ${INTERVAL}s（探测 60s 一轮）"
say "  查看状态 : systemctl status $SERVICE"
say "  看日志   : journalctl -u $SERVICE -f"
if [ "$USER_MODE" = 1 ]; then
  say "  卸载     : curl -fsSL $SERVER/install-agent.sh | sudo bash -s -- --uninstall --as-user $AGENT_USER"
else
  say "  卸载     : curl -fsSL $SERVER/install-agent.sh | sudo bash -s -- --uninstall"
fi
say "------------------------------------------------------------------"
