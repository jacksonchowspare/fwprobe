#!/usr/bin/env bash
# ============================================================================
#  fwprobe agent 安装脚本
#
#    curl -fsSL https://status.example.com/install-agent.sh | sudo bash -s -- \
#         --token <节点token> [--server https://status.example.com]
#
#  参数：
#    --token T      节点令牌（必填，在中心后台生成）
#    --server URL   中心地址（默认由中心下发时自动填好）
#    --interval N   上报间隔秒，默认 30（最小 10）
#    --name N       节点备注名（仅本地记录，中心以别名为准）
#    --uninstall    卸载 agent（停服务、删文件）
# 说明：
#    * agent 只往外上报，不监听任何端口，不需要放行入站
#    * 安装后立即上报一次，可直接在中心看到该节点
# ============================================================================
set -Eeuo pipefail

AGENT_DIR="/usr/local/lib/fwprobe-agent"
AGENT_ETC="/etc/fwprobe-agent"
AGENT_STATE="/var/lib/fwprobe-agent"
UNIT="/etc/systemd/system/fwprobe-agent.service"
SERVICE="fwprobe-agent"

SERVER=""
TOKEN=""
INTERVAL="30"
NAME=""
DO_UNINSTALL=0

while [ $# -gt 0 ]; do
  case "$1" in
    --token)     TOKEN="${2:-}"; shift ;;
    --server)    SERVER="${2:-}"; shift ;;
    --interval)  INTERVAL="${2:-30}"; shift ;;
    --name)      NAME="${2:-}"; shift ;;
    --uninstall) DO_UNINSTALL=1 ;;
    -h|--help)   sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "未知参数: $1" >&2; exit 2 ;;
  esac
  shift
done

say()  { printf '%s\n' "$*"; }
step() { printf '\n\033[1;36m── %s\033[0m\n' "$*"; }
ok()   { printf '   \033[32m✓\033[0m %s\n' "$*"; }
warn() { printf '   \033[33m!\033[0m %s\n' "$*"; }
die()  { printf '\033[31m✗ %s\033[0m\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "请用 root 运行：curl -fsSL <中心>/install-agent.sh | sudo bash -s -- --token ..."

if [ "$DO_UNINSTALL" = 1 ]; then
  step "卸载 fwprobe agent"
  systemctl disable --now "$SERVICE" 2>/dev/null || true
  rm -f "$UNIT"; systemctl daemon-reload 2>/dev/null || true
  rm -rf "$AGENT_DIR" "$AGENT_ETC" "$AGENT_STATE"
  ok "已卸载（中心侧节点记录还在，可在后台删除）"
  exit 0
fi

[ -n "$TOKEN" ] || die "缺少 --token（在中心后台「添加节点」处生成）"
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

step "3. 写入配置"
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
chmod 600 "$AGENT_ETC/config.json"      # 里面有 token
ok "配置写入 $AGENT_ETC/config.json（权限 600）"

step "4. 注册 systemd 服务"
cat > "$UNIT" <<EOF
[Unit]
Description=fwprobe agent (VPS probe collector)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 $AGENT_DIR/agent.py
Restart=always
RestartSec=10
Nice=10
# 采集只读 /proc 与本地网络，不需要额外权限；ICMP 目标若启用需保留 root
User=root

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now "$SERVICE" >/dev/null 2>&1 || true

step "5. 首次上报自检"
sleep 3
if systemctl is-active --quiet "$SERVICE"; then
  ok "服务运行中（$SERVICE）"
else
  warn "服务没起来，看日志：journalctl -u $SERVICE -n 30 --no-pager"
fi
if out="$(python3 "$AGENT_DIR/agent.py" --once 2>&1)"; then
  ok "首次上报成功：$out"
else
  warn "首次上报失败：$out"
  warn "如果是 401/403，请确认 token 与中心上该节点的 token 一致"
fi

say ""
say "------------------------------------------------------------------"
say "  探针 agent 安装完成"
say "  中心地址 : $SERVER"
say "  采集间隔 : ${INTERVAL}s（探测 60s 一轮）"
say "  查看状态 : systemctl status $SERVICE"
say "  看日志   : journalctl -u $SERVICE -f"
say "  卸载     : curl -fsSL $SERVER/install-agent.sh | sudo bash -s -- --uninstall"
say "------------------------------------------------------------------"
