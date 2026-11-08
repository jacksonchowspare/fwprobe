#!/usr/bin/env bash
# ============================================================================
#  iProbe 探针服务中心 · 安装/升级脚本
#
#  一键：
#    curl -fsSL https://raw.githubusercontent.com/jacksonchowspare/fwprobe/main/install.sh | sudo bash
#
#  参数：
#    -p, --port N       服务端口（默认 17899，只监听 127.0.0.1）
#    --bind IP          监听地址，默认 127.0.0.1
#    --base-url URL     对外地址（公开状态页域名，如 https://status.isusz.com）
#    --uninstall        卸载（停服务 + 删程序，保留数据库）
#    --purge            卸载并删除数据库与配置（不可恢复）
#    -h, --help         帮助
#
#  说明：
#    * 零第三方依赖：只用 python3 标准库 + 内置 sqlite3
#    * 服务只监听 127.0.0.1，对外由 nginx 反代（80/443）
#    * 首次安装会生成管理 token（写在 /etc/fwprobe/config.json，仅 root 可读）
# ============================================================================
set -Eeuo pipefail

APP_DIR="/usr/local/lib/fwprobe"
ETC_DIR="/etc/fwprobe"
STATE_DIR="/var/lib/fwprobe"
UNIT="/etc/systemd/system/fwprobe.service"
SERVICE="fwprobe"
PORT="17899"
BIND="127.0.0.1"
BASE_URL=""
MODE="install"

err_trap() { printf '\033[31m✗ 脚本异常退出（%s）：%s\033[0m\n' "$1" "$2" >&2; }
trap 'err_trap "$?" "$BASH_COMMAND"' ERR

say()  { printf '%s\n' "$*"; }
step() { printf '\n\033[1;36m── %s\033[0m\n' "$*"; }
ok()   { printf '   \033[32m✓\033[0m %s\n' "$*"; }
warn() { printf '   \033[33m!\033[0m %s\n' "$*"; }
die()  { printf '\033[31m✗ %s\033[0m\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    -p|--port)   PORT="${2:-}"; shift ;;
    --bind)      BIND="${2:-}"; shift ;;
    --base-url)  BASE_URL="${2:-}"; shift ;;
    --uninstall) MODE="uninstall" ;;
    --purge)     MODE="purge" ;;
    -h|--help)   sed -n '2,22p' "$0"; exit 0 ;;
    *) die "未知参数: $1（用 --help 看用法）" ;;
  esac
  shift
done

[ "$(id -u)" -eq 0 ] || die "请用 root 运行（sudo bash install.sh）"

if [ "$MODE" = "uninstall" ] || [ "$MODE" = "purge" ]; then
  step "卸载 iProbe"
  systemctl disable --now "$SERVICE" 2>/dev/null || true
  rm -f "$UNIT"; systemctl daemon-reload 2>/dev/null || true
  rm -rf "$APP_DIR"
  if [ "$MODE" = "purge" ]; then
    rm -rf "$ETC_DIR" "$STATE_DIR"
    ok "已彻底卸载（含配置与数据库）"
  else
    ok "已卸载程序与服务；配置(/etc/fwprobe)与数据库(/var/lib/fwprobe)保留"
  fi
  say "  nginx 里的 status 域名 server 块需要自己删（如 /etc/nginx/conf.d/fwprobe-status.conf）"
  exit 0
fi

step "1. 环境检查"
command -v python3 >/dev/null 2>&1 || die "缺少 python3（apt-get install -y python3）"
say "   python3 : $(python3 -V 2>&1)"
say "   系统    : $(. /etc/os-release 2>/dev/null && echo "${PRETTY_NAME:-unknown}" || echo unknown)"
python3 - <<'PY' || die "python3 缺少 sqlite3 模块"
import sqlite3, sys
sys.exit(0 if sqlite3.sqlite_version_info >= (3, 20) else 1)
PY
ok "sqlite3 内置模块可用（$(python3 -c 'import sqlite3;print(sqlite3.sqlite_version)')）"

step "2. 部署程序"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[ -f "$SRC_DIR/probe.py" ] || die "找不到 probe.py（请在仓库目录内运行本脚本）"
mkdir -p "$APP_DIR/static" "$ETC_DIR" "$STATE_DIR"
install -m 755 "$SRC_DIR/probe.py" "$APP_DIR/probe.py"
install -m 755 "$SRC_DIR/agent.py" "$APP_DIR/agent.py"
install -m 644 "$SRC_DIR/install-agent.sh" "$APP_DIR/install-agent.sh"
for f in "$SRC_DIR"/static/*; do
  [ -f "$f" ] || continue
  install -m 644 "$f" "$APP_DIR/static/$(basename "$f")"
done
ok "程序 → $APP_DIR"

step "3. 配置文件"
python3 - "$ETC_DIR/config.json" "$PORT" "$BIND" "$BASE_URL" <<'PY'
import json, os, secrets, sys
path, port, bind, base = sys.argv[1:5]
cfg = {"port": int(port), "bind": bind, "db": "/var/lib/fwprobe/probe.db",
       "base_url": base.rstrip("/"), "admin_token": ""}
try:
    with open(path, encoding="utf-8") as fh:
        old = json.load(fh)
    cfg["admin_token"] = old.get("admin_token") or cfg["admin_token"]
    if not base and old.get("base_url"):
        cfg["base_url"] = old["base_url"]
except FileNotFoundError:
    pass
if not cfg["admin_token"]:
    cfg["admin_token"] = secrets.token_urlsafe(32)
with open(path, "w", encoding="utf-8") as fh:
    json.dump(cfg, fh, ensure_ascii=False, indent=2)
os.chmod(path, 0o600)
PY
ADMIN_TOKEN="$(python3 -c "import json;print(json.load(open('$ETC_DIR/config.json'))['admin_token'])")"
ok "配置 → $ETC_DIR/config.json（权限 600）"

step "4. systemd 服务"
cat > "$UNIT" <<EOF
[Unit]
Description=iProbe (VPS probe center)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 $APP_DIR/probe.py serve
Restart=always
RestartSec=5
User=root
Environment=FWPROBE_CONFIG=$ETC_DIR/config.json

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable "$SERVICE" >/dev/null 2>&1 || true
systemctl restart "$SERVICE"
ok "服务已启动（$SERVICE）"

step "5. 自检"
sleep 2
for i in 1 2 3 4 5; do
  if curl -fsS -m 3 "http://127.0.0.1:$PORT/healthz" >/tmp/.fwprobe_health 2>/dev/null; then break; fi
  sleep 1
done
if [ -s /tmp/.fwprobe_health ]; then
  ok "本机健康检查：$(cat /tmp/.fwprobe_health)"
else
  warn "本机健康检查失败，看日志：journalctl -u $SERVICE -n 40 --no-pager"
fi
rm -f /tmp/.fwprobe_health

say ""
say "=================================================================="
say "  iProbe 安装完成"
say "=================================================================="
say "  监听      : http://$BIND:$PORT（不直接对公网）"
say "  数据库    : $STATE_DIR/probe.db"
say "  管理 token: ${ADMIN_TOKEN:0:8}…（完整值在 /etc/fwprobe/config.json）"
say ""
say "  下一步："
say "    1) 在 nginx 里为公开域名加 server 块，反代到 127.0.0.1:$PORT"
say "    2) 添加节点（本机 CLI）："
say "       python3 $APP_DIR/probe.py addnode --alias \"香港-1\" --group HK"
say "    3) 按输出的命令在被监控机器上装 agent"
say "  常用："
say "    python3 $APP_DIR/probe.py listnodes"
say "    systemctl status $SERVICE --no-pager"
say "=================================================================="
