#!/usr/bin/env bash
# 本地端到端自测：起中心 → 建节点 → agent 上报 → 查公开摘要
set -uo pipefail
cd /home/saxon/fwprobe

TMPD=$(mktemp -d)
PORT=17901
export FWPROBE_CONFIG="$TMPD/config.json"
export FWPROBE_DB="$TMPD/probe.db"
export FWPROBE_AGENT_SPOOL="$TMPD/spool"
cat > "$FWPROBE_CONFIG" <<EOF
{"port": $PORT, "bind": "127.0.0.1", "db": "$TMPD/probe.db", "base_url": "http://127.0.0.1:$PORT", "admin_token": "admintok"}
EOF

python3 probe.py serve >"$TMPD/serve.log" 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null; rm -rf "$TMPD"' EXIT

for i in $(seq 1 20); do
  curl -fsS -m 2 "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1 && break
  sleep 0.3
done
echo "== healthz =="; curl -s -m 3 "http://127.0.0.1:$PORT/healthz"; echo

echo "== 建节点 =="
OUT=$(python3 probe.py addnode --alias "本机自测" --group LAB --quota 100G --expires 2026-12-31 --server "http://127.0.0.1:$PORT")
echo "$OUT"
TOKEN=$(echo "$OUT" | grep -oP -- '--token \K[^\s]+')
[ -n "$TOKEN" ] || { echo "!! 没拿到 token"; exit 1; }

echo "== agent 上报 =="
FWPROBE_SERVER="http://127.0.0.1:$PORT" FWPROBE_TOKEN="$TOKEN" python3 agent.py --once || exit 1

echo "== 再报一次（产生 CPU/速率差值） =="
sleep 2
FWPROBE_SERVER="http://127.0.0.1:$PORT" FWPROBE_TOKEN="$TOKEN" python3 agent.py --once || exit 1

echo "== 公开摘要 =="
curl -s -m 5 "http://127.0.0.1:$PORT/api/public/summary" | python3 -m json.tool | head -60

echo "== 断言 =="
curl -s -m 5 "http://127.0.0.1:$PORT/api/public/summary" -o "$TMPD/summary.json"
python3 - "$TMPD/summary.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
n = d["nodes"][0]
ok = []
ok.append(("有节点", len(d["nodes"]) == 1))
ok.append(("别名", n["alias"] == "本机自测"))
ok.append(("在线", n["online"] is True))
ok.append(("有样本", n["sample"] is not None))
ok.append(("有三网探测", len(n["checks"]) == 3))
ok.append(("探测有延迟", all(c["ravg"] is not None for c in n["checks"])))
ok.append(("无 IP 泄露", "public_ip" not in n and "token_hash" not in n))
ok.append(("配额", n["quota_bytes"] == 100 * 1024**3))
ok.append(("到期", n["expires_at"] == "2026-12-31"))
for name, cond in ok:
    print(("  ✓ " if cond else "  ✗ ") + name)
print("结果:", sum(1 for _, c in ok if c), "通过,", sum(1 for _, c in ok if not c), "失败")
sys.exit(0 if all(c for _, c in ok) else 1)
PY
RC=$?
echo "== 服务日志（末尾） =="; tail -5 "$TMPD/serve.log"
exit $RC
