#!/usr/bin/env python3
"""iProbe —— 自建 VPS 探针服务中心（agent 主动上报模型，零第三方依赖）

设计要点
--------
* agent 定时把资源指标与三网探测结果 POST 到 /api/report（每台一个 token）；
  中心不主动连节点，所以节点在内网 / NAT 后面也能上报。
* 存储用内置 sqlite3：原始 30s 数据保留 7 天，1 分钟与 1 小时聚合各留 30 天 / 1 年。
* 公开页只读；管理动作走带 token 的 API 与本机 CLI（addnode / rmtoken / delnode）。

用法
----
    probe.py serve
    probe.py addnode --alias "香港-1" [--group HK] [--quota 500G] [--expires 2026-12-31]
    probe.py listnodes
    probe.py rmtoken <node_id>      # 轮换 token（旧 agent 立即失效）
    probe.py delnode <node_id>
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import shutil
import sqlite3
import sys
import threading
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

VERSION = "0.5.15"
APP_NAME = "iProbe"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")

CONFIG_PATH = os.environ.get("FWPROBE_CONFIG", "/etc/fwprobe/config.json")
DEFAULT_PORT = 17899
DEFAULT_BIND = "127.0.0.1"

OFFLINE_AFTER = 120          # 秒：超过这么久没上报视为离线（连续 4 次 30s 采样）
RAW_KEEP_DAYS = 7
MIN_KEEP_DAYS = 30
HOUR_KEEP_DAYS = 365
MAX_BODY = 512 * 1024        # 单次上报体积上限

SCHEMA = """
CREATE TABLE IF NOT EXISTS nodes (
    id          TEXT PRIMARY KEY,
    alias       TEXT NOT NULL,
    grp         TEXT DEFAULT '',
    token_hash  TEXT NOT NULL,
    os_id       TEXT DEFAULT '',
    os_name     TEXT DEFAULT '',
    kernel      TEXT DEFAULT '',
    hostname    TEXT DEFAULT '',
    public_ip   TEXT DEFAULT '',
    country     TEXT DEFAULT '',
    quota_bytes INTEGER DEFAULT 0,      -- 0 = 不限量
    expires_at  TEXT DEFAULT '',        -- YYYY-MM-DD，空 = 未填
    agent_ver   TEXT DEFAULT '',
    target_ver  TEXT DEFAULT '',      -- 升级目标版本，agent 升到后清空
    pending_uninstall INTEGER DEFAULT 0,  -- 中心点了「卸载探针」，等 agent 下次上报执行
    src         TEXT DEFAULT '',      -- 外部面板的节点 id（面板卸载时用它精确匹配）
    note        TEXT DEFAULT '',
    enabled     INTEGER DEFAULT 1,
    created     INTEGER DEFAULT 0,
    last_seen   INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS samples (
    node_id     TEXT NOT NULL,
    ts          INTEGER NOT NULL,
    cpu         REAL,
    cpu_cores   INTEGER,
    mem_used    INTEGER, mem_total   INTEGER,
    swap_used   INTEGER, swap_total  INTEGER,
    disk_used   INTEGER, disk_total  INTEGER,
    load1       REAL, load5 REAL, load15 REAL,
    iface       TEXT,
    rx_bps      INTEGER, tx_bps      INTEGER,
    rx_total    INTEGER, tx_total    INTEGER,
    tcp         INTEGER, tcp_estab   INTEGER, udp INTEGER,
    procs       INTEGER, uptime      INTEGER,
    PRIMARY KEY (node_id, ts)
);
CREATE INDEX IF NOT EXISTS idx_samples_ts ON samples(ts);

CREATE TABLE IF NOT EXISTS checks (
    node_id TEXT NOT NULL,
    ts      INTEGER NOT NULL,
    name    TEXT NOT NULL,
    proto   TEXT, host TEXT, port INTEGER, family TEXT,
    ok      INTEGER, loss REAL,
    rmin    REAL, ravg REAL, rmax REAL,
    PRIMARY KEY (node_id, ts, name)
);
CREATE INDEX IF NOT EXISTS idx_checks_ts ON checks(ts);

CREATE TABLE IF NOT EXISTS samples_min (
    node_id TEXT NOT NULL, ts INTEGER NOT NULL,
    cpu REAL, mem_used INTEGER, mem_total INTEGER, disk_used INTEGER, disk_total INTEGER,
    load1 REAL, rx_bps INTEGER, tx_bps INTEGER, tcp INTEGER, udp INTEGER,
    PRIMARY KEY (node_id, ts)
);
CREATE TABLE IF NOT EXISTS samples_hour (
    node_id TEXT NOT NULL, ts INTEGER NOT NULL,
    cpu REAL, mem_used INTEGER, mem_total INTEGER, disk_used INTEGER, disk_total INTEGER,
    load1 REAL, rx_bps INTEGER, tx_bps INTEGER, tcp INTEGER, udp INTEGER,
    PRIMARY KEY (node_id, ts)
);
CREATE TABLE IF NOT EXISTS checks_min (
    node_id TEXT NOT NULL, ts INTEGER NOT NULL, name TEXT NOT NULL,
    ok INTEGER, loss REAL, ravg REAL, rmax REAL,
    PRIMARY KEY (node_id, ts, name)
);
CREATE TABLE IF NOT EXISTS ptokens (
    id        TEXT PRIMARY KEY,
    label     TEXT DEFAULT '',
    token_hash TEXT NOT NULL,
    created   INTEGER NOT NULL,
    last_used INTEGER DEFAULT 0,
    enabled   INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS audit (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    ts      INTEGER NOT NULL,
    action  TEXT NOT NULL,
    target  TEXT DEFAULT '',
    detail  TEXT DEFAULT '',
    ip      TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit(ts);

CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id TEXT NOT NULL,
    kind TEXT NOT NULL,          -- offline | check
    target TEXT DEFAULT '',
    started INTEGER, ended INTEGER DEFAULT 0,
    note TEXT DEFAULT ''
);
"""


# --------------------------------------------------------------------------- 配置
def load_config():
    cfg = {"port": DEFAULT_PORT, "bind": DEFAULT_BIND,
           "db": "/var/lib/fwprobe/probe.db", "base_url": "", "admin_token": ""}
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as fh:
            cfg.update(json.load(fh) or {})
    except FileNotFoundError:
        pass
    except Exception as exc:                      # 配置坏了不能让服务起不来
        print(f"[warn] 读取配置失败（用默认值）: {exc}", file=sys.stderr)
    cfg["port"] = int(os.environ.get("FWPROBE_PORT", cfg.get("port") or DEFAULT_PORT))
    cfg["bind"] = os.environ.get("FWPROBE_BIND", cfg.get("bind") or DEFAULT_BIND)
    cfg["db"] = os.environ.get("FWPROBE_DB", cfg.get("db"))
    cfg["admin_token"] = os.environ.get("FWPROBE_ADMIN_TOKEN", cfg.get("admin_token") or "")
    return cfg


# --------------------------------------------------------------------------- 存储
def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def new_token() -> str:
    return secrets.token_urlsafe(32)


MAX_SERIES_POINTS = 720        # 详情页曲线最多给前端 720 个点（画布 ~1000px，再多就是无效像素）


def downsample(rows, limit, keys):
    """把时间序列按等宽桶取平均降到 limit 以内。保留每桶的 ts（桶内首条）。

    为什么在服务端降：一个月的分钟聚合是 4 万多点，既撑爆 JSON 也画不出东西；
    降到 720 点后一个月 ≈ 每小时一个点，曲线形状仍然对。
    """
    rows = [r for r in rows if r]
    if limit <= 0 or len(rows) <= limit:
        return rows
    step = len(rows) / float(limit)
    out = []
    for i in range(int(limit)):
        chunk = rows[int(i * step):int((i + 1) * step)] or [rows[min(len(rows) - 1, int(i * step))]]
        item = {"ts": chunk[0].get("ts")}
        for k in keys:
            if not any(k in c for c in chunk):
                continue
            vals = [c[k] for c in chunk if isinstance(c.get(k), (int, float))]
            item[k] = (sum(vals) / len(vals)) if vals else None
        # 非平均字段（ok 等）沿用最后一条
        for k, v in chunk[-1].items():
            item.setdefault(k, v)
        out.append(item)
    return out


def parse_groups(raw, fallback=""):
    """分组字段统一解析：优先 JSON 数组，老数据回落到单个 grp 字符串"""
    if raw:
        try:
            v = json.loads(raw)
            if isinstance(v, list):
                return [str(x).strip() for x in v if str(x).strip()]
            if isinstance(v, str) and v.strip():
                return [v.strip()]
        except (ValueError, TypeError):
            return [x.strip() for x in str(raw).split(",") if x.strip()]
    return [fallback] if fallback else []


def dump_groups(groups):
    return json.dumps([str(g).strip() for g in (groups or []) if str(g).strip()], ensure_ascii=False)


UPGRADE_MIN_VER = (0, 5, 4)     # 从这版起 agent 才认升级指令，更老的要手动升一次


def _ver_tuple(v):
    try:
        return tuple(int(x) for x in str(v or "").strip().split("."))
    except ValueError:
        return (0,)


def agent_file_meta():
    """中心发布的 agent.py 版本 + sha256（读不到就返回空，升级功能自动降级为不可用）"""
    path = os.path.join(BASE_DIR, "agent.py")
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError:
        return "", ""
    m = re.search(rb'^VERSION\s*=\s*"([0-9][0-9.]*)"', raw, re.M)
    return ((m.group(1).decode() if m else ""), hashlib.sha256(raw).hexdigest())


TAG_MAX = 6                  # 每台最多 6 个自定义标签
TAG_TEXT_MAX = 24            # 标签文字最多 24 个字符
TAG_COLORS = ["#fbbf24", "#34d399", "#4da3ff", "#a78bfa", "#f472b6",
              "#fb923c", "#22d3ee", "#94a3b8", "#f43f5e", "#a3e635"]


SESSION_COOKIE = "iprobe_sess"
SESSION_TTL = 12 * 3600             # 默认 12 小时
SESSION_TTL_LONG = 30 * 24 * 3600   # 勾「保持登录」30 天
LOGIN_FAIL_WINDOW = 600        # 10 分钟
LOGIN_FAIL_MAX = 5             # 同一 IP 最多错 5 次
_login_fails = {}              # ip -> [失败时间戳]
_login_lock = threading.Lock()


def hash_password(pw, iterations=200_000):
    """PBKDF2-HMAC-SHA256，存成 pbkdf2_sha256$迭代$盐$哈希"""
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt, iterations)
    return f"pbkdf2_sha256${iterations}${salt.hex()}${dk.hex()}"


def verify_password(pw, stored):
    try:
        algo, it, salt, want = str(stored).split("$")
        if algo != "pbkdf2_sha256" or not pw:
            return False
        dk = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), bytes.fromhex(salt), int(it))
        return hmac.compare_digest(dk.hex(), want)
    except Exception:
        return False


def save_config(cfg):
    """回写配置（保持 0600；先写临时文件再 rename，避免写一半断电）"""
    os.makedirs(os.path.dirname(CONFIG_PATH) or ".", exist_ok=True)
    tmp = CONFIG_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(cfg, fh, ensure_ascii=False, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, CONFIG_PATH)


def make_session(admin_token, ttl=SESSION_TTL):
    exp = int(time.time()) + ttl
    sig = hmac.new(admin_token.encode("utf-8"), str(exp).encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{exp}.{sig}", exp


def read_session(cookie_header, admin_token):
    """返回剩余秒数（>0 有效），否则 0"""
    if not cookie_header or not admin_token:
        return 0
    for part in cookie_header.split(";"):
        k, _, v = part.strip().partition("=")
        if k != SESSION_COOKIE:
            continue
        exp, _, sig = v.partition(".")
        if not exp.isdigit() or not sig:
            return 0
        want = hmac.new(admin_token.encode("utf-8"), exp.encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, want):
            return 0
        return max(0, int(exp) - int(time.time()))
    return 0


def login_allowed(ip):
    now = int(time.time())
    with _login_lock:
        hits = [t for t in _login_fails.get(ip, []) if now - t < LOGIN_FAIL_WINDOW]
        _login_fails[ip] = hits
        return len(hits) < LOGIN_FAIL_MAX, LOGIN_FAIL_WINDOW - (now - hits[0]) if hits else 0


def note_login_fail(ip):
    with _login_lock:
        _login_fails.setdefault(ip, []).append(int(time.time()))


def clear_login_fail(ip):
    with _login_lock:
        _login_fails.pop(ip, None)


def _clean_color(c):
    """颜色只接受 #rgb / #rrggbb，其它一律回落到预设第一色（防止把 CSS 注进去）"""
    c = str(c or "").strip()
    if re.fullmatch(r"#[0-9a-fA-F]{6}", c) or re.fullmatch(r"#[0-9a-fA-F]{3}", c):
        return c.lower()
    return TAG_COLORS[0]


def parse_tags(raw):
    """标签列：JSON 数组 [{"t": 文字, "c": 颜色}]，脏数据直接丢掉"""
    if not raw:
        return []
    try:
        v = json.loads(raw) if isinstance(raw, str) else raw
    except (ValueError, TypeError):
        return []
    out = []
    for item in (v if isinstance(v, list) else []):
        if isinstance(item, dict):
            t = str(item.get("t") or "").strip()[:TAG_TEXT_MAX]
            c = _clean_color(item.get("c"))
        else:
            t, c = str(item).strip()[:TAG_TEXT_MAX], TAG_COLORS[0]
        if t:
            out.append({"t": t, "c": c})
        if len(out) >= TAG_MAX:
            break
    return out


def sanitize_tags(tags):
    """对外部输入做清洗：字符串/数组都收，去空、限长、限数量"""
    if isinstance(tags, str):
        tags = [{"t": x, "c": TAG_COLORS[0]} for x in tags.split(",")]
    return parse_tags(tags if isinstance(tags, list) else [])


def dump_tags(tags):
    return json.dumps(sanitize_tags(tags), ensure_ascii=False)


class Store:
    def __init__(self, path: str):
        self.path = path
        d = os.path.dirname(path)
        if d:
            os.makedirs(d, exist_ok=True)
        self.lock = threading.Lock()
        self.conn = sqlite3.connect(path, check_same_thread=False, timeout=15)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.executescript(SCHEMA)
        self.conn.commit()
        self._migrate()

    # -- 节点 ---------------------------------------------------------------
    def add_node(self, alias, grp="", quota_bytes=0, expires_at="", note="", groups=None, tags=None):
        nid = secrets.token_hex(6)
        tok = new_token()
        glist = [g.strip() for g in (groups if groups is not None else ([grp] if grp else [])) if g and g.strip()]
        with self.lock:
            self.conn.execute(
                "INSERT INTO nodes(id,alias,grp,groups,tags,token_hash,quota_bytes,expires_at,note,created)"
                " VALUES(?,?,?,?,?,?,?,?,?,?)",
                (nid, alias, (glist[0] if glist else ""), dump_groups(glist), dump_tags(tags),
                 sha256_hex(tok), int(quota_bytes or 0), expires_at or "", note or "", int(time.time())))
            self.conn.commit()
        return nid, tok

    def rotate_token(self, nid):
        tok = new_token()
        with self.lock:
            cur = self.conn.execute("UPDATE nodes SET token_hash=? WHERE id=?", (sha256_hex(tok), nid))
            self.conn.commit()
            return tok if cur.rowcount else None

    def _migrate(self):
        """轻量迁移：新增 groups 列（多分组），老库/老数据继续可用"""
        cols = {r[1] for r in self.conn.execute("PRAGMA table_info(nodes)")}
        if "groups" not in cols:
            self.conn.execute("ALTER TABLE nodes ADD COLUMN groups TEXT DEFAULT ''")
            self.conn.commit()
            # 把老的单个 grp 灌进去，保证卡片标签不丢
            for r in self.conn.execute("SELECT id,grp FROM nodes WHERE grp != ''").fetchall():
                self.conn.execute("UPDATE nodes SET groups=? WHERE id=?",
                                  (dump_groups([r[1]]), r[0]))
            self.conn.commit()
        if "tags" not in cols:
            self.conn.execute("ALTER TABLE nodes ADD COLUMN tags TEXT DEFAULT ''")
            self.conn.commit()
        if "target_ver" not in cols:
            self.conn.execute("ALTER TABLE nodes ADD COLUMN target_ver TEXT DEFAULT ''")
            self.conn.commit()
        if "pending_uninstall" not in cols:
            self.conn.execute("ALTER TABLE nodes ADD COLUMN pending_uninstall INTEGER DEFAULT 0")
            self.conn.commit()
        if "src" not in cols:
            self.conn.execute("ALTER TABLE nodes ADD COLUMN src TEXT DEFAULT ''")
            self.conn.commit()
        self.conn.execute("UPDATE nodes SET country='UK' WHERE UPPER(country)='GB'")
        self.conn.commit()

    def nodes(self):
        with self.lock:
            return [dict(r) for r in self.conn.execute("SELECT * FROM nodes ORDER BY created")]

    def node(self, nid):
        with self.lock:
            r = self.conn.execute("SELECT * FROM nodes WHERE id=?", (nid,)).fetchone()
            return dict(r) if r else None

    def node_by_token(self, tok):
        h = sha256_hex(tok)
        with self.lock:
            r = self.conn.execute("SELECT * FROM nodes WHERE token_hash=?", (h,)).fetchone()
            return dict(r) if r else None

    def update_node(self, nid, **fields):
        if "groups" in fields:
            glist = [str(g).strip() for g in (fields.pop("groups") or []) if str(g).strip()]
            fields["groups"] = dump_groups(glist)
            fields["grp"] = glist[0] if glist else ""       # grp 保留为主分组，兼容旧代码
        if "tags" in fields:
            fields["tags"] = dump_tags(fields.pop("tags"))
        allowed = {"alias", "grp", "groups", "quota_bytes", "expires_at", "note", "enabled",
                   "country", "tags", "target_ver", "pending_uninstall", "src"}
        kv = {k: v for k, v in fields.items() if k in allowed}
        if not kv:
            return False
        sql = "UPDATE nodes SET " + ",".join(f"{k}=?" for k in kv) + " WHERE id=?"
        with self.lock:
            cur = self.conn.execute(sql, (*kv.values(), nid))
            self.conn.commit()
            return cur.rowcount > 0

    # ---------- 供应令牌（给 fwpanel2 之类的外部面板建节点用；只能在中心本机生成） ----------
    def add_ptoken(self, label=""):
        pid = secrets.token_hex(6)
        tok = "pv_" + secrets.token_urlsafe(32)
        with self.lock:
            self.conn.execute("INSERT INTO ptokens(id,label,token_hash,created,enabled) VALUES(?,?,?,?,1)",
                              (pid, (label or "").strip()[:60], sha256_hex(tok), int(time.time())))
            self.conn.commit()
        return pid, tok

    def find_ptoken(self, tok):
        if not tok:
            return None
        h = sha256_hex(tok)
        with self.lock:
            row = self.conn.execute(
                "SELECT * FROM ptokens WHERE token_hash=? AND enabled=1", (h,)).fetchone()
            if row:
                self.conn.execute("UPDATE ptokens SET last_used=? WHERE id=?",
                                  (int(time.time()), row["id"]))
                self.conn.commit()
        return dict(row) if row else None

    def list_ptokens(self):
        with self.lock:
            return [dict(r) for r in self.conn.execute(
                "SELECT id,label,created,last_used,enabled FROM ptokens ORDER BY created DESC")]

    def del_ptoken(self, pid):
        with self.lock:
            cur = self.conn.execute("DELETE FROM ptokens WHERE id=?", (pid,))
            self.conn.commit()
            return cur.rowcount > 0

    def audit(self, action, target="", detail="", ip=""):
        with self.lock:
            self.conn.execute("INSERT INTO audit(ts,action,target,detail,ip) VALUES(?,?,?,?,?)",
                              (int(time.time()), action, target or "", detail or "", ip or ""))
            self.conn.commit()

    def audit_list(self, limit=200):
        with self.lock:
            return [dict(r) for r in self.conn.execute(
                "SELECT * FROM audit ORDER BY id DESC LIMIT ?", (int(limit),))]

    def delete_node(self, nid):
        with self.lock:
            self.conn.execute("DELETE FROM nodes WHERE id=?", (nid,))
            for t in ("samples", "checks", "samples_min", "samples_hour", "checks_min"):
                self.conn.execute(f"DELETE FROM {t} WHERE node_id=?", (nid,))
            self.conn.commit()

    # -- 上报 ---------------------------------------------------------------
    def ingest(self, node, payload, peer_ip):
        ts = int(payload.get("ts") or time.time())
        # 以中心时间为主：agent 时钟偏差别把它当基准
        now = int(time.time())
        if abs(now - ts) > 600:
            ts = now
        with self.lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO samples(node_id,ts,cpu,cpu_cores,mem_used,mem_total,"
                "swap_used,swap_total,disk_used,disk_total,load1,load5,load15,iface,rx_bps,tx_bps,"
                "rx_total,tx_total,tcp,tcp_estab,udp,procs,uptime)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (node["id"], ts,
                 payload.get("cpu"), payload.get("cpu_cores"),
                 (payload.get("mem") or {}).get("used"), (payload.get("mem") or {}).get("total"),
                 (payload.get("swap") or {}).get("used"), (payload.get("swap") or {}).get("total"),
                 (payload.get("disk") or {}).get("used"), (payload.get("disk") or {}).get("total"),
                 (payload.get("load") or [None])[0] if payload.get("load") else None,
                 (payload.get("load") or [None, None])[1] if payload.get("load") else None,
                 (payload.get("load") or [None, None, None])[2] if payload.get("load") else None,
                 (payload.get("net") or {}).get("iface"),
                 (payload.get("net") or {}).get("rx_bps"), (payload.get("net") or {}).get("tx_bps"),
                 (payload.get("net") or {}).get("rx_total"), (payload.get("net") or {}).get("tx_total"),
                 (payload.get("conn") or {}).get("tcp"), (payload.get("conn") or {}).get("estab"),
                 (payload.get("conn") or {}).get("udp"),
                 payload.get("procs"), payload.get("uptime")))
            cts = int(payload.get("checks_ts") or 0) or ts
            if abs(cts - now) > 600:
                cts = ts                      # 补发/时钟漂移，拉回本次上报时刻
            for c in (payload.get("checks") or []):
                self.conn.execute(
                    "INSERT OR REPLACE INTO checks(node_id,ts,name,proto,host,port,family,ok,loss,rmin,ravg,rmax)"
                    " VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                    (node["id"], cts, (c.get("name") or "?")[:32], c.get("proto"), c.get("host"),
                     c.get("port"), c.get("family"), 1 if c.get("ok") else 0,
                     c.get("loss"), c.get("min"), c.get("avg"), c.get("max")))
            self.conn.execute(
                "UPDATE nodes SET last_seen=?, os_id=COALESCE(NULLIF(?,''),os_id),"
                " os_name=COALESCE(NULLIF(?,''),os_name), kernel=COALESCE(NULLIF(?,''),kernel),"
                " hostname=COALESCE(NULLIF(?,''),hostname), agent_ver=COALESCE(NULLIF(?,''),agent_ver),"
                " public_ip=? WHERE id=?",
                (now, payload.get("os_id") or "", payload.get("os_name") or "",
                 payload.get("kernel") or "", payload.get("hostname") or "",
                 payload.get("agent") or "", peer_ip or "", node["id"]))
            self.conn.commit()
        self._maybe_country(node, peer_ip)
        return now

    def _maybe_country(self, node, peer_ip):
        """新节点首次上报：后台查一次归属地，写回 country（后台可手动覆盖）。"""
        if node.get("country"):
            return
        key = node["id"]
        if key in COUNTRY_DONE:
            return
        COUNTRY_DONE.add(key)

        def work():
            code = lookup_country(peer_ip)
            if not code:
                COUNTRY_DONE.discard(key)        # 下次上报再试
                return
            try:
                self.update_node(key, country=code)
            except Exception:
                pass

        threading.Thread(target=work, daemon=True).start()

    # -- 查询 ---------------------------------------------------------------
    def latest(self, nid):
        with self.lock:
            s = self.conn.execute(
                "SELECT * FROM samples WHERE node_id=? ORDER BY ts DESC LIMIT 1", (nid,)).fetchone()
            c = [dict(r) for r in self.conn.execute(
                "SELECT * FROM checks WHERE node_id=? AND ts=(SELECT MAX(ts) FROM checks WHERE node_id=?)",
                (nid, nid))]
        return (dict(s) if s else None), c

    def totals(self, nid):
        """出入站累计：取当天第一笔与最后一笔的差值累加（/proc/net/dev 重启会归零）。"""
        with self.lock:
            r = self.conn.execute(
                "SELECT MIN(ts) mn, MAX(ts) mx FROM samples WHERE node_id=?", (nid,)).fetchone()
            if not r or not r["mn"]:
                return 0, 0
            first = self.conn.execute(
                "SELECT rx_total,tx_total FROM samples WHERE node_id=? ORDER BY ts ASC LIMIT 1",
                (nid,)).fetchone()
            last = self.conn.execute(
                "SELECT rx_total,tx_total FROM samples WHERE node_id=? ORDER BY ts DESC LIMIT 1",
                (nid,)).fetchone()
        rx = max(0, (last["rx_total"] or 0) - (first["rx_total"] or 0))
        tx = max(0, (last["tx_total"] or 0) - (first["tx_total"] or 0))
        return rx, tx

    def check_hist(self, nid, n=20):
        """每条探测线路最近 n 次的原始结果（旧→新），供详情页/调试用。"""
        with self.lock:
            rows = self.conn.execute(
                "SELECT ts,name,ok,loss,rmin,ravg FROM checks WHERE node_id=? ORDER BY ts DESC LIMIT ?",
                (nid, n * 8)).fetchall()
        out = {}
        for r in reversed(rows):
            out.setdefault(r["name"], []).append({
                "ts": r["ts"], "ok": r["ok"], "loss": r["loss"],
                "min": r["rmin"], "avg": r["ravg"]})
        return {k: v[-n:] for k, v in out.items()}

    def three(self, nid, window=None, buckets=None):
        """三网展示口径（对齐 Komari Glassmorphism 主题）：

        最近 1 小时均分成 20 格（每格 3 分钟）；每格延迟 = 格内成功测量的平均值，
        丢包 = 格内丢包次数 / 总次数 ×100；大数字 = 整段窗口的平均延迟与平均丢包。
        没有数据的格子给 None（前端画灰）。
        """
        window = int(window or THREE_WINDOW)
        buckets = int(buckets or THREE_BUCKETS)
        now = int(time.time())
        start = now - window
        size = window / float(buckets)
        with self.lock:
            rows = self.conn.execute(
                "SELECT ts,name,ok,loss,rmin,ravg FROM checks"
                " WHERE node_id=? AND ts>=? ORDER BY ts", (nid, start)).fetchall()
        acc = {}
        for r in rows:
            name = r["name"]
            e = acc.get(name)
            if e is None:
                e = acc[name] = {"lat_sum": 0.0, "lat_n": 0, "total": 0, "lost": 0,
                                 "b": [None] * buckets}
            idx = int((r["ts"] - start) / size)
            idx = min(max(idx, 0), buckets - 1)
            b = e["b"][idx]
            if b is None:
                b = e["b"][idx] = {"ts": int(start + idx * size),
                                   "lat_sum": 0.0, "lat_n": 0, "total": 0, "lost": 0}
            val = r["rmin"] if r["rmin"] is not None else r["ravg"]
            ok = bool(r["ok"]) and val is not None
            b["total"] += 1
            e["total"] += 1
            if ok:
                b["lat_sum"] += val
                b["lat_n"] += 1
                e["lat_sum"] += val
                e["lat_n"] += 1
            else:
                b["lost"] += 1
                e["lost"] += 1

        out = {}
        for name, e in acc.items():
            bl = []
            for b in e["b"]:
                if not b or not b["total"]:
                    bl.append(None)
                    continue
                bl.append({
                    "ts": b["ts"],
                    "latency": round(b["lat_sum"] / b["lat_n"], 1) if b["lat_n"] else None,
                    "loss": round(100.0 * b["lost"] / b["total"], 1),
                })
            out[name] = {
                "name": name,
                "avg_latency": round(e["lat_sum"] / e["lat_n"], 1) if e["lat_n"] else None,
                "avg_loss": round(100.0 * e["lost"] / e["total"], 1) if e["total"] else None,
                "samples": e["total"],
                "buckets": bl,
            }
        return {"window": window, "bucket_seconds": int(size), "targets": out}

    def spark(self, nid, n=24):
        """最近 n 个采样点的上/下行速率（卡片点线走势用，省一次请求）"""
        with self.lock:
            rows = self.conn.execute(
                "SELECT rx_bps,tx_bps FROM samples WHERE node_id=? ORDER BY ts DESC LIMIT ?",
                (nid, n)).fetchall()
        rows = list(reversed(rows))
        return {"rx": [r["rx_bps"] or 0 for r in rows], "tx": [r["tx_bps"] or 0 for r in rows]}

    def series(self, nid, hours=24):
        """详情页曲线：<=24h 原始 30s；<=10d 分钟聚合；更久用小时聚合；最后统一降采样到 ≤720 点"""
        span = max(1, int(hours))
        now = int(time.time())
        since = now - span * 3600
        table = "samples" if span <= 24 else ("samples_min" if span <= 24 * 10 else "samples_hour")
        with self.lock:
            rows = self.conn.execute(
                f"SELECT ts,cpu,mem_used,mem_total,disk_used,disk_total,load1,rx_bps,tx_bps,tcp,udp"
                f" FROM {table} WHERE node_id=? AND ts>=? ORDER BY ts", (nid, since)).fetchall()
            ctable = "checks" if span <= 24 else "checks_min"
            crows = self.conn.execute(
                f"SELECT ts,name,ok,loss,ravg,rmax FROM {ctable}"
                f" WHERE node_id=? AND ts>=? ORDER BY ts", (nid, since)).fetchall()
        points = [{"ts": r["ts"], "cpu": r["cpu"],
                   "mem": r["mem_used"] or 0, "mem_total": r["mem_total"] or 0,
                   "disk": r["disk_used"] or 0, "disk_total": r["disk_total"] or 0,
                   "load1": r["load1"], "rx": r["rx_bps"], "tx": r["tx_bps"],
                   "tcp": r["tcp"], "udp": r["udp"]} for r in rows]
        checks = {}
        for r in crows:
            checks.setdefault(r["name"], []).append(
                {"ts": r["ts"], "ok": r["ok"], "loss": r["loss"], "avg": r["ravg"], "max": r["rmax"]})
        points = downsample(points, MAX_SERIES_POINTS,
                            ("cpu", "mem", "mem_total", "disk", "disk_total", "load1", "rx", "tx", "tcp", "udp"))
        for name in list(checks):
            checks[name] = downsample(checks[name], MAX_SERIES_POINTS, ("avg", "max", "loss"))
        return {"hours": span, "points": points, "checks": checks}

    # -- 维护 ---------------------------------------------------------------
    def rollup_and_prune(self):
        now = int(time.time())
        with self.lock:
            # 分钟聚合：按 60s 桶取平均（幂等，可反复跑）
            self.conn.execute(
                "INSERT OR REPLACE INTO samples_min(node_id,ts,cpu,mem_used,mem_total,disk_used,"
                "disk_total,load1,rx_bps,tx_bps,tcp,udp)"
                " SELECT node_id,(ts/60)*60,AVG(cpu),AVG(mem_used),MAX(mem_total),AVG(disk_used),"
                " MAX(disk_total),AVG(load1),AVG(rx_bps),AVG(tx_bps),AVG(tcp),AVG(udp)"
                " FROM samples WHERE ts>=? GROUP BY node_id,(ts/60)*60", (now - 2 * 86400,))
            self.conn.execute(
                "INSERT OR REPLACE INTO samples_hour(node_id,ts,cpu,mem_used,mem_total,disk_used,"
                "disk_total,load1,rx_bps,tx_bps,tcp,udp)"
                " SELECT node_id,(ts/3600)*3600,AVG(cpu),AVG(mem_used),MAX(mem_total),AVG(disk_used),"
                " MAX(disk_total),AVG(load1),AVG(rx_bps),AVG(tx_bps),AVG(tcp),AVG(udp)"
                " FROM samples_min WHERE ts>=? GROUP BY node_id,(ts/3600)*3600", (now - 40 * 86400,))
            self.conn.execute(
                "INSERT OR REPLACE INTO checks_min(node_id,ts,name,ok,loss,ravg,rmax)"
                " SELECT node_id,(ts/60)*60,name,MAX(ok),MAX(loss),AVG(ravg),MAX(rmax)"
                " FROM checks WHERE ts>=? GROUP BY node_id,(ts/60)*60,name", (now - 2 * 86400,))
            self.conn.execute("DELETE FROM samples WHERE ts<?", (now - RAW_KEEP_DAYS * 86400,))
            self.conn.execute("DELETE FROM checks WHERE ts<?", (now - RAW_KEEP_DAYS * 86400,))
            self.conn.execute("DELETE FROM samples_min WHERE ts<?", (now - MIN_KEEP_DAYS * 86400,))
            self.conn.execute("DELETE FROM checks_min WHERE ts<?", (now - MIN_KEEP_DAYS * 86400,))
            self.conn.execute("DELETE FROM samples_hour WHERE ts<?", (now - HOUR_KEEP_DAYS * 86400,))
            self.conn.commit()

    def db_size(self):
        try:
            return os.path.getsize(self.path)
        except OSError:
            return 0


# --------------------------------------------------------------------------- 工具
THREE_WINDOW = 3600        # 三网展示窗口：最近 1 小时
THREE_BUCKETS = 20         # 20 格 → 每格 3 分钟（对齐 Komari Glassmorphism 主题）

COUNTRY_CACHE = {}
COUNTRY_DONE = set()


# 英国两种写法都存在（ISO 是 GB，口语/分组常用 UK）。展示层统一用 UK：
# 旗帜仍按 GB 算（🇺🇰 不是合法旗帜），所以归一化放在「存储」这一层，界面只认 UK。
CC_CANON = {"GB": "UK", "EL": "GR"}


def norm_country(code: str) -> str:
    c = (code or "").strip().upper()
    if not c:
        return ""
    return CC_CANON.get(c, c[:2])


def lookup_country(ip: str):
    """按 IP 查国家代码（只在新节点首次上报时查一次，失败静默）。

    内网/回环来源（agent 与中心同机、或同内网）拿不到真实出口 IP —— 这时查「本机自己的归属地」，
    对这两类场景正好是对的；真正的公网来源照常用它的 IP 查。

    源顺序：ipinfo.io 优先（对机房 IP 更准），ip-api 兜底。
    ⚠ 实测 ip-api 按 ASN 注册地判，会把「ASN 注册在香港、机器在英国」的机房判成 HK。
    """
    self_lookup = not ip or is_private_ip(ip)
    if not self_lookup and ip in COUNTRY_CACHE:
        return COUNTRY_CACHE[ip]
    if self_lookup:
        urls = ("https://ipinfo.io/json", "http://ip-api.com/json/?fields=countryCode")
    else:
        urls = (f"https://ipinfo.io/{ip}/json",
                f"http://ip-api.com/json/{ip}?fields=countryCode")
    for url in urls:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": f"{APP_NAME}/{VERSION}"})
            with urllib.request.urlopen(req, timeout=5) as r:
                body = r.read().decode("utf-8", "replace").strip()
            code = ""
            if body.startswith("{"):
                obj = json.loads(body)
                code = (obj.get("country") or obj.get("countryCode") or "").upper()
            else:
                code = body[:2].upper()
            if len(code) == 2 and code.isalpha():
                code = norm_country(code)
                if not self_lookup:
                    COUNTRY_CACHE[ip] = code
                return code
        except Exception:
            continue
    return ""


def is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return True


def public_summary(store: Store):
    """公开页数据：不含 IP、不含 token、不含内网信息。"""
    out = []
    now = int(time.time())
    for n in store.nodes():
        if not n.get("enabled"):
            continue
        s, checks = store.latest(n["id"])
        online = bool(n.get("last_seen")) and (now - int(n["last_seen"]) < OFFLINE_AFTER)
        rx, tx = store.totals(n["id"])
        out.append({
            "id": n["id"], "alias": n["alias"],
            "group": n.get("grp", ""),
            "groups": parse_groups(n.get("groups"), n.get("grp", "")),
            "tags": parse_tags(n.get("tags")),
            "os_id": n.get("os_id", ""), "os_name": n.get("os_name", ""),
            "kernel": n.get("kernel", ""),
            "country": n.get("country", ""),
            "online": online,
            "last_seen": n.get("last_seen", 0),
            "uptime": (s or {}).get("uptime") or 0,
            "agent_ver": n.get("agent_ver", ""),
            "expires_at": n.get("expires_at", ""),
            "quota_bytes": n.get("quota_bytes", 0),
            "used_bytes": rx + tx,
            "rx_total": rx, "tx_total": tx,
            "spark": store.spark(n["id"], 24),
            "three": store.three(n["id"]),        # 1 小时 / 20 格（每格 3 分钟），Komari 主题口径
            "sample": s, "checks": checks,
        })
    return {"version": VERSION, "now": now, "offline_after": OFFLINE_AFTER, "nodes": out}


# --------------------------------------------------------------------------- HTTP
class Handler(BaseHTTPRequestHandler):
    server_version = f"{APP_NAME}/{VERSION}"
    protocol_version = "HTTP/1.1"

    # -- 基础设施 -----------------------------------------------------------
    @property
    def store(self) -> Store:
        return self.server.store

    def log_message(self, fmt, *args):
        if os.environ.get("FWPROBE_DEBUG"):
            sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def _send(self, code, obj=None, ctype="application/json; charset=utf-8", raw=None, headers=None):
        body = raw if raw is not None else json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _json_body(self):
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = 0
        if n <= 0 or n > MAX_BODY:
            return None
        raw = self.rfile.read(n)
        if (self.headers.get("Content-Encoding") or "").lower() == "gzip":
            try:
                raw = gzip.decompress(raw)
            except Exception:
                return None
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return None

    def _bearer(self):
        h = self.headers.get("Authorization") or ""
        return h[7:].strip() if h.lower().startswith("bearer ") else ""

    def _admin_ok(self):
        """两种凭证都收：Authorization: Bearer <admin_token>，或登录后的会话 Cookie（后台页面用后者）"""
        tok = self.server.config.get("admin_token") or ""
        if not tok:
            return False
        if secrets.compare_digest(self._bearer(), tok):
            return True
        return read_session(self.headers.get("Cookie") or "", tok) > 0

    def _csrf_ok(self):
        """后台写操作必须带自定义头：跨站表单发不出这种请求（Cookie 已经是 SameSite=Strict，双保险）"""
        return (self.headers.get("X-IPROBE") or "").strip() == "1"

    def _peer_ip(self):
        """真实来源 IP：经 nginx 反代时 peer 是 127.0.0.1，必须用 X-Real-IP / X-Forwarded-For，
        否则所有节点都被当成「中心自己」——归属地/旗标会全部错成中心所在国家。
        只在本机回环/内网来源时才信任这些头（端口只监听 127.0.0.1，外部伪造不到）。"""
        ip = self.client_address[0]
        if is_private_ip(ip):
            for h in ("X-Real-IP", "X-Forwarded-For"):
                v = (self.headers.get(h) or "").strip()
                if not v:
                    continue
                cand = v.split(",")[0].strip()
                if cand and not is_private_ip(cand):
                    return cand
        return ip

    # -- 路由 ---------------------------------------------------------------
    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if path == "/healthz":
            nodes = self.store.nodes()
            return self._send(200, {"ok": True, "version": VERSION, "nodes": len(nodes),
                                    "db_bytes": self.store.db_size()})
        if path in ("/", "/index.html"):
            return self._serve_static("index.html", "text/html; charset=utf-8")
        if path in ("/admin", "/admin/"):
            return self._serve_static("admin.html", "text/html; charset=utf-8")
        if path == "/api/admin/me":
            return self._send(200 if self._admin_ok() else 401, {"ok": self._admin_ok()})
        if path == "/api/admin/audit":
            if not self._admin_ok():
                return self._send(401, {"error": "未授权"})
            return self._send(200, {"items": self.store.audit_list(200)})
        if path == "/api/admin/groups":
            if not self._admin_ok():
                return self._send(401, {"error": "未授权"})
            tally = {}
            for n in self.store.nodes():
                for g in parse_groups(n.get("groups"), n.get("grp") or ""):
                    tally[g] = tally.get(g, 0) + 1
            return self._send(200, {"groups": [{"name": k, "count": v}
                                               for k, v in sorted(tally.items())]})
        if path.startswith("/static/"):
            name = os.path.basename(path)
            ctype = "application/javascript" if name.endswith(".js") else \
                "text/css" if name.endswith(".css") else "application/octet-stream"
            return self._serve_static(name, ctype)
        if path == "/api/public/summary":
            return self._send(200, public_summary(self.store))
        if path == "/api/public/series":
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            nid = (q.get("node") or [""])[0]
            if not self.store.node(nid):
                return self._send(404, {"error": "节点不存在"})
            try:
                hours = int((q.get("hours") or ["24"])[0])
            except ValueError:
                hours = 24
            return self._send(200, self.store.series(nid, hours))
        if path == "/api/provision/nodes":            # 外部面板：看自己建的节点（对账用）
            return self._provision_nodes()
        if path == "/api/nodes":
            if not self._admin_ok():
                return self._send(401, {"error": "未授权"})
            now = int(time.time())
            nodes = []
            for n in self.store.nodes():
                n = dict(n)
                n.pop("token_hash", None)
                n["tags"] = parse_tags(n.get("tags"))
                n["groups_list"] = parse_groups(n.get("groups"), n.get("grp") or "")
                n["can_self_upgrade"] = _ver_tuple(n.get("agent_ver")) >= UPGRADE_MIN_VER
                seen = int(n.get("last_seen") or 0)
                n["online"] = bool(seen) and (now - seen < OFFLINE_AFTER)
                rx, tx = self.store.totals(n["id"])
                n["used_bytes"] = rx + tx
                nodes.append(n)
            return self._send(200, {"nodes": nodes})
        if path == "/install-agent.sh":
            return self._serve_script("install-agent.sh")
        if path == "/agent.py":
            return self._serve_script("agent.py")
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        if path == "/api/admin/login":
            ip = self._peer_ip()
            ok, wait = login_allowed(ip)
            if not ok:
                return self._send(429, {"error": f"尝试过于频繁，请 {wait // 60 + 1} 分钟后再试"})
            data = self._json_body() or {}
            cfg = self.server.config
            tok = cfg.get("admin_token") or ""
            given = str(data.get("password") or data.get("token") or "").strip()
            pw_hash = cfg.get("admin_password") or ""
            ok_pw = bool(pw_hash) and verify_password(given, pw_hash)
            ok_tok = bool(tok) and bool(given) and secrets.compare_digest(given, tok)
            if not (ok_pw or ok_tok):
                note_login_fail(ip)
                self.store.audit("login_fail", "", "", ip)
                return self._send(401, {"error": "密码或 token 不正确"})
            clear_login_fail(ip)
            remember = bool(data.get("remember"))
            value, exp = make_session(tok, SESSION_TTL_LONG if remember else SESSION_TTL)
            self.store.audit("login", "", "", ip)
            cookie = (f"{SESSION_COOKIE}={value}; Path=/; Max-Age={exp - int(time.time())}; "
                      "HttpOnly; SameSite=Strict; Secure")
            return self._send(200, {"ok": True}, headers={"Set-Cookie": cookie})
        if path == "/api/admin/logout":
            cookie = f"{SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict; Secure"
            return self._send(200, {"ok": True}, headers={"Set-Cookie": cookie})
        if path == "/api/admin/passwd":
            if not self._admin_ok():
                return self._send(401, {"error": "未授权"})
            if not self._csrf_ok():
                return self._send(403, {"error": "缺少 X-IPROBE 头"})
            data = self._json_body() or {}
            old_pw = str(data.get("old") or "").strip()
            new_pw = str(data.get("new") or "")
            cfg = self.server.config
            tok = cfg.get("admin_token") or ""
            pw_hash = cfg.get("admin_password") or ""
            ok_old = (bool(pw_hash) and verify_password(old_pw, pw_hash)) or \
                     (bool(tok) and bool(old_pw) and secrets.compare_digest(old_pw, tok))
            if not ok_old:
                return self._send(403, {"error": "当前密码 / token 不正确"})
            if new_pw and len(new_pw) < 8:
                return self._send(400, {"error": "新密码至少 8 位"})
            cfg["admin_password"] = hash_password(new_pw) if new_pw else ""
            try:
                save_config(cfg)
            except OSError as exc:
                return self._send(500, {"error": f"写配置失败：{exc}"})
            self.store.audit("passwd_change", "", "已设置" if new_pw else "已清除", self._peer_ip())
            return self._send(200, {"ok": True})
        if path == "/api/admin/upgrade":             # 一键升级（可传 ids 或 all）
            if not self._admin_ok():
                return self._send(401, {"error": "未授权"})
            if not self._csrf_ok():
                return self._send(403, {"error": "缺少 X-IPROBE 头"})
            meta_ver, _ = agent_file_meta()
            if not meta_ver:
                return self._send(500, {"error": "中心缺少 agent.py，无法升级"})
            data = self._json_body() or {}
            ids = data.get("ids")
            targets = self.store.nodes() if data.get("all") else \
                [n for n in self.store.nodes() if n["id"] in set(ids or [])]
            done = []
            for n in targets:
                if str(n.get("agent_ver") or "") == meta_ver:
                    continue
                self.store.update_node(n["id"], target_ver=meta_ver)
                done.append(n["alias"] or n["id"])
            self.store.audit("agent_upgrade_batch", f"{len(done)} 台", f"→ {meta_ver}", self._peer_ip())
            return self._send(200, {"ok": True, "target": meta_ver, "queued": done})
        if path == "/api/admin/meta":
            if not self._admin_ok():
                return self._send(401, {"error": "未授权"})
            meta_ver, meta_sha = agent_file_meta()
            return self._send(200, {"version": VERSION, "agent_version": meta_ver,
                                    "agent_sha256": meta_sha})
        if path == "/api/admin/groups/rename":
            if not self._admin_ok():
                return self._send(401, {"error": "未授权"})
            if not self._csrf_ok():
                return self._send(403, {"error": "缺少 X-IPROBE 头"})
            data = self._json_body() or {}
            src = str(data.get("from") or "").strip()
            dst = str(data.get("to") or "").strip()
            if not src or not dst:
                return self._send(400, {"error": "from / to 必填"})
            n = 0
            for node in self.store.nodes():
                gl = parse_groups(node.get("groups"), node.get("grp") or "")
                if src not in gl:
                    continue
                gl = [dst if g == src else g for g in gl]
                self.store.update_node(node["id"], groups=gl)
                n += 1
            self.store.audit("group_rename", src, f"→ {dst}，影响 {n} 台", self._peer_ip())
            return self._send(200, {"ok": True, "nodes": n})
        if path == "/api/report":
            tok = self._bearer()
            if not tok:
                return self._send(401, {"error": "缺少 token"})
            node = self.store.node_by_token(tok)
            if not node or not node.get("enabled"):
                return self._send(403, {"error": "token 无效或节点已停用"})
            payload = self._json_body()
            if not isinstance(payload, dict):
                return self._send(400, {"error": "请求体不是合法 JSON"})
            ts = self.store.ingest(node, payload, self._peer_ip())
            if payload.get("agent_uninstall_ack"):
                alias = node.get("alias") or node["id"]
                self.store.delete_node(node["id"])
                self.store.audit("node_uninstalled", alias, "agent 已自卸载并确认", self._peer_ip())
                return self._send(200, {"ok": True, "bye": True})
            resp = {"ok": True, "ts": ts}
            if int(node.get("pending_uninstall") or 0):
                resp["uninstall"] = True
            agent_ver = str(payload.get("agent") or "").strip()
            tgt = str(node.get("target_ver") or "").strip()
            meta_ver, meta_sha = agent_file_meta()
            if tgt and agent_ver and agent_ver == tgt:
                self.store.update_node(node["id"], target_ver="")     # 升级完成，撤掉标记
            elif tgt and meta_ver and tgt == meta_ver and agent_ver != meta_ver:
                base = (self.server.config.get("base_url") or "").rstrip("/")
                resp["upgrade"] = {"version": meta_ver,
                                   "url": base + "/agent.py",
                                   "sha256": meta_sha}
            return self._send(200, resp)
        if path == "/api/provision/nodes":
            return self._provision_nodes()
        if path == "/api/provision/remove":           # 外部面板：卸载探针后删掉节点记录
            ptok = self.store.find_ptoken(self._bearer())
            if not ptok:
                return self._send(401, {"error": "供应令牌无效"})
            data = self._json_body() or {}
            alias = (data.get("alias") or "").strip()
            nid = (data.get("id") or "").strip()
            src = (data.get("source") or "").strip()
            mine = [n for n in self.store.nodes() if (n.get("note") or "").startswith("由供应令牌")]
            target = None
            if nid:
                target = next((n for n in mine if n["id"] == nid), None)
            if not target and src:
                target = next((n for n in mine if n.get("src") == src), None)
            if not target and alias:
                target = next((n for n in mine if n.get("alias") == alias), None)
            if not target and alias:
                # 兜底：面板节点名与中心别名常不一致（SG1-Oracle 对 新加坡SG1-Oracle），
                # 归一化后互相包含且唯一命中才删，避免误删
                def norm(x):
                    return "".join(ch for ch in (x or "").lower() if ch.isalnum())
                a = norm(alias)
                hits = [n for n in mine if a and (a in norm(n.get("alias")) or norm(n.get("alias")) in a)]
                if len(hits) == 1:
                    target = hits[0]
            if not target:
                return self._send(404, {"error": "找不到该节点"})
            self.store.delete_node(target["id"])
            self.store.audit("provision_remove", target.get("alias") or target["id"],
                             f"via {ptok.get('label') or ptok.get('id')}", self._peer_ip())
            return self._send(200, {"ok": True, "removed": target["id"]})
        if path == "/api/provision/node":             # 外部面板（fwpanel2）按需建探针节点
            ptok = self.store.find_ptoken(self._bearer())
            if not ptok:
                return self._send(401, {"error": "供应令牌无效"})
            data = self._json_body() or {}
            alias = (data.get("alias") or "").strip()[:40]
            if not alias:
                return self._send(400, {"error": "alias 必填"})
            groups = data.get("groups")
            if groups is None:
                g = data.get("group", "")
                groups = [g] if g else []
            tags = data.get("tags") or []
            nid, tok = self.store.add_node(alias, "", int(data.get("quota_bytes") or 0),
                                           data.get("expires_at", ""),
                                           f"由供应令牌「{ptok.get('label') or ptok.get('id')}」创建",
                                           groups=groups, tags=tags)
            src = (data.get("source") or "").strip()[:64]
            if src:
                self.store.update_node(nid, src=src)
            base = (self.server.config.get("base_url") or "").rstrip("/")
            self.store.audit("provision", alias, f"id={nid} via {ptok.get('label') or ptok.get('id')}",
                             self._peer_ip())
            return self._send(200, {"id": nid, "token": tok, "server": base,
                                    "command": f"curl -fsSL {base}/install-agent.sh | "
                                               f"sudo bash -s -- --token {tok} --server {base}"})
        if path == "/api/nodes":                      # 管理：新增节点
            if not self._admin_ok():
                return self._send(401, {"error": "未授权"})
            if not self._csrf_ok():
                return self._send(403, {"error": "缺少 X-IPROBE 头"})
            data = self._json_body() or {}
            alias = (data.get("alias") or "").strip()
            if not alias:
                return self._send(400, {"error": "alias 必填"})
            groups = data.get("groups")
            if groups is None:
                groups = data.get("group", "")
                groups = [groups] if groups else []
            nid, tok = self.store.add_node(alias, "", int(data.get("quota_bytes") or 0),
                                           data.get("expires_at", ""), data.get("note", ""),
                                           groups=groups, tags=data.get("tags") or [])
            self.store.audit("node_add", alias, f"id={nid}", self._peer_ip())
            return self._send(200, {"id": nid, "token": tok})
        if path.startswith("/api/nodes/"):            # 管理：改节点 / 轮换 token
            if not self._admin_ok():
                return self._send(401, {"error": "未授权"})
            if not self._csrf_ok():
                return self._send(403, {"error": "缺少 X-IPROBE 头"})
            rest = path[len("/api/nodes/"):].strip("/")
            if rest.endswith("/upgrade"):             # 下发升级指令（agent 下次上报时执行）
                nid = rest[:-len("/upgrade")].strip("/")
                node = self.store.node(nid)
                if not node:
                    return self._send(404, {"error": "节点不存在"})
                meta_ver, meta_sha = agent_file_meta()
                if not meta_ver:
                    return self._send(500, {"error": "中心缺少 agent.py，无法升级"})
                if str(node.get("agent_ver") or "") == meta_ver:
                    return self._send(400, {"error": f"已经是 {meta_ver}"})
                self.store.update_node(nid, target_ver=meta_ver)
                self.store.audit("agent_upgrade", node.get("alias") or nid,
                                 f"→ {meta_ver}", self._peer_ip())
                return self._send(200, {"ok": True, "target": meta_ver})
            if rest.endswith("/uninstall"):          # 让 agent 自卸载，确认后节点从中心移除
                nid = rest[:-len("/uninstall")].strip("/")
                node = self.store.node(nid)
                if not node:
                    return self._send(404, {"error": "节点不存在"})
                self.store.update_node(nid, pending_uninstall=1)
                self.store.audit("agent_uninstall", node.get("alias") or nid,
                                 "已下发卸载指令", self._peer_ip())
                return self._send(200, {"ok": True,
                                        "online": bool(node.get("last_seen") and
                                                       int(time.time()) - int(node["last_seen"]) < OFFLINE_AFTER)})
            if rest.endswith("/token"):               # 生成新 token，旧 token 立即失效
                nid = rest[:-len("/token")].strip("/")
                node = self.store.node(nid)
                if not node:
                    return self._send(404, {"error": "节点不存在"})
                tok = self.store.rotate_token(nid)
                self.store.audit("token_rotate", node.get("alias") or nid, f"id={nid}", self._peer_ip())
                return self._send(200, {"id": nid, "token": tok})
            nid = rest
            data = self._json_body() or {}
            if "country" in data:
                data["country"] = norm_country(data.get("country") or "")
            if not self.store.update_node(nid, **data):
                return self._send(404, {"error": "节点不存在或无有效字段"})
            node = self.store.node(nid) or {}
            changed = ",".join(k for k in data if k in
                               {"alias", "groups", "tags", "quota_bytes", "expires_at", "note", "enabled", "country"})
            self.store.audit("node_update", node.get("alias") or nid, changed, self._peer_ip())
            return self._send(200, {"ok": True})
        return self._send(404, {"error": "not found"})

    def do_DELETE(self):
        path = urllib.parse.urlparse(self.path).path
        if path.startswith("/api/nodes/"):
            if not self._admin_ok():
                return self._send(401, {"error": "未授权"})
            if not self._csrf_ok():
                return self._send(403, {"error": "缺少 X-IPROBE 头"})
            nid = path[len("/api/nodes/"):].strip("/")
            node = self.store.node(nid) or {}
            self.store.delete_node(nid)
            self.store.audit("node_delete", node.get("alias") or nid, f"id={nid}", self._peer_ip())
            return self._send(200, {"ok": True})
        return self._send(404, {"error": "not found"})

    # -- 静态 ---------------------------------------------------------------
    def _provision_nodes(self):
        """供应令牌视角：列出由供应令牌创建的节点（给面板对账用）"""
        ptok = self.store.find_ptoken(self._bearer())
        if not ptok:
            return self._send(401, {"error": "供应令牌无效"})
        now = int(time.time())
        out = []
        for n in self.store.nodes():
            if not (n.get("note") or "").startswith("由供应令牌"):
                continue
            groups = n.get("groups") or "[]"
            if isinstance(groups, str):
                try:
                    groups = json.loads(groups)
                except ValueError:
                    groups = []
            out.append({"id": n["id"], "alias": n.get("alias", ""), "groups": groups,
                        "agent_ver": n.get("agent_ver", ""),
                        "online": bool(n.get("last_seen") and
                                       now - int(n["last_seen"]) < OFFLINE_AFTER)})
        return self._send(200, {"ok": True, "nodes": out})

    def _serve_static(self, name, ctype):
        p = os.path.join(STATIC_DIR, name)
        try:
            with open(p, "rb") as fh:
                data = fh.read()
        except OSError:
            return self._send(404, {"error": "static not found"})
        return self._send(200, raw=data, ctype=ctype)

    def _serve_script(self, name):
        p = os.path.join(BASE_DIR, name)
        try:
            with open(p, "rb") as fh:
                data = fh.read()
        except OSError:
            return self._send(404, {"error": "script not found"})
        return self._send(200, raw=data, ctype="text/plain; charset=utf-8")


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr, handler, store, config):
        super().__init__(addr, handler)
        self.store = store
        self.config = config


def maintenance_loop(store, stop: threading.Event, every=300):
    while not stop.wait(every):
        try:
            store.rollup_and_prune()
        except Exception as exc:
            print(f"[warn] 维护任务失败: {exc}", file=sys.stderr)


# --------------------------------------------------------------------------- CLI
def cmd_serve(_args):
    cfg = load_config()
    store = Store(cfg["db"])
    stop = threading.Event()
    t = threading.Thread(target=maintenance_loop, args=(store, stop), daemon=True)
    t.start()
    srv = Server((cfg["bind"], cfg["port"]), Handler, store, cfg)
    print(f"{APP_NAME} {VERSION} 监听 {cfg['bind']}:{cfg['port']}  db={cfg['db']}", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        srv.server_close()


def _quota(s):
    if not s:
        return 0
    s = str(s).strip().upper().replace("B", "")
    mult = 1
    if s.endswith("K"):
        mult, s = 1024, s[:-1]
    elif s.endswith("M"):
        mult, s = 1024 ** 2, s[:-1]
    elif s.endswith("G"):
        mult, s = 1024 ** 3, s[:-1]
    elif s.endswith("T"):
        mult, s = 1024 ** 4, s[:-1]
    try:
        return int(float(s) * mult)
    except ValueError:
        return 0


def cmd_addnode(args):
    cfg = load_config()
    store = Store(cfg["db"])
    nid, tok = store.add_node(args.alias, args.group, _quota(args.quota),
                              args.expires or "", args.note or "")
    base = (args.server or cfg.get("base_url") or "https://status.example.com").rstrip("/")
    print(f"节点已创建\n  id    : {nid}\n  alias : {args.alias}")
    print(f"\n该节点的安装命令（token 只显示这一次，请立即保存）：\n"
          f"  curl -fsSL {base}/install-agent.sh | sudo bash -s -- --token {tok} --server {base}\n")
    return 0


def cmd_passwd(args):
    cfg = load_config()
    if args.clear:
        cfg["admin_password"] = ""
        save_config(cfg)
        print("已清除后台密码，只能用管理 token 登录。")
        return 0
    import getpass
    p1 = getpass.getpass("设置后台登录密码（至少 8 位）: ")
    if len(p1) < 8:
        print("密码太短", file=sys.stderr)
        return 2
    p2 = getpass.getpass("再输一次: ")
    if p1 != p2:
        print("两次不一致", file=sys.stderr)
        return 2
    cfg["admin_password"] = hash_password(p1)
    save_config(cfg)
    print("已设置后台登录密码（只存哈希，明文不落盘）。")
    return 0


def cmd_ptoken(args):
    store = Store(load_config()["db"])
    if args.action == "add":
        pid, tok = store.add_ptoken(args.value or "")
        print(f"已生成供应令牌 id={pid}（标签：{args.value or '无'}）")
        print(tok)
        print("只显示这一次，丢了就 rm 掉重新生成。", file=sys.stderr)
        return 0
    if args.action == "rm":
        ok = store.del_ptoken(args.value)
        print("已删除。" if ok else "没有这个 id。")
        return 0 if ok else 1
    rows = store.list_ptokens()
    if not rows:
        print("还没有供应令牌。生成：probe.py ptoken add -- 备注名")
        return 0
    for r in rows:
        last = time.strftime("%Y-%m-%d %H:%M", time.localtime(r["last_used"])) if r["last_used"] else "从未使用"
        print(f"{r['id']}  {r['label'] or '-'}  最后一次使用：{last}")
    return 0


def cmd_token(_args):
    cfg = load_config()
    tok = cfg.get("admin_token") or ""
    if not tok:
        print("配置里没有 admin_token，请重新安装或手动补一个。", file=sys.stderr)
        return 2
    print(tok)
    print("（这是管理 token，等同后台密码，别贴到公开的地方）", file=sys.stderr)
    return 0


def cmd_listnodes(_args):
    cfg = load_config()
    store = Store(cfg["db"])
    now = int(time.time())
    print(f"{'id':14s} {'alias':18s} {'group':10s} {'状态':6s} {'最近上报':14s} 备注")
    for n in store.nodes():
        online = bool(n.get("last_seen")) and (now - int(n["last_seen"]) < OFFLINE_AFTER)
        seen = time.strftime("%m-%d %H:%M:%S", time.localtime(n["last_seen"])) if n.get("last_seen") else "-"
        print(f"{n['id']:14s} {(n['alias'] or '')[:18]:18s} {(n.get('grp') or '')[:10]:10s} "
              f"{'在线' if online else '离线':6s} {seen:14s} {n.get('note') or ''}")
    return 0


def cmd_rmtoken(args):
    cfg = load_config()
    store = Store(cfg["db"])
    tok = store.rotate_token(args.node_id)
    if not tok:
        print("节点不存在", file=sys.stderr)
        return 1
    base = (cfg.get("base_url") or "https://status.example.com").rstrip("/")
    print(f"新 token（旧 agent 立即失效，重新安装或改配置后重启 agent）：\n"
          f"  curl -fsSL {base}/install-agent.sh | sudo bash -s -- --token {tok} --server {base}")
    return 0


def cmd_delnode(args):
    cfg = load_config()
    store = Store(cfg["db"])
    if not store.node(args.node_id):
        print("节点不存在", file=sys.stderr)
        return 1
    store.delete_node(args.node_id)
    print("已删除（含历史数据）")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog="probe.py", description=f"{APP_NAME} {VERSION}")
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("serve")

    p = sub.add_parser("addnode")
    p.add_argument("--alias", required=True)
    p.add_argument("--group", default="")
    p.add_argument("--quota", default="", help="如 500G / 1T，留空表示不限量")
    p.add_argument("--expires", default="", help="到期日 YYYY-MM-DD")
    p.add_argument("--note", default="")
    p.add_argument("--server", default="", help="对外地址（默认取配置 base_url）")

    p = sub.add_parser("ptoken")
    p.add_argument("action", choices=["add", "list", "rm"], nargs="?", default="list")
    p.add_argument("value", nargs="?", default="", help="add 时是标签，rm 时是令牌 id")
    p = sub.add_parser("passwd"); p.add_argument("--clear", action="store_true",
                                                 help="清除后台密码，只保留 token 登录")
    sub.add_parser("token")
    sub.add_parser("listnodes")
    p = sub.add_parser("rmtoken"); p.add_argument("node_id")
    p = sub.add_parser("delnode"); p.add_argument("node_id")

    args = ap.parse_args(argv)
    fn = {"serve": cmd_serve, "addnode": cmd_addnode, "listnodes": cmd_listnodes,
          "rmtoken": cmd_rmtoken, "delnode": cmd_delnode,
          "passwd": cmd_passwd, "token": cmd_token, "ptoken": cmd_ptoken}.get(args.cmd)
    if not fn:
        ap.print_help()
        return 2
    return fn(args) or 0


if __name__ == "__main__":
    sys.exit(main())
