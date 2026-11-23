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
import calendar
import datetime
import gzip
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import sqlite3
import sys
import threading
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

VERSION = "0.5.38"
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
    quota_bytes INTEGER DEFAULT 0,      -- 0 = 不限量（每个周期的额度）
    quota_mode  TEXT DEFAULT '',        -- day|month|year = 配额按周期统计，空 = 只累计不切周期
    quota_start TEXT DEFAULT '',        -- 周期起始日 YYYY-MM-DD（如 2026-11-11 + month → 每月 11 日 00:00 重置）
    expires_at  TEXT DEFAULT '',        -- YYYY-MM-DD，空 = 未填（不滚动时用这个死日期）
    renew_mode  TEXT DEFAULT '',        -- day|month|year = 到期日自动往后滚，空 = 不滚
    renew_start TEXT DEFAULT '',        -- 首次到期日 YYYY-MM-DD（滚动的起点）
    cyc_start   INTEGER DEFAULT 0,      -- 当前周期起点 ts
    cyc_rx      INTEGER DEFAULT 0,      -- 本周期出站字节
    cyc_tx      INTEGER DEFAULT 0,      -- 本周期入站字节
    last_rx_total INTEGER DEFAULT -1,   -- agent 上次上报的累计计数器（识别重启归零）
    last_tx_total INTEGER DEFAULT -1,
    agent_ver   TEXT DEFAULT '',
    agent_uid   INTEGER DEFAULT -1,     -- agent 进程的 uid：0=root，其它=低权限模式（-1 未知/老版本）
    target_ver  TEXT DEFAULT '',      -- 升级目标版本，agent 升到后清空
    pending_uninstall INTEGER DEFAULT 0,  -- 中心点了「卸载探针」，等 agent 下次上报执行
    src         TEXT DEFAULT '',      -- 外部面板的节点 id（面板卸载时用它精确匹配）
    sort_order  INTEGER DEFAULT 0,    -- 展示页卡片顺序（后台拖动调整，小在前）
    note        TEXT DEFAULT '',
    enabled     INTEGER DEFAULT 1,
    created     INTEGER DEFAULT 0,
    last_seen   INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS targets (          -- 三网探测目标（中心统一管理，下发到 agent）
    id         TEXT PRIMARY KEY,
    op         TEXT DEFAULT '',    -- 运营商：电信 / 联通 / 移动 / 广电…
    region     TEXT DEFAULT '',    -- 地区：上海 / 香港 / 洛杉矶…
    name       TEXT NOT NULL,      -- 展示名 = op·region（同时是历史数据的分组键）
    host       TEXT NOT NULL,
    port       INTEGER DEFAULT 80,
    proto      TEXT DEFAULT 'tcp', -- tcp | icmp
    family     TEXT DEFAULT 'auto',-- auto | 4 | 6
    enabled    INTEGER DEFAULT 1,
    sort_order INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS aliases (          -- 目标改过的旧名字 → 现在的名字（历史数据归一用）
    old  TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    ts   INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS traffic_hist (   -- 每台机器已结束的配额周期用量（月/年周期也要能看历史）
    node_id  TEXT NOT NULL,
    start_ts INTEGER NOT NULL,
    end_ts   INTEGER NOT NULL,
    rx       INTEGER DEFAULT 0,
    tx       INTEGER DEFAULT 0,
    PRIMARY KEY (node_id, start_ts)
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
def read_config_file():
    """只读配置文件里实际存在的键（热加载用，避免默认值把内存里的值冲掉）。"""
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as fh:
            return json.load(fh) or {}
    except FileNotFoundError:
        return {}
    except Exception as exc:                      # 配置坏了不能让服务起不来
        print(f"[warn] 读取配置失败（用默认值）: {exc}", file=sys.stderr)
        return {}


def load_config():
    cfg = {"port": DEFAULT_PORT, "bind": DEFAULT_BIND,
           "db": "/var/lib/fwprobe/probe.db", "base_url": "", "admin_token": ""}
    cfg.update(read_config_file())
    cfg["port"] = int(os.environ.get("FWPROBE_PORT", cfg.get("port") or DEFAULT_PORT))
    cfg["bind"] = os.environ.get("FWPROBE_BIND", cfg.get("bind") or DEFAULT_BIND)
    cfg["db"] = os.environ.get("FWPROBE_DB", cfg.get("db"))
    cfg["admin_token"] = os.environ.get("FWPROBE_ADMIN_TOKEN", cfg.get("admin_token") or "")
    return cfg


def _cfg_mtime():
    try:
        return os.path.getmtime(CONFIG_PATH)
    except OSError:
        return 0


# --------------------------------------------------------------------------- 三网目标
# 默认还是上海三网（v4 启用，v6 留着但关闭）。op/region 分开存，展示名拼成「电信·上海」。
DEFAULT_TARGETS = [
    {"id": "ct4", "op": "电信", "region": "上海", "host": "sh-ct-v4.ip.zstaticcdn.com",
     "port": 80, "proto": "tcp", "family": "auto", "enabled": 1},
    {"id": "cu4", "op": "联通", "region": "上海", "host": "sh-cu-v4.ip.zstaticcdn.com",
     "port": 80, "proto": "tcp", "family": "auto", "enabled": 1},
    {"id": "cm4", "op": "移动", "region": "上海", "host": "sh-cm-v4.ip.zstaticcdn.com",
     "port": 80, "proto": "tcp", "family": "auto", "enabled": 1},
    {"id": "ct6", "op": "电信", "region": "上海v6", "host": "sh-ct-v6.ip.zstaticcdn.com",
     "port": 80, "proto": "tcp", "family": "6", "enabled": 0},
    {"id": "cu6", "op": "联通", "region": "上海v6", "host": "sh-cu-v6.ip.zstaticcdn.com",
     "port": 80, "proto": "tcp", "family": "6", "enabled": 0},
    {"id": "cm6", "op": "移动", "region": "上海v6", "host": "sh-cm-v6.ip.zstaticcdn.com",
     "port": 80, "proto": "tcp", "family": "6", "enabled": 0},
]
TARGET_MAX = 6


def target_name(op, region):
    op, region = (op or "").strip(), (region or "").strip()
    return f"{op}·{region}" if (op and region) else (op or region)


def guess_target_alias(name, targets):
    """旧名字 → 现在的目标名。只认老默认格式（地区+运营商 / 运营商+地区，含 v6 后缀），
    避免把用户自己起的名字误并。"""
    n = str(name or "").strip()
    if not n:
        return None
    for t in targets or []:
        op = (t.get("op") or "").strip()
        region = (t.get("region") or "").strip()
        tn = t.get("name")
        if not op or not region or not tn:
            continue
        base = region[:-2] if region.endswith("v6") else region
        suf = "v6" if region.endswith("v6") else ""
        cands = {region + op, op + region, region + "·" + op, op + "·" + region,
                 base + op + suf, op + base + suf,
                 base + op + "IPv6", op + base + "IPv6", base + op + "(IPv6)"}
        if n in cands and n != tn:
            return tn
    return None


def clean_target(t, idx=0):
    """校验并归一一条三网目标；非法直接抛 ValueError（中文原因，后台原样显示）。"""
    if not isinstance(t, dict):
        raise ValueError("目标格式不对")
    host = str(t.get("host") or "").strip()
    if not host:
        raise ValueError("主机不能为空")
    if len(host) > 120 or any(ch.isspace() for ch in host):
        raise ValueError(f"主机不合法：{host}")
    proto = str(t.get("proto") or "tcp").strip().lower()
    if proto not in ("tcp", "icmp"):
        raise ValueError("协议只能是 tcp 或 icmp")
    family = str(t.get("family") or "auto").strip().lower()
    family = "4" if family in ("4", "ipv4") else "6" if family in ("6", "ipv6") else "auto"
    try:
        port = int(t.get("port") or 80)
    except (TypeError, ValueError):
        raise ValueError("端口必须是数字")
    if proto == "tcp" and not 1 <= port <= 65535:
        raise ValueError("端口要在 1–65535 之间")
    op = str(t.get("op") or "").strip()[:12]
    region = str(t.get("region") or "").strip()[:12]
    # 展示名一律由 运营商·地区 拼出来（改了地区卡片上就跟着变）；两者都空才退回 name / host
    name = (target_name(op, region) or str(t.get("name") or "").strip() or host)[:32]
    return {"id": (str(t.get("id") or "").strip()[:16] or secrets.token_hex(4)),
            "op": op, "region": region, "name": name, "host": host,
            "port": 80 if proto == "icmp" else port, "proto": proto, "family": family,
            "enabled": 1 if t.get("enabled", True) else 0,
            "sort_order": int(t.get("sort_order") if t.get("sort_order") is not None else idx * 10)}


def targets_signature(items):
    """目标列表指纹：中心与 agent 必须逐字一致（enabled 归一成 bool，否则 1/True 会算出不同指纹）。"""
    rows = [{"name": str(t.get("name") or ""), "host": str(t.get("host") or ""),
             "port": int(t.get("port") or 80), "proto": str(t.get("proto") or "tcp"),
             "family": str(t.get("family") or "auto"), "enabled": bool(t.get("enabled", True))}
            for t in (items or [])]
    raw = json.dumps(rows, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


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
        # RLock：ingest 持锁时还会调 account_traffic（也要锁），普通 Lock 会自锁死
        self.lock = threading.RLock()
        self.conn = sqlite3.connect(path, check_same_thread=False, timeout=15)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.executescript(SCHEMA)
        self.conn.commit()
        self._migrate()
        self.repair_aliases()

    # -- 节点 ---------------------------------------------------------------
    def add_node(self, alias, grp="", quota_bytes=0, expires_at="", note="", groups=None, tags=None,
                 quota_mode=None, quota_start="", renew_mode=None, renew_start=""):
        """新节点默认：配额按月统计（起点=今天）、到期按月自动滚动（起点=到期日或今天）。
        开关默认开启是用户明确要求：免费机每月自动往后滚，不用每月手改。"""
        nid = secrets.token_hex(6)
        tok = new_token()
        today = local_date().isoformat()
        quota_mode = "month" if quota_mode is None else str(quota_mode).strip().lower()
        renew_mode = "month" if renew_mode is None else str(renew_mode).strip().lower()
        quota_start = (quota_start or today)[:10]
        renew_start = (renew_start or expires_at or today)[:10]
        glist = [g.strip() for g in (groups if groups is not None else ([grp] if grp else [])) if g and g.strip()]
        with self.lock:
            # 新节点排到展示页最后（老数据 sort_order 为 0 时也能排到最前，不会插队打乱已设顺序）
            r = self.conn.execute("SELECT MAX(sort_order) mx FROM nodes").fetchone()
            order = int((r["mx"] if r and r["mx"] is not None else 0) or 0) + 10
            self.conn.execute(
                "INSERT INTO nodes(id,alias,grp,groups,tags,token_hash,quota_bytes,expires_at,note,"
                "sort_order,created,quota_mode,quota_start,renew_mode,renew_start)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (nid, alias, (glist[0] if glist else ""), dump_groups(glist), dump_tags(tags),
                 sha256_hex(tok), int(quota_bytes or 0), expires_at or "", note or "",
                 order, int(time.time()), quota_mode, quota_start, renew_mode, renew_start))
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
        # v0.5.24：配额周期 + 到期滚动
        for col, ddl in (("quota_mode", "TEXT DEFAULT ''"), ("quota_start", "TEXT DEFAULT ''"),
                         ("renew_mode", "TEXT DEFAULT ''"), ("renew_start", "TEXT DEFAULT ''"),
                         ("agent_uid", "INTEGER DEFAULT -1"),
                         ("cyc_start", "INTEGER DEFAULT 0"), ("cyc_rx", "INTEGER DEFAULT 0"),
                         ("cyc_tx", "INTEGER DEFAULT 0"),
                         ("last_rx_total", "INTEGER DEFAULT -1"),
                         ("last_tx_total", "INTEGER DEFAULT -1"),
                         ("last_acct_ts", "INTEGER DEFAULT 0")):
            if col not in cols:
                self.conn.execute(f"ALTER TABLE nodes ADD COLUMN {col} {ddl}")
        self.conn.commit()
        # 老节点：把最近保留样本的差值先记成本周期用量（否则卡片上会突然变成 0 B）
        for r in self.conn.execute("SELECT id FROM nodes WHERE cyc_start IS NULL OR cyc_start=0"):
            rx, tx = self.totals(r[0])
            self.conn.execute("UPDATE nodes SET cyc_start=?,cyc_rx=?,cyc_tx=? WHERE id=?",
                              (int(time.time()), int(rx), int(tx), r[0]))
        self.conn.commit()
        # 老节点先按"已用 0、计数器从当前值起步"初始化，第一次上报之后开始准确累计
        for r in self.conn.execute("SELECT id FROM nodes WHERE last_rx_total IS NULL OR last_rx_total < 0"):
            lr = self.conn.execute("SELECT rx_total,tx_total FROM samples WHERE node_id=?"
                                   " ORDER BY ts DESC LIMIT 1", (r[0],)).fetchone()
            if lr:
                self.conn.execute("UPDATE nodes SET last_rx_total=?,last_tx_total=? WHERE id=?",
                                  (int(lr[0] or 0), int(lr[1] or 0), r[0]))
            else:
                self.conn.execute("UPDATE nodes SET last_rx_total=0,last_tx_total=0 WHERE id=?", (r[0],))
        self.conn.commit()
        if "pending_uninstall" not in cols:
            self.conn.execute("ALTER TABLE nodes ADD COLUMN pending_uninstall INTEGER DEFAULT 0")
            self.conn.commit()
        if "src" not in cols:
            self.conn.execute("ALTER TABLE nodes ADD COLUMN src TEXT DEFAULT ''")
            self.conn.commit()
        # v0.5.18：记录地区是自动识别还是人工填的（自动值永不覆盖手工值，清空后回到自动）
        if "country_src" not in cols:
            self.conn.execute("ALTER TABLE nodes ADD COLUMN country_src TEXT DEFAULT ''")
            self.conn.commit()
        if "country_ip" not in cols:
            self.conn.execute("ALTER TABLE nodes ADD COLUMN country_ip TEXT DEFAULT ''")
            self.conn.commit()
        if "country_ts" not in cols:
            self.conn.execute("ALTER TABLE nodes ADD COLUMN country_ts INTEGER DEFAULT 0")
            self.conn.commit()
        if "sort_order" not in cols:
            self.conn.execute("ALTER TABLE nodes ADD COLUMN sort_order INTEGER DEFAULT 0")
            self.conn.commit()
            # 老库按创建时间回填，升级前后顺序看起来一致（不改变用户已有观感）
            for i, r in enumerate(self.conn.execute(
                    "SELECT id FROM nodes ORDER BY created").fetchall()):
                self.conn.execute("UPDATE nodes SET sort_order=? WHERE id=?", (i * 10, r["id"]))
            self.conn.commit()
        self.conn.execute("UPDATE nodes SET country='UK' WHERE UPPER(country)='GB'")
        self.conn.commit()
        self.seed_targets()

    def nodes(self):
        with self.lock:
            return [dict(r) for r in self.conn.execute(
                "SELECT * FROM nodes ORDER BY sort_order, created")]

    def reorder(self, ids):
        """按给定 id 顺序重排公开页卡片（sort_order = 下标×10，留空隙方便以后插队）。"""
        seen, clean = set(), []
        for nid in ids or []:
            nid = str(nid or "").strip()
            if nid and nid not in seen:
                seen.add(nid)
                clean.append(nid)
        if not clean:
            return 0
        n = 0
        with self.lock:
            for i, nid in enumerate(clean):
                cur = self.conn.execute("UPDATE nodes SET sort_order=? WHERE id=?", (i * 10, nid))
                n += 1 if cur.rowcount else 0
            self.conn.commit()
        return n

    def next_sort_order(self):
        with self.lock:
            r = self.conn.execute("SELECT MAX(sort_order) mx FROM nodes").fetchone()
        return int((r["mx"] if r and r["mx"] is not None else 0) or 0) + 10

    # -- 三网目标 -----------------------------------------------------------
    def targets(self):
        with self.lock:
            return [dict(r) for r in self.conn.execute(
                "SELECT * FROM targets ORDER BY sort_order, id")]

    def targets_ver(self):
        return targets_signature(self.targets())

    def seed_targets(self):
        """首次启动写入默认三网目标（已有数据则不动）。"""
        with self.lock:
            if self.conn.execute("SELECT 1 FROM targets LIMIT 1").fetchone():
                return 0
            for i, t in enumerate(DEFAULT_TARGETS):
                c = clean_target(dict(t), i)
                self.conn.execute(
                    "INSERT OR REPLACE INTO targets(id,op,region,name,host,port,proto,family,"
                    "enabled,sort_order) VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (c["id"], c["op"], c["region"], c["name"], c["host"], c["port"],
                     c["proto"], c["family"], c["enabled"], c["sort_order"]))
            self.conn.commit()
        return len(DEFAULT_TARGETS)

    def save_targets(self, items, rename_history=True):
        """整表替换目标；改名时可选把历史数据一起改名（否则那一路的 1 小时窗口会重新积累）。"""
        clean = [clean_target(t, i) for i, t in enumerate(items or [])]
        if not clean:
            raise ValueError("至少要保留一条目标")
        if len(clean) > TARGET_MAX:
            raise ValueError(f"最多 {TARGET_MAX} 条目标")
        renamed = []
        with self.lock:
            old = {r["id"]: r["name"] for r in self.conn.execute("SELECT id,name FROM targets")}
            self.conn.execute("DELETE FROM targets")
            for t in clean:
                self.conn.execute(
                    "INSERT INTO targets(id,op,region,name,host,port,proto,family,enabled,sort_order)"
                    " VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (t["id"], t["op"], t["region"], t["name"], t["host"], t["port"], t["proto"],
                     t["family"], t["enabled"], t["sort_order"]))
            if rename_history:
                for t in clean:
                    old_name = old.get(t["id"])
                    if old_name and old_name != t["name"]:
                        # 记别名 + 把两张检查表里的旧名字一起改掉（内部幂等）
                        self.record_alias(old_name, t["name"])
                        renamed.append([old_name, t["name"]])
            self.conn.commit()
        return self.targets_ver(), renamed

    # -- 目标改名的历史名归一 ------------------------------------------------
    def alias_map(self):
        with self.lock:
            return {r["old"]: r["name"] for r in self.conn.execute("SELECT old,name FROM aliases")}

    def record_alias(self, old, name):
        """记下「旧名 → 新名」：以后 agent 再用旧名上报也会落成新名，库里的老数据也并过去。"""
        if not old or not name or old == name:
            return False
        try:
            with self.lock:
                self.conn.execute("INSERT OR REPLACE INTO aliases(old,name,ts) VALUES(?,?,?)",
                                  (old, name, int(time.time())))
                self.conn.execute("UPDATE aliases SET name=? WHERE name=?", (name, old))  # 链式改名
                for table in ("checks", "checks_min"):
                    # ⚠ 不能直接 UPDATE：同一台机器同一秒可能新旧两个名字都有行，
                    #    主键是 (node_id,ts,name)，改名会撞唯一约束。先删重复行再改名。
                    self.conn.execute(
                        f"DELETE FROM {table} WHERE name=? AND EXISTS ("
                        f" SELECT 1 FROM {table} x WHERE x.node_id={table}.node_id"
                        f" AND x.ts={table}.ts AND x.name=?)", (old, name))
                    self.conn.execute(f"UPDATE {table} SET name=? WHERE name=?", (name, old))
                self.conn.commit()
        except Exception:
            # ⚠ 必须回滚：异常被上层 catch 掉后，这条连接上的半截事务会在下一次 commit
            #    时被一起提交（实测：checks 改完、checks_min 没改，名字只并了一半）
            try:
                self.conn.rollback()
            except Exception:
                pass
            raise
        return True

    def repair_aliases(self):
        """把库里还在用旧名字的检查数据归一（早期改名留下的孤儿名，会让详情页曲线出现两套）。

        规则保守：只有旧名等于「地区+运营商」「运营商+地区」（含 v6 后缀）这类老格式才并；
        已经记过别名但库里还留着旧名行的，也在这里补刀并掉（幂等）。"""
        try:
            with self.lock:
                names = {r["name"] for r in self.conn.execute("SELECT name FROM targets")}
                amap = {r["old"]: r["name"] for r in self.conn.execute("SELECT old,name FROM aliases")}
                orphans = set()
                for table in ("checks", "checks_min"):
                    for r in self.conn.execute(f"SELECT DISTINCT name FROM {table}"):
                        if r["name"] not in names:
                            orphans.add(r["name"])
            if not orphans:
                return []
            tg = self.targets()
            fixed = []
            for o in orphans:
                new = amap.get(o) or guess_target_alias(o, tg)
                if new and new != o and self.record_alias(o, new):
                    fixed.append([o, new])
            if fixed:
                print(f"[aliases] 历史名已归一：{fixed}", file=sys.stderr, flush=True)
            return fixed
        except Exception as exc:          # 清理失败不能拦住服务启动
            try:
                self.conn.rollback()
            except Exception:
                pass
            print(f"[aliases] 归一历史名失败：{exc}", file=sys.stderr, flush=True)
            return []

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
                   "quota_mode", "quota_start", "renew_mode", "renew_start",
                   "country", "country_src", "country_ip", "country_ts",
                   "tags", "target_ver", "pending_uninstall", "src"}
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

    def set_country(self, nid, code, src="auto", ip="", ts=0):
        """写地区 + 来源（auto/manual）+ 识别用的 IP + 时间，供后台展示「为什么是这个旗标」。"""
        with self.lock:
            cur = self.conn.execute(
                "UPDATE nodes SET country=?, country_src=?, country_ip=?, country_ts=? WHERE id=?",
                (norm_country(code), src or "", ip or "", int(ts or 0), nid))
            self.conn.commit()
            return cur.rowcount > 0

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
            amap = {r["old"]: r["name"] for r in self.conn.execute("SELECT old,name FROM aliases")}
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
                cname = (c.get("name") or "?")[:32]
                cname = amap.get(cname, cname)          # 旧名字自动落到新名字上（改名后不再出现两套曲线）
                self.conn.execute(
                    "INSERT OR REPLACE INTO checks(node_id,ts,name,proto,host,port,family,ok,loss,rmin,ravg,rmax)"
                    " VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                    (node["id"], cts, cname, c.get("proto"), c.get("host"),
                     c.get("port"), c.get("family"), 1 if c.get("ok") else 0,
                     c.get("loss"), c.get("min"), c.get("avg"), c.get("max")))
            net = payload.get("net") or {}
            if net.get("rx_total") is not None or net.get("tx_total") is not None:
                self.account_traffic(node["id"], net.get("rx_total"), net.get("tx_total"), ts)
            self.conn.execute(
                "UPDATE nodes SET last_seen=?, os_id=COALESCE(NULLIF(?,''),os_id),"
                " os_name=COALESCE(NULLIF(?,''),os_name), kernel=COALESCE(NULLIF(?,''),kernel),"
                " hostname=COALESCE(NULLIF(?,''),hostname), agent_ver=COALESCE(NULLIF(?,''),agent_ver),"
                " agent_uid=COALESCE(?,agent_uid),"
                " public_ip=? WHERE id=?",
                (now, payload.get("os_id") or "", payload.get("os_name") or "",
                 payload.get("kernel") or "", payload.get("hostname") or "",
                 payload.get("agent") or "", payload.get("uid"),
                 peer_ip or "", node["id"]))
            self.conn.commit()
        self._maybe_country(node["id"], peer_ip)
        return now

    def _maybe_country(self, nid, peer_ip):
        """节点还没有地区时自动识别；失败按 30s→1h 退避重试，不再一锤子永久放弃。

        手工填过的（country_src='manual'）不碰；后台清空地区后自动回到这里重新识别。
        """
        n = self.node(nid) or {}
        if not n:
            return
        if (n.get("country") or "").strip():
            reset_country_schedule(nid)
            return
        if not schedule_country(nid):
            return
        threading.Thread(target=self._country_work, args=(nid, peer_ip), daemon=True).start()

    def _country_work(self, nid, peer_ip):
        code, source, err = detect_country(peer_ip)
        if not code:
            log(f"归属地识别失败 node={nid} ip={peer_ip or '-'} 原因={err}")
            return
        try:
            self.set_country(nid, code, "auto", peer_ip or "", int(time.time()))
            reset_country_schedule(nid)
            log(f"归属地识别 node={nid} ip={peer_ip or '-'} -> {code}（{source}）")
        except Exception as exc:                      # 写库失败：把退避清掉，下次上报立刻再试
            reset_country_schedule(nid)
            log(f"归属地写库失败 node={nid}: {exc}")

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

    def account_traffic(self, nid, rx_total, tx_total, rep_ts=None):
        """把 agent 的累计计数器换算成「本周期用量」。

        本次读数无效（rx 与 tx 都是 0 = agent 读不到网卡）时整条不计，基准也不动。
        其余按 counter_delta() 三态判断：
        - 基准未知（-1/0/空）→ 本次不累加，只把当前读数立为基准；
        - 计数器变小（新值 > 0）→ 重启归零，按从 0 起算；
        - 其余 → 正常增量。
        跨周期时把上一段归档进 traffic_hist 再清零，长期不进后台也不会丢数。

        ⚠ 补发/乱序的旧上报不记账（rep_ts 早于已记账时刻就整条跳过）：agent 断线时会把
        payload 存 spool 目录，恢复后先补发旧包、再发新包 —— 旧包的计数器更小，
        旧逻辑把它当「重启归零」→ 整条计数器（几百 GB）被当成本次增量记进本周期
        （v0.5.37 前实测：温哥华 17GB 被记成 617GB，三包补发各加一份）。"""
        n = self.node(nid)
        if not n:
            return None
        try:
            rx_total = int(rx_total) if rx_total is not None else 0
            tx_total = int(tx_total) if tx_total is not None else 0
        except (TypeError, ValueError):
            return None
        if rx_total <= 0 and tx_total <= 0:        # 0/0 = 网卡没读到，无效读数
            return None
        rx_total = max(0, rx_total)
        tx_total = max(0, tx_total)
        now = int(time.time())
        try:
            rep_ts = int(rep_ts) if rep_ts else now
        except (TypeError, ValueError):
            rep_ts = now
        last_acct = int(n.get("last_acct_ts") or 0)
        if last_acct and rep_ts < last_acct:       # 补发/乱序的旧包：计数器只会更小
            log("跳过乱序上报（不记账）：%s 包内时间 %d < 已记账 %d"
                % (nid, rep_ts, last_acct))
            return None

        cstart, _cend = cycle_bounds((n.get("quota_mode") or "").strip(), n.get("quota_start"), now)
        cyc_start = int(n.get("cyc_start") or 0)
        cyc_rx = int(n.get("cyc_rx") or 0)
        cyc_tx = int(n.get("cyc_tx") or 0)
        last_rx = int(n.get("last_rx_total") if n.get("last_rx_total") is not None else -1)
        last_tx = int(n.get("last_tx_total") if n.get("last_tx_total") is not None else -1)
        archived = None
        if cstart and cyc_start and cstart > cyc_start:
            with self.lock:
                self.conn.execute("INSERT OR REPLACE INTO traffic_hist(node_id,start_ts,end_ts,rx,tx)"
                                  " VALUES(?,?,?,?,?)",
                                  (nid, cyc_start, min(cstart, now), cyc_rx, cyc_tx))
                self.conn.commit()
            archived = {"start": cyc_start, "end": min(cstart, now), "rx": cyc_rx, "tx": cyc_tx}
            cyc_rx = cyc_tx = 0
            cyc_start = cstart
        if not cyc_start:
            cyc_start = cstart or now
        d_rx = counter_delta(last_rx, rx_total)
        d_tx = counter_delta(last_tx, tx_total)
        if d_rx is None and d_tx is None:          # 两个方向都是无效读数：整条丢掉
            return None
        new_rx = rx_total if d_rx is not None else last_rx     # 无效方向保持原基准
        new_tx = tx_total if d_tx is not None else last_tx
        cyc_rx += max(0, d_rx or 0)
        cyc_tx += max(0, d_tx or 0)
        if d_rx is not None and last_rx > 0 and rx_total < last_rx:
            if rx_total <= last_rx // 2:
                log("流量计数器归零（多半是重启）：%s rx %d → %d" % (nid, last_rx, rx_total))
            else:
                log("计数器小幅回退（读数抖动，不入账）：%s rx %d → %d"
                    % (nid, last_rx, rx_total))
        with self.lock:
            self.conn.execute("UPDATE nodes SET cyc_start=?,cyc_rx=?,cyc_tx=?,"
                              "last_rx_total=?,last_tx_total=?,last_acct_ts=? WHERE id=?",
                              (cyc_start, cyc_rx, cyc_tx, new_rx, new_tx,
                               max(last_acct, rep_ts), nid))
            self.conn.commit()
        return archived

    def cycle_info(self, n):
        """本周期展示信息：起止、剩余天数、本期已用（rx+tx）"""
        mode = (n.get("quota_mode") or "").strip()
        if mode not in PERIOD_UNITS:
            return {}
        cstart, cend = cycle_bounds(mode, n.get("quota_start"))
        if not cstart:
            return {}
        used = int(n.get("cyc_rx") or 0) + int(n.get("cyc_tx") or 0)
        left = max(0, (local_date(cend) - local_date()).days)   # 按日历天数，别用 86400 折算
        d_end = local_date(cend)
        # 区间是 [起始日 00:00, 重置日 00:00)：界面上要写成「起始日 → 重置日的前一天」。
        # 直接用 reset_date 当区间末尾会读成「10 号 → 下月 10 号」，看着像多算一天
        # （实际 10 号起按月 = 10 号 00:00 ~ 下月 9 号 24:00，那一刻就是下月 10 号 00:00 重置）。
        return {"mode": mode, "unit": UNIT_CN.get(mode, mode), "used": used,
                "start": cstart, "end": cend,
                "start_date": local_date(cstart).isoformat(),
                "end_date": (d_end - datetime.timedelta(days=1)).isoformat(),  # 周期内最后一天（含）
                "reset_date": d_end.isoformat(),               # 这天 00:00 重置
                "reset_at": d_end.isoformat() + " 00:00",
                "days_left": left}

    def lifetime(self, nid):
        """这台机器自本功能上线以来的总收发（归档周期 + 当前周期）"""
        with self.lock:
            r = self.conn.execute("SELECT COALESCE(SUM(rx),0) rx, COALESCE(SUM(tx),0) tx"
                                  " FROM traffic_hist WHERE node_id=?", (nid,)).fetchone()
            cur = self.conn.execute("SELECT cyc_rx,cyc_tx FROM nodes WHERE id=?", (nid,)).fetchone()
        return int(r["rx"] or 0) + int((cur["cyc_rx"] if cur else 0) or 0), \
               int(r["tx"] or 0) + int((cur["cyc_tx"] if cur else 0) or 0)

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
            amap = {r["old"]: r["name"] for r in self.conn.execute("SELECT old,name FROM aliases")}
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
            nm = amap.get(r["name"], r["name"])          # 旧名字并到新名字（双重保险）
            checks.setdefault(nm, []).append(
                {"ts": r["ts"], "ok": r["ok"], "loss": r["loss"], "avg": r["ravg"], "max": r["rmax"]})
        for k, v in list(checks.items()):       # 旧名新名并到一起后同一时刻可能重复，去重
            if len(v) > 1:
                uniq = {p["ts"]: p for p in v}
                if len(uniq) != len(v):
                    checks[k] = [uniq[ts] for ts in sorted(uniq)]
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

COUNTRY_CACHE = {}          # 公网 IP → 国家码（process 内）
COUNTRY_RETRY = {}          # node_id → {"next": 下次可试时间, "tries": 已试次数}
COUNTRY_LOCK = threading.Lock()
COUNTRY_BACKOFF = (30, 60, 120, 300, 900, 1800, 3600)   # 失败退避，最长 1 小时


def log(msg):
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}", flush=True)


def schedule_country(nid, now=None):
    """登记一次自动识别尝试。返回 True = 现在可以试（并已排好下一次退避）。"""
    now = time.time() if now is None else now
    with COUNTRY_LOCK:
        st = COUNTRY_RETRY.get(nid) or {"next": 0, "tries": 0}
        if now < st["next"]:
            return False
        st["next"] = now + COUNTRY_BACKOFF[min(st["tries"], len(COUNTRY_BACKOFF) - 1)]
        st["tries"] = int(st["tries"]) + 1
        COUNTRY_RETRY[nid] = st
        return True


def reset_country_schedule(nid=None):
    with COUNTRY_LOCK:
        if nid is None:
            COUNTRY_RETRY.clear()
        else:
            COUNTRY_RETRY.pop(nid, None)


# 英国两种写法都存在（ISO 是 GB，口语/分组常用 UK）。展示层统一用 UK：
# 旗帜仍按 GB 算（🇺🇰 不是合法旗帜），所以归一化放在「存储」这一层，界面只认 UK。
CC_CANON = {"GB": "UK", "EL": "GR"}


def norm_country(code: str) -> str:
    """只保留合法的两位字母代码（GB→UK）；非法输入返回空串，由调用方决定报错还是留空。"""
    c = (code or "").strip().upper()
    if not re.fullmatch(r"[A-Z]{2}", c):
        return ""
    return CC_CANON.get(c, c)


# 归属地数据源（按顺序尝试）：ipinfo 对机房 IP 最准，ip-api 兜底，ipwho.is 再兜一层
COUNTRY_SOURCES = (
    ("ipinfo", "https://ipinfo.io{path}/json", "country"),
    ("ip-api", "http://ip-api.com/json{path}?fields=countryCode,status,message", "countryCode"),
    ("ipwho", "https://ipwho.is{path}", "country_code"),
)


def _country_code_from(body: str, key: str):
    """从各家返回里取两位国家码（JSON 或纯文本）。返回 (code, 失败原因)。"""
    if not body:
        return "", "空响应"
    if body.startswith("{"):
        try:
            obj = json.loads(body)
        except ValueError:
            return "", "响应不是合法 JSON"
        if obj.get("success") is False:
            return "", str(obj.get("message") or obj.get("reason") or "接口返回失败")[:40]
        code = str(obj.get(key) or obj.get("country") or obj.get("countryCode") or "").upper()
    else:
        code = body[:2].upper()
    if len(code) == 2 and code.isalpha():
        return norm_country(code), ""
    return "", "没有国家码"


def detect_country(ip: str):
    """查 IP 归属地，返回 (国家码, 命中的源, 失败原因)。

    内网/回环来源（agent 与中心同机、或同内网）拿不到真实出口 IP —— 这时查「本机自己的归属地」，
    对这两类场景正好是对的；真正的公网来源照常用它的 IP 查。
    源顺序：ipinfo.io → ip-api → ipwho.is（单个源不通不影响出结果）。
    """
    self_lookup = not ip or is_private_ip(ip)
    if not self_lookup and ip in COUNTRY_CACHE:
        return COUNTRY_CACHE[ip], "cache", ""
    errs = []
    for name, tpl, key in COUNTRY_SOURCES:
        url = tpl.format(path="" if self_lookup else "/" + ip)
        try:
            req = urllib.request.Request(url, headers={"User-Agent": f"{APP_NAME}/{VERSION}"})
            with urllib.request.urlopen(req, timeout=5) as r:
                body = r.read().decode("utf-8", "replace").strip()
            code, err = _country_code_from(body, key)
            if code:
                if not self_lookup:
                    COUNTRY_CACHE[ip] = code
                return code, name, ""
            errs.append(f"{name}:{err}")
        except Exception as exc:
            errs.append(f"{name}:{type(exc).__name__}")
    return "", "", "；".join(errs) or "没有可用数据源"


def lookup_country(ip: str):
    """兼容旧调用：只要国家码。"""
    return detect_country(ip)[0]


# --------------------------------------------------------------- 计费周期 / 到期滚动
# 周期按 CST 切日：服务器多半是 UTC，直接用本地时间会让"每月 11 日重置"变成 11 日早上 8 点
TZ_OFFSET_HOURS = 8
PERIOD_UNITS = ("day", "month", "year")
UNIT_CN = {"day": "每天", "month": "每月", "year": "每年"}


def _tz():
    return datetime.timezone(datetime.timedelta(hours=TZ_OFFSET_HOURS))


def local_date(ts=None):
    return datetime.datetime.fromtimestamp(int(ts if ts is not None else time.time()), _tz()).date()


def day_start_ts(d):
    return int(datetime.datetime(d.year, d.month, d.day, tzinfo=_tz()).timestamp())


def parse_date(s):
    s = str(s or "").strip()[:10]
    if not s:
        return None
    try:
        return datetime.date.fromisoformat(s)
    except ValueError:
        return None


def add_months(d, n):
    """加 n 个月，日按月末回退（1-31 加一月 → 2-28/29）"""
    m = d.month - 1 + n
    y, m = d.year + m // 12, m % 12 + 1
    return datetime.date(y, m, min(d.day, calendar.monthrange(y, m)[1]))


def add_period(d, unit, n=1):
    if unit == "day":
        return d + datetime.timedelta(days=n)
    if unit == "year":
        try:
            return d.replace(year=d.year + n)
        except ValueError:                 # 2-29 → 2-28
            return d.replace(year=d.year + n, day=28)
    return add_months(d, n)


def counter_delta(last, cur):
    """累计计数器 → 本次增量。三态：

    - cur <= 0                → None：本次读数无效（agent 读不到网卡会返回 0），不入账、基准不变
    - last 未知（None/<=0）   → 0：第一次上报，从当前值起步，本次不累加
                                （⚠ 0 是「未知」哨兵，绝不能拿来做 last，否则 cur-0 就是整条计数器）
    - cur >= last             → cur - last：正常增量
    - cur < last 且腰斩（<= last/2）→ cur：计数器变小 = 重启归零，按从 0 起算
    - cur < last 但只掉一点   → 0：读数抖动 / 乱序旧包，不能把整条计数器当增量

    ⚠ 最后这条是「腰斩才算重启」的判据：重启后计数器从 0 起，必然远小于 last；
    只回退几 MB/几百 MB 的是驱动计数器抖动（或补发的旧包），旧逻辑一律当重启、
    直接把 cur（=整条计数器，几百 GB）加进本周期 —— 实测一台 17GB 的机器被记成 617GB。
    """
    try:
        cur = int(cur)
    except (TypeError, ValueError):
        return None
    if cur <= 0:
        return None
    if last is None:
        return 0
    try:
        last = int(last)
    except (TypeError, ValueError):
        return 0
    if last <= 0:
        return 0
    if cur >= last:
        return cur - last
    if cur <= last // 2:            # 腰斩以上 = 真的重启归零
        return cur
    return 0                        # 小幅回退：不入账，基准会在调用处重设成 cur


def cycle_bounds(mode, start, now=None):
    """当前配额周期 [start_ts, end_ts)：起始日 + 按 day/month/year 递推，跨过多个周期也只给当前这段。
    mode 不是 day/month/year 时返回 (0, 0) = 不按周期。"""
    if mode not in PERIOD_UNITS:
        return 0, 0
    today = local_date(now)
    base = parse_date(start) or today
    if base > today:                        # 起始日在未来：第一个周期从那天开始
        return day_start_ts(base), day_start_ts(add_period(base, mode))
    cur, guard = base, 0
    while guard < 4000:
        nxt = add_period(cur, mode)
        if nxt > today:
            break
        cur, guard = nxt, guard + 1
    return day_start_ts(cur), day_start_ts(add_period(cur, mode))


def roll_forward(base, unit, today=None, after_today=False):
    """到期日自动滚动：从 base 按单位往后推到 ≥ 今天。
    after_today=True 时推到严格大于今天（到期日当天算已续到下一期，不会显示"今天到期"）。"""
    if unit not in PERIOD_UNITS:
        return parse_date(base)
    d = parse_date(base)
    if not d:
        return None
    today = today or local_date()
    guard = 0
    while guard < 4000 and (d < today or (after_today and d == today)):
        d, guard = add_period(d, unit), guard + 1
    return d


def expires_info(n):
    """对外展示的到期日：自动滚动时就给滚动后的那天 + 剩余天数"""
    base = (n.get("renew_start") or "").strip() or (n.get("expires_at") or "").strip()
    mode = (n.get("renew_mode") or "").strip()
    if mode in PERIOD_UNITS and base:
        eff = roll_forward(base, mode, after_today=True)
        if eff:
            return {"auto": True, "mode": mode, "base": base, "date": eff.isoformat(),
                    "days_left": (eff - local_date()).days}
    d = parse_date(base)
    if d:
        return {"auto": False, "mode": "", "base": base, "date": d.isoformat(),
                "days_left": (d - local_date()).days}
    return {"auto": False, "mode": "", "base": "", "date": "", "days_left": None}


def is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return True


def resolve_host(host, timeout=3.0):
    """解析主机名 → IP 列表（带硬超时：getaddrinfo 卡住会拖死后台请求）。"""
    box = {}

    def work():
        try:
            ips = []
            for _, _, _, _, sockaddr in socket.getaddrinfo(host, None):
                ip = sockaddr[0]
                if ip not in ips:
                    ips.append(ip)
            box["ips"] = ips
        except Exception as exc:
            box["err"] = type(exc).__name__

    t = threading.Thread(target=work, daemon=True)
    t.start()
    t.join(timeout)
    if "ips" in box:
        return box["ips"], ""
    return [], box.get("err") or "解析超时"


def geoip_city(ip, timeout=5):
    """城市级归属地（ip-api 中文优先，ipinfo 兜底）。CDN 多 IP 时只是个参考值，不保证是你要的那个城市。"""
    urls = (f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,city&lang=zh-CN",
            f"https://ipinfo.io/{ip}/json")
    for url in urls:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": f"{APP_NAME}/{VERSION}"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                obj = json.loads(r.read().decode("utf-8", "replace") or "{}")
            if obj.get("status") == "fail":
                continue
            city = (obj.get("city") or "").split(",")[0].strip()
            cc = norm_country(obj.get("countryCode") or obj.get("country") or "")
            if city or cc:
                return {"ip": ip, "city": city, "country": cc}
        except Exception:
            continue
    return {"ip": ip, "city": "", "country": ""}


def public_summary(store: Store):
    """公开页数据：不含 IP、不含 token、不含内网信息。"""
    out = []
    now = int(time.time())
    # 三网目标：给每一路补上运营商与排序（前端按顺序画、按运营商配色，改名后颜色不会乱）
    tlist = store.targets()
    opmap = {t["name"]: (t.get("op") or "", i) for i, t in enumerate(tlist)}
    for n in store.nodes():
        if not n.get("enabled"):
            continue
        s, checks = store.latest(n["id"])
        online = bool(n.get("last_seen")) and (now - int(n["last_seen"]) < OFFLINE_AFTER)
        rx, tx = store.lifetime(n["id"])
        cycle = store.cycle_info(n)
        exp = expires_info(n)
        three = store.three(n["id"])
        for tname, tdata in (three.get("targets") or {}).items():
            op, order = opmap.get(tname, ("", 99))
            tdata["op"] = op
            tdata["order"] = order
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
            "expires_at": exp.get("date") or n.get("expires_at", ""),
            "expires": exp,                          # auto/mode/days_left，前端据此标黄标红、写"每月自动续"
            "quota_bytes": n.get("quota_bytes", 0),
            "cycle": cycle,                          # 空字典 = 不按周期，used 就是累计
            "used_bytes": cycle.get("used") if cycle else (rx + tx),
            "rx_total": rx, "tx_total": tx,
            "spark": store.spark(n["id"], 24),
            "three": three,                        # 1 小时 / 20 格（每格 3 分钟），Komari 主题口径
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

    @staticmethod
    def _check_period_fields(data):
        """配额周期 / 到期续期字段的校验与归一（day|month|year，日期 YYYY-MM-DD）"""
        for k in ("quota_mode", "renew_mode"):
            if k in data:
                v = str(data.get(k) or "").strip().lower()
                if v and v not in PERIOD_UNITS:
                    return "周期只能选 day / month / year（或留空表示不按周期）"
                data[k] = v
        for k in ("quota_start", "renew_start"):
            if k in data:
                v = str(data.get(k) or "").strip()[:10]
                if v and not parse_date(v):
                    return "起始日期格式应为 YYYY-MM-DD"
                data[k] = "" if not v or v == "0000-00-00" else v
        return ""

    def _admin_ok(self):
        """两种凭证都收：Authorization: Bearer <admin_token>，或登录后的会话 Cookie（后台页面用后者）"""
        tok = self.server.cfg().get("admin_token") or ""
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
        if path == "/api/admin/targets":
            if not self._admin_ok():
                return self._send(401, {"error": "未授权"})
            return self._send(200, {"items": self.store.targets(), "ver": self.store.targets_ver()})
        if path == "/api/admin/meta":
            # ⚠ 前端 load() 是用 GET 拉的；只挂在 do_POST 上的话一律 404 → META.agent_version 为空
            #   → 后台永远不显示「全部升级」按钮（v0.5.5~v0.5.21 一直如此，2026-11-11 才被发现）
            if not self._admin_ok():
                return self._send(401, {"error": "未授权"})
            meta_ver, meta_sha = agent_file_meta()
            return self._send(200, {"version": VERSION, "agent_version": meta_ver,
                                    "agent_sha256": meta_sha})
        if path == "/api/admin/groups":
            if not self._admin_ok():
                return self._send(401, {"error": "未授权"})
            tally = {}
            for n in self.store.nodes():
                for g in parse_groups(n.get("groups"), n.get("grp") or ""):
                    tally[g] = tally.get(g, 0) + 1
            return self._send(200, {"groups": [{"name": k, "count": v}
                                               for k, v in sorted(tally.items())]})
        if path == "/favicon.ico":
            # 浏览器默认就会请求根路径的 /favicon.ico（不读 <link>），必须单独给路由
            return self._serve_static("favicon.ico", "image/x-icon")
        if path.startswith("/static/"):
            name = os.path.basename(path)
            ctype = "application/javascript" if name.endswith(".js") else \
                "text/css" if name.endswith(".css") else \
                "image/x-icon" if name.endswith(".ico") else \
                "image/png" if name.endswith(".png") else \
                "application/octet-stream"
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
                uid = n.get("agent_uid")
                n["low_priv"] = (uid is not None and int(uid) > 0)   # 专用用户跑 = 非 root
                seen = int(n.get("last_seen") or 0)
                n["online"] = bool(seen) and (now - seen < OFFLINE_AFTER)
                rx, tx = self.store.lifetime(n["id"])
                n["rx_total"], n["tx_total"] = rx, tx
                n["cycle"] = self.store.cycle_info(n)
                n["expires"] = expires_info(n)
                n["used_bytes"] = n["cycle"].get("used") if n["cycle"] else rx + tx
                n["expires_at"] = n["expires"].get("date") or n.get("expires_at", "")
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
            cfg = self.server.cfg()
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
            cfg = self.server.cfg()
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
        if path == "/api/admin/targets":              # 三网目标：保存并下发
            if not self._admin_ok():
                return self._send(401, {"error": "未授权"})
            if not self._csrf_ok():
                return self._send(403, {"error": "缺少 X-IPROBE 头"})
            data = self._json_body() or {}
            try:
                ver, renamed = self.store.save_targets(
                    data.get("items") or [], bool(data.get("rename_history", True)))
            except ValueError as exc:
                return self._send(400, {"error": str(exc)})
            self.store.audit("targets_update", "", f"{len(data.get('items') or [])} 条 → {ver}",
                             self._peer_ip())
            return self._send(200, {"ok": True, "ver": ver, "renamed": renamed})
        if path == "/api/admin/targets/geoip":        # 解析目标 → IP / 城市（给「地区」做初值）
            if not self._admin_ok():
                return self._send(401, {"error": "未授权"})
            if not self._csrf_ok():
                return self._send(403, {"error": "缺少 X-IPROBE 头"})
            data = self._json_body() or {}
            host = str(data.get("host") or "").strip()
            if not host:
                return self._send(400, {"error": "host 必填"})
            ips, err = resolve_host(host)
            if not ips:
                return self._send(400, {"error": f"解析失败：{err}"})
            geo = geoip_city(ips[0])
            return self._send(200, {"ok": True, "ips": ips[:5], "ip": geo["ip"],
                                    "city": geo["city"], "country": geo["country"]})
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
                base = (self.server.cfg().get("base_url") or "").rstrip("/")
                resp["upgrade"] = {"version": meta_ver,
                                   "url": base + "/agent.py",
                                   "sha256": meta_sha}
            # 三网目标下发：只有 0.5.11+ 的 agent 会在上报里带 targets_ver，老 agent 保持本地配置
            if "targets_ver" in payload:
                tver = self.store.targets_ver()
                if str(payload.get("targets_ver") or "") != tver:
                    tl = self.store.targets()
                    if tl:
                        resp["targets"] = {"ver": tver, "list": [
                            {k: t.get(k) for k in ("name", "host", "port", "proto", "family", "enabled")}
                            for t in tl]}
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
            base = (self.server.cfg().get("base_url") or "").rstrip("/")
            self.store.audit("provision", alias, f"id={nid} via {ptok.get('label') or ptok.get('id')}",
                             self._peer_ip())
            return self._send(200, {"id": nid, "token": tok, "server": base,
                                    "command": f"curl -fsSL {base}/install-agent.sh | "
                                               f"sudo bash -s -- --token {tok} --server {base} "
                                               f"--as-user fwprobe"})
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
            if rest == "order":                        # 展示页卡片顺序（后台拖动后保存）
                data = self._json_body() or {}
                ids = data.get("ids")
                if not isinstance(ids, list):
                    return self._send(400, {"error": "ids 必须是节点 id 数组"})
                n = self.store.reorder(ids)
                self.store.audit("node_order", "", f"重排 {n} 台", self._peer_ip())
                return self._send(200, {"ok": True, "count": n})
            if rest == "renew-batch":                  # 批量设到期续期（选中的节点一次搞定）
                payload = self._json_body() or {}
                ids = payload.get("ids")
                all_nodes = bool(payload.get("all"))
                data = {k: v for k, v in payload.items() if k not in ("ids", "all")}
                err = self._check_period_fields(data)
                if err:
                    return self._send(400, {"error": err})
                mode = (data.get("renew_mode") or "").strip()
                start = (data.get("renew_start") or "").strip()
                changed = 0
                for n in self.store.nodes():
                    if not all_nodes and ids and n["id"] not in set(ids):
                        continue
                    # 起点留空 = 用这台机器现在的到期日（没有就用今天），不用一台台填
                    base = start or (n.get("renew_start") or n.get("expires_at") or "").strip() \
                        or local_date().isoformat()
                    upd = {"renew_mode": mode, "renew_start": base}
                    if "quota_mode" in data:                     # 勾了「同时设置配额周期」
                        upd["quota_mode"] = (data.get("quota_mode") or "").strip()
                        upd["quota_start"] = (data.get("quota_start") or "").strip() \
                            or local_date().isoformat()
                    self.store.update_node(n["id"], **upd)
                    changed += 1
                self.store.audit("node_renew_batch", f"{changed} 台",
                                 f"{mode or '不自动'} 起点 {start or '各自当前到期日'}", self._peer_ip())
                return self._send(200, {"ok": True, "count": changed})
            if rest == "country-refresh-all":          # 所有还没有地区的节点立即重新识别
                updated, failed = [], []
                for n in self.store.nodes():
                    if (n.get("country") or "").strip():
                        continue
                    code, source, err = detect_country(n.get("public_ip") or "")
                    if code:
                        self.store.set_country(n["id"], code, "auto", n.get("public_ip") or "",
                                               int(time.time()))
                        reset_country_schedule(n["id"])
                        updated.append({"id": n["id"], "alias": n.get("alias"), "country": code})
                    else:
                        failed.append({"id": n["id"], "alias": n.get("alias"), "error": err})
                self.store.audit("country_refresh_all", "", f"成功 {len(updated)} / 失败 {len(failed)}",
                                 self._peer_ip())
                return self._send(200, {"ok": True, "updated": updated, "failed": failed})
            if rest.endswith("/country-refresh"):      # 单台重新识别（按已记录的来源 IP）
                nid = rest[:-len("/country-refresh")].strip("/")
                node = self.store.node(nid)
                if not node:
                    return self._send(404, {"error": "节点不存在"})
                ip = node.get("public_ip") or ""
                code, source, err = detect_country(ip)
                if not code:
                    return self._send(502, {"error": f"识别失败：{err or '没有可用数据源'}"})
                self.store.set_country(nid, code, "auto", ip, int(time.time()))
                reset_country_schedule(nid)
                self.store.audit("country_refresh", node.get("alias") or nid,
                                 f"{code}（{source}）", self._peer_ip())
                return self._send(200, {"ok": True, "country": code, "source": source})
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
            err = self._check_period_fields(data)
            if err:
                return self._send(400, {"error": err})
            if data.get("renew_mode") and not data.get("renew_start") and "renew_start" in data:
                data["renew_start"] = local_date().isoformat()   # 开了续期没给起点：从今天开始滚
            if "country" in data:
                raw = str(data.get("country") or "").strip().upper()
                if raw and not re.fullmatch(r"[A-Z]{2}", raw):
                    return self._send(400, {"error": "地区代码必须是两位字母，例如 JP / UK"})
                data["country"] = norm_country(raw)
                data["country_ip"] = ""
                data["country_ts"] = int(time.time()) if raw else 0
                data["country_src"] = "manual" if raw else ""
                reset_country_schedule(nid)      # 改成手动 / 清空回自动：两种都重置退避
            if not self.store.update_node(nid, **data):
                return self._send(404, {"error": "节点不存在或无有效字段"})
            node = self.store.node(nid) or {}
            changed = ",".join(k for k in data if k in
                               {"alias", "groups", "tags", "quota_bytes", "expires_at", "note",
                                "enabled", "country", "quota_mode", "quota_start",
                                "renew_mode", "renew_start"})
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
        self._cfg_mtime = _cfg_mtime()

    def cfg(self):
        """配置热加载：CLI 里 `probe.py passwd / token` 只改文件，服务不重启也得生效。

        ⚠ 早期只在启动时读一次 config.json → 改完密码登录仍报「密码不正确」，用户以为密码错了
        （实测坑：2026-11-11 CC1）。这里按 mtime 变化惰性重读，登录/token 校验前都会走一遍。
        """
        mt = _cfg_mtime()
        if mt and mt != self._cfg_mtime:
            try:
                fresh = read_config_file()
                self.config.update(fresh)
                self._cfg_mtime = mt
                log(f"配置已热加载：{CONFIG_PATH}")
            except Exception as exc:
                log(f"配置热加载失败：{exc}")
        return self.config


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
                              args.expires or "", args.note or "",
                              quota_mode=args.quota_mode or None,
                              quota_start=args.quota_start or "",
                              renew_mode=args.renew or None,
                              renew_start=args.renew_start or "")
    base = (args.server or cfg.get("base_url") or "https://status.example.com").rstrip("/")
    print(f"节点已创建\n  id    : {nid}\n  alias : {args.alias}")
    print(f"\n该节点的安装命令（token 只显示这一次，请立即保存）：\n"
          f"  curl -fsSL {base}/install-agent.sh | sudo bash -s -- --token {tok} --server {base} --as-user fwprobe\n")
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
    print("已设置后台登录密码（只存哈希，明文不落盘）。服务会按文件变化自动热加载，登录立即生效。")
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
          f"  curl -fsSL {base}/install-agent.sh | sudo bash -s -- --token {tok} --server {base} --as-user fwprobe")
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
    p.add_argument("--quota-mode", default="", choices=["", "day", "month", "year"],
                   help="配额周期：day/month/year（默认 month）")
    p.add_argument("--quota-start", default="", help="周期起始日 YYYY-MM-DD（默认今天）")
    p.add_argument("--renew", default="", choices=["", "day", "month", "year"],
                   help="到期自动滚动：day/month/year（默认 month，不自动传空字符串写不了就用编辑后台改）")
    p.add_argument("--renew-start", default="", help="续期起点 YYYY-MM-DD（默认 = 到期日 / 今天）")
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
