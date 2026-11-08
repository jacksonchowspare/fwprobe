#!/usr/bin/env python3
"""fwprobe agent —— 单文件探针采集端（零第三方依赖）

采什么
------
* CPU 使用率（/proc/stat 差值）、核数
* 内存 / Swap（/proc/meminfo）
* 磁盘（statvfs，默认根分区）
* 负载（/proc/loadavg）、进程数（/proc 数字目录数）
* 网络上下行速率与累计（/proc/net/dev 主网卡差值）
* TCP / UDP 连接数（/proc/net/tcp{,6}、/proc/net/udp{,6}）
* 三网探测：TCPing（默认）或 ICMP（每条目标可选），3 次握手取 min/avg/max 与丢包率

上报
----
POST {server}/api/report，Authorization: Bearer <token>，失败时写入本地 spool
（上限 200 条，恢复后补发），所有出网都有硬超时。

用法
----
    agent.py --once            # 采一次、报一次，打印结果（调试用）
    agent.py --print           # 只打印采集结果，不联网
    agent.py                   # 常驻（systemd 用）
"""
from __future__ import annotations

import argparse
import gzip
import json
import os
import random
import select
import socket
import struct
import sys
import time
import urllib.error
import urllib.request

VERSION = "0.4.4"
CONFIG_PATH = os.environ.get("FWPROBE_AGENT_CONFIG", "/etc/fwprobe-agent/config.json")
SPOOL_DIR = os.environ.get("FWPROBE_AGENT_SPOOL", "/var/lib/fwprobe-agent/spool")
SPOOL_MAX = 200
REPORT_TIMEOUT = 15

DEFAULT_TARGETS = [
    {"name": "上海电信", "proto": "tcp", "host": "sh-ct-v4.ip.zstaticcdn.com", "port": 80, "family": "auto", "enabled": True},
    {"name": "上海联通", "proto": "tcp", "host": "sh-cu-v4.ip.zstaticcdn.com", "port": 80, "family": "auto", "enabled": True},
    {"name": "上海移动", "proto": "tcp", "host": "sh-cm-v4.ip.zstaticcdn.com", "port": 80, "family": "auto", "enabled": True},
    {"name": "上海电信v6", "proto": "tcp", "host": "sh-ct-v6.ip.zstaticcdn.com", "port": 80, "family": "6", "enabled": False},
    {"name": "上海联通v6", "proto": "tcp", "host": "sh-cu-v6.ip.zstaticcdn.com", "port": 80, "family": "6", "enabled": False},
    {"name": "上海移动v6", "proto": "tcp", "host": "sh-cm-v6.ip.zstaticcdn.com", "port": 80, "family": "6", "enabled": False},
]


# --------------------------------------------------------------------------- 配置
def load_config(path=CONFIG_PATH):
    cfg = {"server": "", "token": "", "interval": 30, "check_interval": 60,
           "disk_mount": "/", "targets": DEFAULT_TARGETS, "name": ""}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            cfg.update(json.load(fh) or {})
    except FileNotFoundError:
        pass
    if os.environ.get("FWPROBE_SERVER"):
        cfg["server"] = os.environ["FWPROBE_SERVER"]
    if os.environ.get("FWPROBE_TOKEN"):
        cfg["token"] = os.environ["FWPROBE_TOKEN"]
    cfg["server"] = (cfg.get("server") or "").rstrip("/")
    return cfg


# --------------------------------------------------------------------------- /proc 读取
def _read(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def cpu_stat():
    """/proc/stat 第一行 → (total, idle) 累计 jiffies"""
    line = _read("/proc/stat").splitlines()[0] if _read("/proc/stat") else ""
    if not line.startswith("cpu"):
        return None
    nums = [int(x) for x in line.split()[1:9]]
    idle = nums[3] + (nums[4] if len(nums) > 4 else 0)      # idle + iowait
    return sum(nums), idle


def meminfo():
    out = {}
    for line in _read("/proc/meminfo").splitlines():
        k, _, rest = line.partition(":")
        try:
            out[k] = int(rest.strip().split()[0]) * 1024     # kB → 字节
        except (IndexError, ValueError):
            continue
    total = out.get("MemTotal", 0)
    avail = out.get("MemAvailable") or (out.get("MemFree", 0) + out.get("Buffers", 0) + out.get("Cached", 0))
    swap_total = out.get("SwapTotal", 0)
    swap_free = out.get("SwapFree", 0)
    return {"used": max(0, total - avail), "total": total}, \
           {"used": max(0, swap_total - swap_free), "total": swap_total}


def disk_usage(mount="/"):
    try:
        st = os.statvfs(mount)
    except OSError:
        return {"used": 0, "total": 0}
    total = st.f_blocks * st.f_frsize
    free = st.f_bavail * st.f_frsize
    return {"used": max(0, total - free), "total": total}


def loadavg():
    try:
        with open("/proc/loadavg") as fh:
            parts = fh.read().split()
        return [float(parts[0]), float(parts[1]), float(parts[2])]
    except Exception:
        return [0.0, 0.0, 0.0]


def proc_count():
    n = 0
    try:
        for name in os.listdir("/proc"):
            if name.isdigit():
                n += 1
    except OSError:
        pass
    return n


def uptime_seconds():
    try:
        return int(float(_read("/proc/uptime").split()[0]))
    except Exception:
        return 0


def primary_iface():
    """默认路由网卡名"""
    try:
        for line in _read("/proc/net/route").splitlines()[1:]:
            parts = line.split()
            if len(parts) > 1 and parts[1] == "00000000":
                return parts[0]
    except Exception:
        pass
    try:
        for line in _read("/proc/net/dev").splitlines()[2:]:
            name = line.split(":")[0].strip()
            if name and name != "lo":
                return name
    except Exception:
        pass
    return "eth0"


def net_counters(iface):
    """/proc/net/dev 某网卡 → (rx_bytes, tx_bytes)"""
    for line in _read("/proc/net/dev").splitlines()[2:]:
        if ":" not in line:
            continue
        name, data = line.split(":", 1)
        if name.strip() != iface:
            continue
        parts = data.split()
        try:
            return int(parts[0]), int(parts[8])
        except (IndexError, ValueError):
            return 0, 0
    return 0, 0


def conn_counts():
    """TCP 总连接 / ESTABLISHED / UDP 连接（v4+v6）"""
    tcp = estab = udp = 0
    for path, is_tcp in (("/proc/net/tcp", True), ("/proc/net/tcp6", True),
                         ("/proc/net/udp", False), ("/proc/net/udp6", False)):
        lines = _read(path).splitlines()
        for line in lines[1:]:
            parts = line.split()
            if len(parts) < 4:
                continue
            if is_tcp:
                tcp += 1
                if parts[3] == "01":       # TCP_ESTABLISHED
                    estab += 1
            elif not is_tcp and len(parts) >= 2:
                udp += 1
    return tcp, estab, udp


def os_info():
    info = {"os_id": "", "os_name": "", "kernel": ""}
    for line in _read("/etc/os-release").splitlines():
        k, _, v = line.partition("=")
        v = v.strip().strip('"')
        if k == "ID":
            info["os_id"] = v
        elif k == "PRETTY_NAME":
            info["os_name"] = v
    try:
        info["kernel"] = os.uname().release
    except Exception:
        pass
    return info


def hostname():
    try:
        return os.uname().nodename
    except Exception:
        return ""


# --------------------------------------------------------------------------- 探测
def resolve_all(host, family="auto"):
    """解析出该目标的**全部**地址，返回 (地址列表, 族标签)。

    为什么不全用第一个：三网目标是 CDN 域名，一次解析会拿到多个 A 记录，
    不同时刻命中不同边缘节点，延迟能差 10 倍以上（实测 30ms ↔ 1000ms）。
    逐个测一遍取最优，才反映「这条线路的真实质量」，也不会一次抽到慢节点就报红。
    """
    fam = {"4": socket.AF_INET, "6": socket.AF_INET6}.get(str(family))
    tag = str(family) if fam is not None else "auto"
    order = [fam] if fam is not None else [socket.AF_INET6, socket.AF_INET]
    for f in order:
        try:
            infos = socket.getaddrinfo(host, None, f, socket.SOCK_STREAM)
        except socket.gaierror:
            continue
        addrs = []
        for info in infos:
            ip = info[4][0]
            if ip not in addrs:
                addrs.append(ip)
        if addrs:
            return addrs, ("6" if f == socket.AF_INET6 else "4")
    return [], tag


def resolve(host, family="auto"):
    addrs, tag = resolve_all(host, family)
    return (addrs[0] if addrs else None), tag


# Komari 口径（komari-agent/server/task.go）：每轮只取一个数据点，不做多次平均。
# 1) 单次测量，超时 3s，DNS 解析单独做、不计入耗时
# 2) 首次 >1000ms 就重试，最多 3 次，取第一个 ≤1000ms 的结果
# 3) TCP 模式特判：首次比后续低 800ms 以上 → SYN 重传（线路并没这么好），记丢包
# 4) 重试完仍 >1000ms → 记丢包
CHECK_TIMEOUT = 3.0
HIGH_LAT_MS = 1000.0
HIGH_LAT_RETRIES = 3
TCP_RETRANS_DIFF = 800.0

_ROTATION = {}          # 目标 → 轮次计数：多 A 记录按轮次轮换，避免一轮混测不同边缘


def _tcp_once(addr, port, timeout):
    t0 = time.time()
    s = socket.create_connection((addr, int(port or 80)), timeout=timeout)
    s.close()
    return (time.time() - t0) * 1000.0


def _icmp_once(addr, family, timeout):
    """单包 ICMP。原始套接字，需要 root / CAP_NET_RAW。"""
    fam_i = socket.AF_INET6 if str(family) == "6" else socket.AF_INET
    s = socket.socket(fam_i, socket.SOCK_RAW,
                      socket.IPPROTO_ICMP if fam_i == socket.AF_INET else socket.IPPROTO_ICMPV6)
    try:
        s.settimeout(timeout)
        ident = os.getpid() & 0xFFFF
        payload = struct.pack("!d", time.time()) + b"fwprobe"
        hdr = struct.pack("!BBHHH", 8, 0, 0, ident, 1)
        pkt = struct.pack("!BBHHH", 8, 0, _icmp_checksum(hdr + payload), ident, 1) + payload
        t0 = time.time()
        s.sendto(pkt, (addr, 0))
        while True:
            r, _, _ = select.select([s], [], [], timeout)
            if not r:
                raise socket.timeout()
            data, peer = s.recvfrom(2048)
            if peer[0] != addr:
                continue
            off = 20 if fam_i == socket.AF_INET else 0
            if len(data) < off + 8 or data[off] not in (0, 129):
                continue
            return (time.time() - t0) * 1000.0
    finally:
        s.close()


def probe_once(host, port=80, proto="tcp", family="auto", timeout=None):
    """按 Komari 口径测一个点，返回 {ok, loss, min, avg, max, family, addr, note}。

    min/avg/max 三者相同 —— 一次测量只有一个值，保留字段是为了兼容已有存储与前端。
    """
    timeout = CHECK_TIMEOUT if timeout is None else timeout
    addrs, fam = resolve_all(host, family)
    if not addrs:
        return {"ok": False, "loss": 100.0, "min": None, "avg": None, "max": None,
                "family": fam, "addr": None, "note": "DNS 解析失败"}

    key = "%s|%s" % (host, family)
    idx = _ROTATION.get(key, 0)
    _ROTATION[key] = idx + 1
    addr = addrs[idx % len(addrs)]          # 一轮只打一个地址，下一轮换下一个

    def measure():
        if proto == "icmp":
            return _icmp_once(addr, fam, timeout)
        return _tcp_once(addr, port, timeout)

    def attempt():
        try:
            return measure(), None
        except (OSError, socket.timeout):
            return None, "timeout"

    first, err = attempt()
    if err:
        return {"ok": False, "loss": 100.0, "min": None, "avg": None, "max": None,
                "family": fam, "addr": addr, "note": "超时"}

    value, note = first, ""
    if first > HIGH_LAT_MS:
        value = None
        for i in range(HIGH_LAT_RETRIES):
            second, err2 = attempt()
            if err2:
                continue
            if second <= HIGH_LAT_MS:
                if proto == "tcp" and (first - second) > TCP_RETRANS_DIFF:
                    note = "疑似 SYN 重传（首测 %.0fms → 复测 %.0fms）" % (first, second)
                else:
                    value = second
                break
        if value is None and not note:
            note = "重试 %d 次仍 >%dms" % (HIGH_LAT_RETRIES, int(HIGH_LAT_MS))

    if value is None:
        return {"ok": False, "loss": 100.0, "min": None, "avg": None, "max": None,
                "family": fam, "addr": addr, "note": note}

    v = round(value, 1)
    return {"ok": True, "loss": 0.0, "min": v, "avg": v, "max": v,
            "family": fam, "addr": addr, "note": note}


def tcping(host, port, attempts=1, timeout=None, family="auto"):
    """兼容旧调用的薄封装：attempts>1 时重复 probe_once 做统计（正常路径不用）。"""
    results = [probe_once(host, port, "tcp", family, timeout) for _ in range(max(1, int(attempts)))]
    return _merge(results)


def icmp_ping(host, attempts=1, timeout=None, family="4"):
    results = [probe_once(host, 0, "icmp", family, timeout) for _ in range(max(1, int(attempts)))]
    return _merge(results)


def _merge(results):
    oks = [r for r in results if r["ok"]]
    loss = round(100.0 * (len(results) - len(oks)) / max(1, len(results)), 1)
    if not oks:
        return {"ok": False, "loss": 100.0, "min": None, "avg": None, "max": None,
                "family": results[0]["family"] if results else "auto"}
    vals = [r["avg"] for r in oks]
    return {"ok": True, "loss": loss, "min": min(vals), "avg": round(sum(vals) / len(vals), 1),
            "max": max(vals), "family": oks[0]["family"]}


def _icmp_checksum(data):
    s = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + (data[i + 1] if i + 1 < len(data) else 0)
        s += word
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def icmp_ping(host, attempts=3, timeout=2.0, family="4"):
    """原始套接字 ICMP（需要 root / CAP_NET_RAW）"""
    addr, fam = resolve(host, family if str(family) in ("4", "6") else "4")
    if not addr:
        return {"ok": False, "loss": 100.0, "min": None, "avg": None, "max": None, "family": fam}
    fam_i = socket.AF_INET6 if fam == "6" else socket.AF_INET
    try:
        s = socket.socket(fam_i, socket.SOCK_RAW, socket.IPPROTO_ICMP if fam_i == socket.AF_INET else socket.IPPROTO_ICMPV6)
    except PermissionError:
        return {"ok": False, "loss": 100.0, "min": None, "avg": None, "max": None,
                "family": fam, "error": "无权限（需要 root 或 CAP_NET_RAW）"}
    except OSError as exc:
        return {"ok": False, "loss": 100.0, "min": None, "avg": None, "max": None,
                "family": fam, "error": str(exc)}
    rtts, fails = [], 0
    s.settimeout(timeout)
    for i in range(attempts):
        ident = os.getpid() & 0xFFFF
        payload = struct.pack("!d", time.time()) + b"fwprobe"
        hdr = struct.pack("!BBHHH", 8, 0, 0, ident, i + 1)
        csum = _icmp_checksum(hdr + payload)
        pkt = struct.pack("!BBHHH", 8, 0, csum, ident, i + 1) + payload
        t0 = time.time()
        try:
            s.sendto(pkt, (addr, 0))
            while True:
                r, _, _ = select.select([s], [], [], timeout)
                if not r:
                    raise socket.timeout()
                data, peer = s.recvfrom(2048)
                if peer[0] != addr:
                    continue
                # IPv4 头 20 字节后是 ICMP；IPv6 无 IP 头
                off = 20 if fam_i == socket.AF_INET else 0
                if len(data) < off + 8:
                    continue
                typ = data[off]
                if typ not in (0, 129):        # echo reply (v4 / v6)
                    continue
                rtts.append((time.time() - t0) * 1000.0)
                break
        except (socket.timeout, OSError):
            fails += 1
    s.close()
    loss = round(fails * 100.0 / attempts, 1)
    if not rtts:
        return {"ok": False, "loss": 100.0, "min": None, "avg": None, "max": None, "family": fam}
    return {"ok": True, "loss": loss, "min": round(min(rtts), 1),
            "avg": round(sum(rtts) / len(rtts), 1), "max": round(max(rtts), 1), "family": fam}


def run_checks(targets):
    out = []
    for t in targets or []:
        if not t.get("enabled", True):
            continue
        proto = (t.get("proto") or "tcp").lower()
        name = t.get("name") or t.get("host") or "?"
        host = t.get("host") or ""
        if not host:
            continue
        port = None if proto == "icmp" else int(t.get("port") or 80)
        res = probe_once(host, port or 0, proto, t.get("family", "auto"))
        out.append({"name": name, "proto": proto, "host": host, "port": port,
                    "family": res.get("family", t.get("family", "auto")),
                    "addr": res.get("addr"), "note": res.get("note", ""),
                    "ok": res["ok"], "loss": res["loss"],
                    "min": res["min"], "avg": res["avg"], "max": res["max"]})
    return out


# --------------------------------------------------------------------------- 采样
class Sampler:
    def __init__(self, cfg):
        self.cfg = cfg
        self.last_cpu = None
        self.last_net = None
        self.last_net_ts = None
        self.last_checks = None
        self.last_checks_ts = 0

    def sample(self):
        now = time.time()
        st = cpu_stat()
        cpu_pct = None
        if st and self.last_cpu:
            dt = st[0] - self.last_cpu[0]
            di = st[1] - self.last_cpu[1]
            if dt > 0:
                cpu_pct = round(max(0.0, min(100.0, 100.0 * (dt - di) / dt)), 2)
        self.last_cpu = st

        mem, swap = meminfo()
        iface = primary_iface()
        rx, tx = net_counters(iface)
        rx_bps = tx_bps = 0
        if self.last_net and self.last_net_ts:
            dt = max(0.001, now - self.last_net_ts)
            rx_bps = max(0, int((rx - self.last_net[0]) / dt))
            tx_bps = max(0, int((tx - self.last_net[1]) / dt))
        self.last_net = (rx, tx)
        self.last_net_ts = now

        tcp, estab, udp = conn_counts()
        info = os_info()
        payload = {
            "agent": VERSION,
            "ts": int(now),
            "hostname": hostname(),
            "kernel": info["kernel"], "os_id": info["os_id"], "os_name": info["os_name"],
            "uptime": uptime_seconds(),
            "cpu": cpu_pct, "cpu_cores": os.cpu_count() or 1,
            "mem": mem, "swap": swap,
            "disk": disk_usage(self.cfg.get("disk_mount") or "/"),
            "load": loadavg(),
            "net": {"iface": iface, "rx_bps": rx_bps, "tx_bps": tx_bps,
                    "rx_total": rx, "tx_total": tx},
            "conn": {"tcp": tcp, "estab": estab, "udp": udp},
            "procs": proc_count(),
            "checks": [],
        }
        # 探测按 check_interval 走（默认 60s；卡片 20 格 = 20 分钟，每分钟走 1 格）
        ci = float(self.cfg.get("check_interval") or 60)
        if self.last_checks is None or (now - self.last_checks_ts) >= ci:
            self.last_checks = run_checks(self.cfg.get("targets"))
            self.last_checks_ts = now
        payload["checks"] = self.last_checks or []
        payload["checks_ts"] = int(self.last_checks_ts) if self.last_checks else 0
        return payload


# --------------------------------------------------------------------------- 上报
def post_report(cfg, payload):
    url = cfg["server"] + "/api/report"
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    headers = {"Content-Type": "application/json", "Authorization": "Bearer " + cfg["token"],
               "User-Agent": f"fwprobe-agent/{VERSION}"}
    if len(data) > 4096:                     # 大包再压缩，小包不值得
        data = gzip.compress(data)
        headers["Content-Encoding"] = "gzip"
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=REPORT_TIMEOUT) as resp:
        return resp.read().decode("utf-8", "replace")


def spool_save(payload):
    try:
        os.makedirs(SPOOL_DIR, exist_ok=True)
        names = sorted(f for f in os.listdir(SPOOL_DIR) if f.endswith(".json"))
        while len(names) >= SPOOL_MAX:
            os.unlink(os.path.join(SPOOL_DIR, names.pop(0)))
        fn = os.path.join(SPOOL_DIR, f"{int(time.time()*1000)}-{random.randint(1000,9999)}.json")
        with open(fn, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False)
    except OSError:
        pass


def spool_flush(cfg):
    try:
        names = sorted(f for f in os.listdir(SPOOL_DIR) if f.endswith(".json"))
    except OSError:
        return 0
    sent = 0
    for name in names:
        p = os.path.join(SPOOL_DIR, name)
        try:
            with open(p, "r", encoding="utf-8") as fh:
                payload = json.load(fh)
            post_report(cfg, payload)
            os.unlink(p)
            sent += 1
        except Exception:
            break                      # 还连不上就停下，下一轮再试
    return sent


# --------------------------------------------------------------------------- 主循环
def main(argv=None):
    ap = argparse.ArgumentParser(prog="agent.py", description=f"fwprobe agent {VERSION}")
    ap.add_argument("--once", action="store_true", help="采一次并上报，打印结果")
    ap.add_argument("--print", dest="do_print", action="store_true", help="只打印采集结果，不上报")
    ap.add_argument("--config", default=CONFIG_PATH)
    args = ap.parse_args(argv)

    cfg = load_config(args.config)
    if not cfg.get("token"):
        # 没配 token 时也允许本地采样（方便调试），只是不上报
        pass

    sampler = Sampler(cfg)
    sampler.sample()                     # 第一次只建基线（CPU/网速需要差值）
    if args.do_print or args.once:
        payload = sampler.sample()
        if args.do_print:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
            return 0
        try:
            print(post_report(cfg, payload))
        except Exception as exc:
            print(f"上报失败: {exc}", file=sys.stderr)
            spool_save(payload)
            return 1
        return 0

    interval = max(10, int(cfg.get("interval") or 30))
    print(f"fwprobe agent {VERSION} 启动：每 {interval}s 上报到 {cfg.get('server')}", flush=True)
    while True:
        t0 = time.time()
        try:
            payload = sampler.sample()
            try:
                post_report(cfg, payload)
                spool_flush(cfg)
            except Exception as exc:
                print(f"[warn] 上报失败（已入本地缓存）: {exc}", file=sys.stderr)
                spool_save(payload)
        except Exception as exc:                     # 采集本身出错不能把进程弄死
            print(f"[warn] 采样失败: {exc}", file=sys.stderr)
        dt = interval - (time.time() - t0)
        time.sleep(max(1.0, dt))


if __name__ == "__main__":
    sys.exit(main())
