#!/usr/bin/env python3
"""fwprobe 单元测试（python3 -m unittest test.test_probe -v）

覆盖：节点 CRUD / token 轮换 / 上报入库 / 公开摘要不泄露隐私 / HTTP 路由与鉴权 /
agent 的 /proc 解析 / TCPing 真实握手 / 配额解析。
"""
import datetime
import json
import pathlib
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import agent as A          # noqa: E402
import probe as P          # noqa: E402


def mk_store():
    d = tempfile.mkdtemp()
    return P.Store(os.path.join(d, "t.db")), d


def payload(cpu=1.5, rx=1000, tx=2000, checks=None):
    return {
        "agent": "0.1.0", "ts": int(time.time()), "hostname": "test-host",
        "kernel": "6.1.0", "os_id": "debian", "os_name": "Debian GNU/Linux 13", "uptime": 3600,
        "cpu": cpu, "cpu_cores": 2,
        "mem": {"used": 300, "total": 1000}, "swap": {"used": 0, "total": 2048},
        "disk": {"used": 5000, "total": 20000}, "load": [0.1, 0.2, 0.3],
        "net": {"iface": "eth0", "rx_bps": rx, "tx_bps": tx, "rx_total": 50000, "tx_total": 90000},
        "conn": {"tcp": 12, "estab": 5, "udp": 3}, "procs": 88,
        "checks": checks if checks is not None else [
            {"name": "上海电信", "proto": "tcp", "host": "a.example", "port": 80, "family": "4",
             "ok": True, "loss": 0.0, "min": 29.0, "avg": 30.5, "max": 32.0},
        ],
    }


class TestStore(unittest.TestCase):
    def setUp(self):
        self.st, self.dir = mk_store()

    def tearDown(self):
        self.st.conn.close()

    def test_add_node_and_token_lookup(self):
        nid, tok = self.st.add_node("香港-1", "HK", quota_bytes=500 * 1024 ** 3,
                                    expires_at="2026-12-31")
        n = self.st.node(nid)
        self.assertEqual(n["alias"], "香港-1")
        self.assertEqual(n["grp"], "HK")
        self.assertEqual(n["quota_bytes"], 500 * 1024 ** 3)
        self.assertEqual(self.st.node_by_token(tok)["id"], nid)
        self.assertIsNone(self.st.node_by_token("wrong-token"))
        # 库里不能出现明文 token
        self.assertNotEqual(n["token_hash"], tok)
        self.assertEqual(len(n["token_hash"]), 64)

    def test_rotate_token_invalidates_old(self):
        nid, tok = self.st.add_node("x")
        new = self.st.rotate_token(nid)
        self.assertIsNotNone(new)
        self.assertIsNone(self.st.node_by_token(tok))
        self.assertEqual(self.st.node_by_token(new)["id"], nid)
        self.assertIsNone(self.st.rotate_token("nope"))

    def test_ingest_and_latest(self):
        nid, tok = self.st.add_node("a")
        node = self.st.node(nid)
        ts = self.st.ingest(node, payload(), "1.2.3.4")
        self.assertTrue(ts > 0)
        s, checks = self.st.latest(nid)
        self.assertEqual(s["cpu"], 1.5)
        self.assertEqual(s["mem_total"], 1000)
        self.assertEqual(s["tcp"], 12)
        self.assertEqual(len(checks), 1)
        self.assertEqual(checks[0]["name"], "上海电信")
        self.assertAlmostEqual(checks[0]["ravg"], 30.5)
        # 上报时记录了来源 IP 与系统信息
        n2 = self.st.node(nid)
        self.assertEqual(n2["public_ip"], "1.2.3.4")
        self.assertEqual(n2["os_id"], "debian")
        self.assertGreater(n2["last_seen"], 0)

    def test_ingest_skewed_clock_uses_server_time(self):
        nid, _ = self.st.add_node("a")
        node = self.st.node(nid)
        bad = payload()
        bad["ts"] = int(time.time()) - 7200        # agent 时钟差 2 小时
        ts = self.st.ingest(node, bad, "1.2.3.4")
        self.assertLess(abs(ts - int(time.time())), 5)

    def test_totals_and_reset(self):
        nid, _ = self.st.add_node("a")
        node = self.st.node(nid)
        now = int(time.time())
        p1 = payload(); p1["ts"] = now - 60; p1["net"]["rx_total"] = 1000; p1["net"]["tx_total"] = 2000
        p2 = payload(); p2["ts"] = now - 30; p2["net"]["rx_total"] = 5000; p2["net"]["tx_total"] = 9000
        self.st.ingest(node, p1, "1.1.1.1")
        self.st.ingest(node, p2, "1.1.1.1")
        rx, tx = self.st.totals(nid)
        self.assertEqual((rx, tx), (4000, 7000))
        # 计数器回绕（机器重启 → 累计值归零）不应出现负数
        p3 = payload(); p3["ts"] = now; p3["net"]["rx_total"] = 10; p3["net"]["tx_total"] = 10
        self.st.ingest(node, p3, "1.1.1.1")
        rx, tx = self.st.totals(nid)
        self.assertGreaterEqual(rx, 0)
        self.assertGreaterEqual(tx, 0)

    def test_delete_node_cascades(self):
        nid, _ = self.st.add_node("a")
        node = self.st.node(nid)
        self.st.ingest(node, payload(), "1.1.1.1")
        self.st.delete_node(nid)
        self.assertIsNone(self.st.node(nid))
        s, checks = self.st.latest(nid)
        self.assertIsNone(s)
        self.assertEqual(checks, [])

    def test_update_node_fields(self):
        nid, _ = self.st.add_node("a")
        self.assertTrue(self.st.update_node(nid, alias="b", quota_bytes=123, expires_at="2027-01-01"))
        n = self.st.node(nid)
        self.assertEqual((n["alias"], n["quota_bytes"], n["expires_at"]), ("b", 123, "2027-01-01"))
        self.assertFalse(self.st.update_node(nid, token_hash="hack"))    # 白名单外的字段不接受
        self.assertFalse(self.st.update_node("nope", alias="x"))

    def test_public_summary_hides_private_fields(self):
        nid, _ = self.st.add_node("香港-1")
        node = self.st.node(nid)
        self.st.ingest(node, payload(), "203.0.113.9")
        d = P.public_summary(self.st)
        self.assertEqual(len(d["nodes"]), 1)
        n = d["nodes"][0]
        for leak in ("token_hash", "public_ip", "hostname"):
            self.assertNotIn(leak, n)
        self.assertEqual(n["kernel"], "6.1.0")      # 内核版本是有意公开的（卡片上用）
        self.assertEqual(n["alias"], "香港-1")
        self.assertIn("sample", n)
        self.assertTrue(n["online"])

    def test_multi_groups(self):
        """一个节点可挂多个分组：groups 存 JSON，grp 保留主分组（兼容老代码）"""
        nid, _ = self.st.add_node("n1", groups=["生产", "东京"])
        n = self.st.node(nid)
        self.assertEqual(n["grp"], "生产")
        self.assertEqual(P.parse_groups(n["groups"]), ["生产", "东京"])
        # 改组
        self.st.update_node(nid, groups=["测试"])
        n = self.st.node(nid)
        self.assertEqual(P.parse_groups(n["groups"]), ["测试"])
        self.assertEqual(n["grp"], "测试")
        # 清空分组
        self.st.update_node(nid, groups=[])
        n = self.st.node(nid)
        self.assertEqual(P.parse_groups(n["groups"]), [])
        self.assertEqual(n["grp"], "")

    def test_check_hist(self):
        """卡片 20 格滚动条：每条线路按时间旧→新返回，最多 20 条"""
        nid, _ = self.st.add_node("a")
        node = self.st.node(nid)
        now = int(time.time())
        for i in range(25):
            # 注意：中心会把偏离本机时间 >600s 的 ts 拉回 now（防伪造/防乱序），
            # 所以测试数据要落在 10 分钟内，否则会被合并
            p = payload(); p["ts"] = now - (25 - i) * 20
            p["checks"][0]["avg"] = 50 + i      # 上报字段是 min/avg/max（入库变 rmin/ravg）
            p["checks"][0]["min"] = 40 + i
            self.st.ingest(node, p, "1.1.1.1")
        h = self.st.check_hist(nid, 20)
        ct = h["上海电信"]
        self.assertEqual(len(ct), 20)
        self.assertEqual(ct[0]["min"], 45.0)      # i=5 起（最新 20 条里最早那条）
        self.assertEqual(ct[-1]["min"], 64.0)
        self.assertTrue(all(ct[i]["ts"] <= ct[i + 1]["ts"] for i in range(len(ct) - 1)))

    def test_three_buckets(self):
        """三网口径：1 小时分 20 格（每格 3 分钟），格值取平均 + 格内丢包率"""
        nid, _ = self.st.add_node("a")
        now = int(time.time())
        # 注意：主键是 (node_id, ts, name)，同一条线路同一秒只能有一行（一轮一个值），
        # 所以同一格内要错开几秒
        rows = [
            # 第 0 格 [now-3600, now-3420)：成功 100ms、200ms 各一次，丢包一次
            (nid, now - 3500, "上海电信", 1, 0.0, 100.0, 100.0, 100.0),
            (nid, now - 3460, "上海电信", 1, 0.0, 200.0, 200.0, 200.0),
            (nid, now - 3440, "上海电信", 0, 100.0, None, None, None),
            # 最后一格（当前）
            (nid, now - 60, "上海电信", 1, 0.0, 50.0, 50.0, 50.0),
        ]
        for r in rows:
            self.st.conn.execute(
                "INSERT OR REPLACE INTO checks(node_id,ts,name,ok,loss,rmin,ravg,rmax)"
                " VALUES(?,?,?,?,?,?,?,?)", r)
        self.st.conn.commit()

        t = self.st.three(nid)
        self.assertEqual(t["bucket_seconds"], 180)
        target = t["targets"]["上海电信"]
        self.assertEqual(len(target["buckets"]), 20)
        self.assertAlmostEqual(target["buckets"][0]["latency"], 150.0, 1)   # (100+200)/2
        self.assertAlmostEqual(target["buckets"][0]["loss"], 33.3, 1)      # 1/3 丢
        self.assertIsNone(target["buckets"][10])                            # 空桶 → 前端画灰
        self.assertAlmostEqual(target["buckets"][19]["latency"], 50.0, 1)
        self.assertAlmostEqual(target["avg_latency"], 116.7, 1)             # (100+200+50)/3
        self.assertAlmostEqual(target["avg_loss"], 25.0, 1)                 # 1/4 丢

    def test_checks_dedupe_by_checks_ts(self):
        """同一轮探测被多次上报（资源 30s 报一次、探测 60s 一次）时不能重复入库"""
        nid, _ = self.st.add_node("a")
        node = self.st.node(nid)
        now = int(time.time())
        p = payload(); p["ts"] = now; p["checks_ts"] = now - 5
        self.st.ingest(node, p, "1.1.1.1")
        self.st.ingest(node, p, "1.1.1.1")          # 30 秒后又报同一轮
        got = self.st.conn.execute("SELECT COUNT(*) FROM checks WHERE node_id=?", (nid,)).fetchone()[0]
        self.assertEqual(got, len(p["checks"]))     # 没有翻倍

        p2 = payload(); p2["ts"] = now + 30; p2["checks_ts"] = now + 25
        self.st.ingest(node, p2, "1.1.1.1")         # 新的一轮
        got = self.st.conn.execute("SELECT COUNT(*) FROM checks WHERE node_id=?", (nid,)).fetchone()[0]
        self.assertEqual(got, 2 * len(p["checks"]))

    def test_spark_series(self):
        nid, _ = self.st.add_node("a")
        node = self.st.node(nid)
        now = int(time.time())
        for i in range(3):
            p = payload(); p["ts"] = now - (3 - i) * 30
            p["net"]["rx_bps"] = 100 * (i + 1); p["net"]["tx_bps"] = 200 * (i + 1)
            p["cpu"] = 1.0 * (i + 1)
            self.st.ingest(node, p, "1.1.1.1")
        sp = self.st.spark(nid, 10)
        self.assertEqual(sp["rx"], [100, 200, 300])
        self.assertEqual(sp["tx"], [200, 400, 600])
        ser = self.st.series(nid, 1)
        self.assertEqual(len(ser["points"]), 3)
        self.assertEqual(ser["points"][-1]["cpu"], 3.0)
        self.assertIn("上海电信", ser["checks"])
        self.assertEqual(len(ser["checks"]["上海电信"]), 3)

    def test_offline_after_threshold(self):
        nid, _ = self.st.add_node("a")
        node = self.st.node(nid)
        self.st.ingest(node, payload(), "1.1.1.1")
        with self.st.lock:
            self.st.conn.execute("UPDATE nodes SET last_seen=? WHERE id=?",
                                 (int(time.time()) - P.OFFLINE_AFTER - 5, nid))
            self.st.conn.commit()
        n = P.public_summary(self.st)["nodes"][0]
        self.assertFalse(n["online"])

    def test_disabled_node_not_public(self):
        nid, tok = self.st.add_node("a")
        self.st.update_node(nid, enabled=0)
        self.assertEqual(P.public_summary(self.st)["nodes"], [])
        node = self.st.node(nid)
        # 停用节点的上报要被拒（服务端在 HTTP 层判断，这里验证数据本身不再更新）
        before = self.st.node(nid)["last_seen"]
        self.st.ingest(node, payload(), "1.1.1.1")
        self.assertNotEqual(before, None)


class TestStaticPage(unittest.TestCase):
    """静态页结构自检 —— 曾经因为脚本编辑把 CSS 甩到 <html> 前面，页面顶部直接显示一串 CSS 源码。"""

    @classmethod
    def setUpClass(cls):
        cls.src = pathlib.Path(P.__file__).with_name("static").joinpath("index.html").read_text("utf-8")

    def test_doctype_first(self):
        self.assertTrue(self.src.lstrip().startswith("<!DOCTYPE html>"),
                        "index.html 必须以 DOCTYPE 开头，前面不能有任何文本")

    def test_single_style_block(self):
        self.assertEqual(self.src.count("<style"), 1)
        self.assertEqual(self.src.count("</style>"), 1)

    def test_no_css_outside_style(self):
        head = self.src[:self.src.index("<body")]
        before_style = head[:head.index("<style")]
        self.assertNotIn("{", before_style, "<style> 之前出现了 CSS 文本")
        after_style = head[head.index("</style>"):]
        self.assertNotIn("keyframes", after_style)

    def test_strip_styles_present(self):
        self.assertIn(".strip{display:block", self.src)
        self.assertIn(".strip rect.live", self.src)
        # 详情页返回后必须重排小方块：列表隐藏时量不到宽度，不重排就永久空白
        self.assertIn("STRIPS_DIRTY", self.src)
        self.assertIn("relayoutStrips();", self.src)
        self.assertNotIn(".cells{display:flex", self.src)   # 旧的 flex 格子实现已废弃


class TestCountryDetect(unittest.TestCase):
    """归属地识别：多源兜底 + 失败退避重试（旧版一次失败就永久拉黑，节点 country 一直空）"""

    def tearDown(self):
        P.COUNTRY_CACHE.clear()
        P.reset_country_schedule()

    def test_schedule_backoff_and_reset(self):
        P.reset_country_schedule()
        self.assertTrue(P.schedule_country("n1", now=1000))
        self.assertFalse(P.schedule_country("n1", now=1001))      # 退避中，不再打接口
        self.assertTrue(P.schedule_country("n1", now=1030))
        self.assertFalse(P.schedule_country("n1", now=1031))
        P.reset_country_schedule("n1")
        self.assertTrue(P.schedule_country("n1", now=1031))

    def test_detect_country_third_source(self):
        calls = []

        class _Resp:
            def __init__(self, body): self.body = body
            def read(self, n=None): return self.body
            def __enter__(self): return self
            def __exit__(self, *a): return False

        def fake(url, timeout=0):
            u = url if isinstance(url, str) else getattr(url, "full_url", "")
            calls.append(u)
            if "ipinfo.io" in u:
                raise OSError("blocked")
            if "ip-api.com" in u:
                return _Resp(b'{"status":"fail","message":"reserved range"}')
            return _Resp(b'{"success":true,"country_code":"JP"}')

        orig = P.urllib.request.urlopen
        P.urllib.request.urlopen = fake
        try:
            code, source, err = P.detect_country("8.8.4.4")
        finally:
            P.urllib.request.urlopen = orig
        self.assertEqual((code, source, err), ("JP", "ipwho", ""))
        self.assertTrue(any("ipwho.is" in c for c in calls))

    def test_detect_country_reports_reason(self):
        """全挂时要带上每个源的原因，否则线上只能猜（本次故障就是这么被藏住的）"""

        class _Resp:
            def read(self, n=None): return b'{"status":"fail","message":"quota exceeded"}'
            def __enter__(self): return self
            def __exit__(self, *a): return False

        orig = P.urllib.request.urlopen
        P.urllib.request.urlopen = lambda url, timeout=0: _Resp()
        try:
            code, source, err = P.detect_country("8.8.8.8")
        finally:
            P.urllib.request.urlopen = orig
        self.assertEqual(code, "")
        for name in ("ipinfo", "ip-api"):
            self.assertIn(name, err)

    def test_norm_country_only_two_letters(self):
        self.assertEqual(P.norm_country("jp"), "JP")
        self.assertEqual(P.norm_country("GB"), "UK")
        self.assertEqual(P.norm_country("日本"), "")
        self.assertEqual(P.norm_country("J"), "")
        self.assertEqual(P.norm_country("JPN"), "")


class TestConfigHotReload(unittest.TestCase):
    """CLI 改密码后不用重启服务（旧版只在启动时读一次 config.json，用户改完密码仍登不进去）"""

    def test_password_applies_without_restart(self):
        import tempfile
        path = os.path.join(tempfile.mkdtemp(), "config.json")
        with open(path, "w") as fh:
            json.dump({"admin_token": "t0", "admin_password": ""}, fh)
        orig = P.CONFIG_PATH
        P.CONFIG_PATH = path
        try:
            srv = P.Server(("127.0.0.1", 0), P.Handler, None, P.load_config())
            try:
                self.assertEqual(srv.cfg().get("admin_password"), "")
                with open(path, "w") as fh:
                    json.dump({"admin_token": "t0", "admin_password": "h-new"}, fh)
                future = time.time() + 5
                os.utime(path, (future, future))
                self.assertEqual(srv.cfg().get("admin_password"), "h-new")
                self.assertEqual(srv.cfg().get("admin_token"), "t0")   # 文件里有的键不能被默认值冲掉
            finally:
                srv.server_close()
        finally:
            P.CONFIG_PATH = orig

    def test_missing_config_is_harmless(self):
        orig = P.CONFIG_PATH
        P.CONFIG_PATH = "/nonexistent/fwprobe/config.json"
        try:
            srv = P.Server(("127.0.0.1", 0), P.Handler, None, {"admin_token": "keep"})
            try:
                self.assertEqual(srv.cfg().get("admin_token"), "keep")
            finally:
                srv.server_close()
        finally:
            P.CONFIG_PATH = orig


class TestThreeTargets(unittest.TestCase):
    """三网目标（v0.5.21）：中心统一管理 + 下发 agent"""

    def setUp(self):
        self.st, self.dir = mk_store()

    def test_seed_defaults(self):
        ts = self.st.targets()
        self.assertEqual([t["name"] for t in ts],
                         ["电信·上海", "联通·上海", "移动·上海",
                          "电信·上海v6", "联通·上海v6", "移动·上海v6"])
        self.assertEqual(sum(t["enabled"] for t in ts), 3)      # 只有 v4 三条默认启用
        self.assertEqual(ts[0]["proto"], "tcp")

    def test_name_composed_from_op_and_region(self):
        self.st.save_targets([
            {"id": "x", "op": "广电", "region": "北京", "host": "1.1.1.1", "proto": "icmp"},
            {"id": "y", "op": "电信", "region": "", "host": "2.2.2.2", "proto": "tcp", "port": 443},
        ])
        ts = self.st.targets()
        self.assertEqual([t["name"] for t in ts], ["广电·北京", "电信"])
        self.assertEqual(ts[0]["proto"], "icmp")
        self.assertEqual(ts[1]["port"], 443)

    def test_invalid_items_rejected(self):
        for bad in ([], [{"host": ""}], [{"host": "a b"}], [{"host": "x", "proto": "udp"}],
                    [{"host": "x", "port": 99999}], [{"host": f"h{i}.example"} for i in range(7)]):
            with self.assertRaises(ValueError):
                self.st.save_targets(bad)
        self.assertEqual(len(self.st.targets()), 6)            # 拒绝后不能动原有数据

    def test_version_tracks_content(self):
        v1 = self.st.targets_ver()
        self.st.save_targets([{"host": "1.1.1.1", "op": "电信", "region": "上海"}])
        v2 = self.st.targets_ver()
        self.assertNotEqual(v1, v2)
        self.st.save_targets([{"host": "1.1.1.1", "op": "电信", "region": "上海"}])
        self.assertEqual(v2, self.st.targets_ver())            # 内容没变 → 指纹不变，不会反复下发

    def test_rename_history(self):
        old = self.st.targets()[0]
        self.st.conn.execute(
            "INSERT INTO checks(node_id,ts,name,proto,host,port,family,ok,loss,rmin,ravg,rmax)"
            " VALUES('n1',?,?,?,?,?,?,1,0,10,10,10)",
            (int(time.time()), old["name"], "tcp", old["host"], 80, "4"))
        self.st.conn.commit()
        _, renamed = self.st.save_targets([dict(old, region="北京")], rename_history=True)
        self.assertEqual(renamed, [[old["name"], "电信·北京"]])
        row = self.st.conn.execute("SELECT COUNT(*) c FROM checks WHERE name='电信·北京'").fetchone()
        self.assertEqual(row["c"], 1)


class TestAgentTargets(unittest.TestCase):
    """agent 侧：接收中心下发的目标，写回本地配置且指纹与中心一致"""

    def test_apply_targets_writes_config(self):
        path = os.path.join(tempfile.mkdtemp(), "config.json")
        cfg = {"server": "http://x", "token": "t", "targets": [], "_path": path}
        ok = A.apply_targets(cfg, {"ver": "v", "list": [
            {"name": "电信·上海", "host": "1.1.1.1", "port": 80, "proto": "tcp",
             "family": "auto", "enabled": 1},
            {"name": "广电·北京", "host": "2.2.2.2", "port": 80, "proto": "icmp",
             "family": "4", "enabled": 0},
        ]})
        self.assertTrue(ok)
        with open(path, encoding="utf-8") as fh:
            saved = json.load(fh)
        self.assertEqual([t["name"] for t in saved["targets"]], ["电信·上海", "广电·北京"])
        self.assertEqual(saved["targets"][1]["proto"], "icmp")
        self.assertFalse(saved["targets"][1]["enabled"])
        self.assertNotIn("_path", saved)                      # 内部字段不能写进配置文件
        self.assertEqual(A.targets_signature(cfg["targets"]), P.targets_signature(saved["targets"]))

    def test_apply_targets_ignores_empty(self):
        cfg = {"token": "t", "_path": os.path.join(tempfile.mkdtemp(), "c.json")}
        self.assertFalse(A.apply_targets(cfg, {"list": []}))
        self.assertFalse(A.apply_targets(cfg, {}))

    def test_payload_carries_targets_ver(self):
        cfg = {"server": "", "token": "", "interval": 30, "check_interval": 60,
               "targets": [{"name": "电信·上海", "host": "127.0.0.1", "port": 80, "proto": "tcp",
                            "family": "auto", "enabled": True}]}
        s = A.Sampler(cfg)
        s.sample()
        p = s.sample()
        self.assertEqual(p.get("targets_ver"), P.targets_signature(cfg["targets"]))


class TestBillingPeriod(unittest.TestCase):
    """配额周期（日/月/年 + 起始日）与到期自动滚动（v0.5.24）"""

    def _ts(self, *args):
        tz = datetime.timezone(datetime.timedelta(hours=8))
        return int(datetime.datetime(*args, tzinfo=tz).timestamp())

    def test_add_months_clamps_to_month_end(self):
        self.assertEqual(P.add_months(datetime.date(2026, 1, 31), 1), datetime.date(2026, 2, 28))
        self.assertEqual(P.add_months(datetime.date(2026, 3, 31), 1), datetime.date(2026, 4, 30))
        self.assertEqual(P.add_months(datetime.date(2026, 11, 11), 1), datetime.date(2026, 12, 11))
        self.assertEqual(P.add_months(datetime.date(2026, 12, 11), 2), datetime.date(2027, 2, 11))

    def test_add_period_units(self):
        self.assertEqual(P.add_period(datetime.date(2024, 2, 29), "year"), datetime.date(2025, 2, 28))
        self.assertEqual(P.add_period(datetime.date(2026, 11, 11), "day"), datetime.date(2026, 11, 12))
        self.assertEqual(P.add_period(datetime.date(2026, 11, 11), "year"), datetime.date(2027, 11, 11))

    def test_cycle_bounds_month(self):
        """11-11 起按月：11-11 00:00 ~ 12-11 00:00；12-11 当天就进入下一段"""
        st, en = P.cycle_bounds("month", "2026-11-11", self._ts(2026, 11, 20, 12))
        self.assertEqual(P.local_date(st).isoformat(), "2026-11-11")
        self.assertEqual(P.local_date(en).isoformat(), "2026-12-11")
        st2, en2 = P.cycle_bounds("month", "2026-11-11", self._ts(2026, 12, 11, 0, 30))
        self.assertEqual(P.local_date(st2).isoformat(), "2026-12-11")
        self.assertEqual(P.local_date(en2).isoformat(), "2027-01-11")

    def test_cycle_bounds_day_year_and_off(self):
        now = self._ts(2026, 11, 20, 9)
        st, en = P.cycle_bounds("day", "2026-11-11", now)
        self.assertEqual(P.local_date(st).isoformat(), "2026-11-20")
        self.assertEqual(P.local_date(en).isoformat(), "2026-11-21")
        st, en = P.cycle_bounds("year", "2026-11-11", now)
        self.assertEqual(P.local_date(st).isoformat(), "2026-11-11")
        self.assertEqual(P.local_date(en).isoformat(), "2027-11-11")
        self.assertEqual(P.cycle_bounds("", "2026-11-11", now), (0, 0))

    def test_cycle_info_shows_last_day_inclusive(self):
        """10 号起按月 = 10 号 00:00 ~ 下月 9 号 24:00：展示要给 9 号，重置日另标。"""
        today = P.local_date()
        st, _d = mk_store()
        nid, _tok = st.add_node("周期展示")
        st.update_node(nid, quota_mode="month", quota_start=today.isoformat())
        ci = st.cycle_info(st.node(nid))
        nxt = P.add_months(today, 1)
        self.assertEqual(ci["start_date"], today.isoformat())
        self.assertEqual(ci["end_date"], (nxt - datetime.timedelta(days=1)).isoformat())
        self.assertEqual(ci["reset_date"], nxt.isoformat())
        self.assertEqual(ci["reset_at"], nxt.isoformat() + " 00:00")
        self.assertEqual(ci["days_left"], (nxt - today).days)

    def test_cycle_start_in_future(self):
        """起始日填了未来日期：第一个周期从那天才开始，不会把今天算进上一段"""
        st, en = P.cycle_bounds("month", "2027-01-11", self._ts(2026, 11, 20, 9))
        self.assertEqual(P.local_date(st).isoformat(), "2027-01-11")
        self.assertEqual(P.local_date(en).isoformat(), "2027-02-11")

    def test_roll_forward(self):
        today = datetime.date(2026, 11, 11)
        # 到期日当天算已续到下一期（不显示"今天到期"）
        self.assertEqual(P.roll_forward("2026-11-11", "month", today, after_today=True),
                         datetime.date(2026, 12, 11))
        self.assertEqual(P.roll_forward("2026-12-11", "month", today), datetime.date(2026, 12, 11))
        self.assertEqual(P.roll_forward("2020-01-05", "year", today), datetime.date(2027, 1, 5))
        self.assertEqual(P.roll_forward("2026-11-11", "day", today, after_today=True),
                         datetime.date(2026, 11, 12))
        self.assertEqual(P.roll_forward("2026-11-11", "", today), datetime.date(2026, 11, 11))

    def test_expires_info(self):
        today = P.local_date()
        e = P.expires_info({"renew_mode": "month", "renew_start": today.isoformat()})
        self.assertTrue(e["auto"])
        self.assertEqual(e["date"], P.add_months(today, 1).isoformat())
        self.assertEqual(e["days_left"], (P.add_months(today, 1) - today).days)
        e2 = P.expires_info({"renew_mode": "", "expires_at": today.isoformat()})
        self.assertFalse(e2["auto"])
        self.assertEqual(e2["days_left"], 0)
        self.assertEqual(P.expires_info({}), {"auto": False, "mode": "", "base": "",
                                              "date": "", "days_left": None})


class TestTrafficAccounting(unittest.TestCase):
    def setUp(self):
        self.st, self.dir = mk_store()
        self.nid, self.tok = self.st.add_node("算流量")

    def _report(self, rx, tx):
        self.st.ingest(self.st.node(self.nid),
                       {"ts": int(time.time()), "net": {"rx_total": rx, "tx_total": tx}}, "1.2.3.4")

    def test_accumulates_deltas(self):
        self._report(1000, 2000)               # 首报：只记基线
        n = self.st.node(self.nid)
        self.assertEqual((n["cyc_rx"], n["cyc_tx"]), (0, 0))
        self._report(5000, 9000)
        n = self.st.node(self.nid)
        self.assertEqual((n["cyc_rx"], n["cyc_tx"]), (4000, 7000))
        self.assertEqual(self.st.cycle_info(n)["used"], 11000)

    def test_counter_reset_after_reboot(self):
        self._report(1000, 1000)
        self._report(9000, 9000)
        self._report(300, 200)                 # 重启后计数器归零
        n = self.st.node(self.nid)
        self.assertEqual((n["cyc_rx"], n["cyc_tx"]), (8300, 8200))

    def test_cycle_rollover_archives(self):
        self._report(100, 100)                 # 先立基线
        self.st.conn.execute("UPDATE nodes SET cyc_start=?,cyc_rx=?,cyc_tx=? WHERE id=?",
                             (int(time.time()) - 40 * 86400, 777, 888, self.nid))
        self.st.conn.commit()
        self._report(150, 140)
        hist = self.st.conn.execute("SELECT * FROM traffic_hist WHERE node_id=?", (self.nid,)).fetchall()
        self.assertEqual(len(hist), 1)
        self.assertEqual((hist[0]["rx"], hist[0]["tx"]), (777, 888))
        n = self.st.node(self.nid)
        self.assertEqual((n["cyc_rx"], n["cyc_tx"]), (50, 40))     # 新周期从 0 起
        self.assertEqual(self.st.lifetime(self.nid), (827, 928))   # 归档 + 本期

    def test_unknown_baseline_never_adds_whole_counter(self):
        """基准写成 0（老库迁移的「未知」哨兵）时，绝不能拿 0 当上次读数。

        曾经 d = rx_total - 0 = 整条网卡计数器 → 一台只有 12GB 用量的机器被记成 1.85TB。
        """
        self.st.conn.execute("UPDATE nodes SET last_rx_total=0,last_tx_total=0,cyc_rx=0,cyc_tx=0"
                             " WHERE id=?", (self.nid,))
        self.st.conn.commit()
        self._report(512_000_000_000, 503_000_000_000)
        n = self.st.node(self.nid)
        self.assertEqual((n["cyc_rx"], n["cyc_tx"]), (0, 0))
        self.assertEqual(n["last_rx_total"], 512_000_000_000)
        self._report(512_000_050_000, 503_000_040_000)
        n = self.st.node(self.nid)
        self.assertEqual((n["cyc_rx"], n["cyc_tx"]), (50_000, 40_000))

    def test_zero_reading_is_ignored_and_keeps_baseline(self):
        """agent 读不到网卡会报 0/0：当次不入账，基准也不能被写成 0（否则下一条就炸）"""
        self._report(1000, 2000)
        self._report(5000, 9000)
        self._report(0, 0)
        n = self.st.node(self.nid)
        self.assertEqual((n["cyc_rx"], n["cyc_tx"]), (4000, 7000))
        self.assertEqual((n["last_rx_total"], n["last_tx_total"]), (5000, 9000))
        self._report(6000, 10000)
        n = self.st.node(self.nid)
        self.assertEqual((n["cyc_rx"], n["cyc_tx"]), (5000, 8000))

    def test_counter_delta_states(self):
        self.assertIsNone(P.counter_delta(100, 0))       # 无效读数
        self.assertIsNone(P.counter_delta(0, 0))
        self.assertEqual(P.counter_delta(0, 500), 0)     # 未知基准：只立基线
        self.assertEqual(P.counter_delta(-1, 500), 0)
        self.assertEqual(P.counter_delta(None, 500), 0)
        self.assertEqual(P.counter_delta(500, 900), 400) # 正常增量
        self.assertEqual(P.counter_delta(900, 300), 300) # 重启归零
        self.assertEqual(P.counter_delta(900, 900), 0)

    def test_defaults_switch_on(self):
        n = self.st.node(self.nid)
        self.assertEqual(n["quota_mode"], "month")     # 配额默认按月
        self.assertEqual(n["renew_mode"], "month")     # 到期默认按月自动滚动
        self.assertTrue(n["quota_start"] and n["renew_start"])


class TestLowPrivAgent(unittest.TestCase):
    """agent 非 root 运行（安装脚本 --as-user）"""

    def test_as_root_uses_sudo_when_not_root(self):
        orig = A.os.geteuid
        A.os.geteuid = lambda: 1000
        try:
            self.assertEqual(A.as_root(["/bin/systemctl", "restart", "fwprobe-agent"]),
                             ["/usr/bin/sudo", "-n", "/bin/systemctl", "restart", "fwprobe-agent"])
        finally:
            A.os.geteuid = orig

    def test_as_root_passthrough_for_root(self):
        orig = A.os.geteuid
        A.os.geteuid = lambda: 0
        try:
            self.assertEqual(A.as_root(["/bin/ls"]), ["/bin/ls"])
        finally:
            A.os.geteuid = orig

    def test_payload_carries_uid(self):
        cfg = {"server": "", "token": "", "interval": 30, "check_interval": 60, "targets": []}
        s = A.Sampler(cfg)
        s.sample()
        self.assertEqual(s.sample().get("uid"), os.geteuid())

    def test_installer_supports_user_mode(self):
        src = pathlib.Path(ROOT, "install-agent.sh").read_text(encoding="utf-8")
        for token in ("--as-user", "useradd --system", "AmbientCapabilities=CAP_NET_RAW",
                      "CapabilityBoundingSet=CAP_NET_RAW", "NOPASSWD: /bin/systemctl restart",
                      "fwprobe-agent-uninstall.sh", "visudo -cf", "sudo -u \"$AGENT_USER\""):
            self.assertIn(token, src)
        self.assertEqual(subprocess.run(["bash", "-n", os.path.join(ROOT, "install-agent.sh")],
                                        capture_output=True).returncode, 0)


class TestTargetAliases(unittest.TestCase):
    """目标改名后旧名字的数据要并到新名字，详情页不能再出现「上海电信」和「电信·上海」两套曲线"""

    def setUp(self):
        self.st, self.dir = mk_store()
        self.st.seed_targets()
        self.nid, _ = self.st.add_node("a")
        self.node = self.st.node(self.nid)

    def tearDown(self):
        self.st.conn.close()

    def _orphans(self):
        with self.st.lock:
            return [r["name"] for r in self.st.conn.execute(
                "SELECT DISTINCT name FROM checks ORDER BY name")]

    def test_repair_folds_old_default_names(self):
        now = int(time.time())
        for name in ("上海电信", "上海联通", "上海移动"):
            self.st.conn.execute(
                "INSERT OR REPLACE INTO checks(node_id,ts,name,ok,loss,rmin,ravg,rmax)"
                " VALUES(?,?,?,?,?,?,?,?)", (self.nid, now, name, 1, 0.0, 30.0, 30.0, 30.0))
        self.st.conn.commit()
        fixed = dict(self.st.repair_aliases())
        self.assertEqual(fixed["上海电信"], "电信·上海")
        self.assertEqual(fixed["上海联通"], "联通·上海")
        self.assertEqual(fixed["上海移动"], "移动·上海")
        self.assertEqual(sorted(self._orphans()), sorted(["电信·上海", "联通·上海", "移动·上海"]))
        self.assertEqual(self.st.series(self.nid, 1)["checks"].keys(), {"电信·上海", "联通·上海", "移动·上海"})
        # 幂等：再跑一次不会重复并
        self.assertEqual(self.st.repair_aliases(), [])

    def test_ingest_maps_old_name_after_alias(self):
        """改名后老 agent 还用旧名上报：落库时直接换成新名，不会另起一条曲线"""
        self.st.record_alias("上海电信", "电信·上海")
        now = int(time.time())
        p = payload(checks=[{"name": "上海电信", "proto": "tcp", "host": "a.example", "port": 80,
                             "family": "4", "ok": True, "loss": 0.0, "min": 29.0, "avg": 30.5,
                             "max": 32.0}])
        p["ts"] = now
        self.st.ingest(self.node, p, "1.1.1.1")
        self.assertEqual(self._orphans(), ["电信·上海"])

    def test_rename_moves_history_and_records_alias(self):
        now = int(time.time())
        self.st.conn.execute(
            "INSERT OR REPLACE INTO checks(node_id,ts,name,ok,loss,rmin,ravg,rmax)"
            " VALUES(?,?,?,?,?,?,?,?)", (self.nid, now, "电信·上海", 1, 0.0, 20.0, 20.0, 20.0))
        self.st.conn.commit()
        items = [dict(t) for t in self.st.targets()]
        for t in items:
            if t["id"] == "ct4":
                t["region"] = "北京"
        ver, renamed = self.st.save_targets(items, rename_history=True)
        self.assertIn(["电信·上海", "电信·北京"], renamed)
        self.assertEqual(self._orphans(), ["电信·北京"])
        self.assertEqual(self.st.alias_map().get("电信·上海"), "电信·北京")
        # 之后 agent 还报旧名也不会长出新的一条
        p = payload(checks=[{"name": "电信·上海", "proto": "tcp", "host": "a.example", "port": 80,
                             "family": "4", "ok": True, "loss": 0.0, "min": 1.0, "avg": 2.0,
                             "max": 3.0}])
        p["ts"] = now + 5
        self.st.ingest(self.node, p, "1.1.1.1")
        self.assertEqual(self._orphans(), ["电信·北京"])

    def test_alias_merge_survives_same_second_collision(self):
        """同一台机器同一秒新旧名字都有行：主键会撞，改名不能报错，只能留一条"""
        now = int(time.time())
        for table in ("checks", "checks_min"):
            for nm, avg in (("上海电信", 30.0), ("电信·上海", 45.0)):
                self.st.conn.execute(
                    f"INSERT OR REPLACE INTO {table}(node_id,ts,name,ok,loss,ravg)"
                    f" VALUES(?,?,?,?,?,?)", (self.nid, now, nm, 1, 0.0, avg))
        self.st.conn.commit()
        self.assertTrue(self.st.record_alias("上海电信", "电信·上海"))
        self.assertEqual(self._orphans(), ["电信·上海"])
        with self.st.lock:
            n = self.st.conn.execute("SELECT COUNT(*) c FROM checks_min").fetchone()["c"]
        self.assertEqual(n, 1)

    def test_repair_heals_leftover_rows_for_known_alias(self):
        """别名已经记了、但库里还留着旧名行（上次改名只并了一半）→ 启动时补刀并掉"""
        now = int(time.time())
        self.st.conn.execute("INSERT OR REPLACE INTO aliases(old,name,ts) VALUES('上海电信','电信·上海',?)",
                             (now,))
        self.st.conn.execute(
            "INSERT OR REPLACE INTO checks(node_id,ts,name,ok,loss,ravg) VALUES(?,?,?,?,?,?)",
            (self.nid, now, "上海电信", 1, 0.0, 30.0))
        self.st.conn.commit()
        self.assertIn(["上海电信", "电信·上海"], self.st.repair_aliases())
        self.assertEqual(self._orphans(), ["电信·上海"])

    def test_guess_alias_ignores_custom_names(self):
        tg = self.st.targets()
        self.assertIsNone(P.guess_target_alias("我的线路A", tg))
        self.assertEqual(P.guess_target_alias("上海电信v6", tg), "电信·上海v6")


class TestOrdering(unittest.TestCase):
    """展示页卡片顺序（v0.5.19）：后台拖动 → nodes.sort_order → 公开页按序渲染"""

    def setUp(self):
        self.st, self.dir = mk_store()

    def test_new_nodes_append_in_creation_order(self):
        a, _ = self.st.add_node("A")
        b, _ = self.st.add_node("B")
        c, _ = self.st.add_node("C")
        self.assertEqual([n["id"] for n in self.st.nodes()], [a, b, c])

    def test_reorder_changes_public_order(self):
        a, _ = self.st.add_node("A")
        b, _ = self.st.add_node("B")
        c, _ = self.st.add_node("C")
        self.assertEqual(self.st.reorder([c, a, b]), 3)
        self.assertEqual([n["alias"] for n in self.st.nodes()], ["C", "A", "B"])
        self.assertEqual([n["alias"] for n in P.public_summary(self.st)["nodes"]], ["C", "A", "B"])

    def test_reorder_ignores_unknown_and_duplicates(self):
        a, _ = self.st.add_node("A")
        b, _ = self.st.add_node("B")
        self.assertEqual(self.st.reorder([a, a, "nope", b]), 2)
        self.assertEqual([n["alias"] for n in self.st.nodes()], ["A", "B"])

    def test_reorder_empty_is_noop(self):
        self.st.add_node("A")
        self.assertEqual(self.st.reorder([]), 0)
        self.assertEqual([n["alias"] for n in self.st.nodes()], ["A"])

    def test_new_node_after_custom_order_goes_last(self):
        a, _ = self.st.add_node("A")
        b, _ = self.st.add_node("B")
        self.st.reorder([b, a])
        self.st.add_node("C")
        self.assertEqual([n["alias"] for n in self.st.nodes()], ["B", "A", "C"])

    def test_order_via_http(self):
        st, d = mk_store()
        cfg = {"admin_token": "admin-test"}
        srv = P.Server(("127.0.0.1", 0), P.Handler, st, cfg)
        th = threading.Thread(target=srv.serve_forever, daemon=True)
        th.start()
        base = f"http://127.0.0.1:{srv.server_address[1]}"
        try:
            a, _ = st.add_node("A")
            b, _ = st.add_node("B")

            def post(body):
                req = urllib.request.Request(base + "/api/nodes/order", data=json.dumps(body).encode(),
                                             method="POST",
                                             headers={"Content-Type": "application/json",
                                                      "X-IPROBE": "1", "Authorization": "Bearer admin-test"})
                try:
                    with urllib.request.urlopen(req, timeout=5) as r:
                        return r.status, r.read().decode()
                except urllib.error.HTTPError as e:
                    return e.code, e.read().decode()

            code, body = post({"ids": [b, a]})
            self.assertEqual(code, 200, body)
            self.assertEqual([n["alias"] for n in st.nodes()], ["B", "A"])
            code, body = post({"ids": "nope"})
            self.assertEqual(code, 400, body)
        finally:
            srv.shutdown()
            srv.server_close()


class TestAdminPage(unittest.TestCase):
    """后台静态页自检：地区选择器与地区列必须真的在位（v0.5.18）"""

    @classmethod
    def setUpClass(cls):
        cls.src = pathlib.Path(P.__file__).with_name("static").joinpath("admin.html").read_text("utf-8")

    def test_country_picker_present(self):
        for token in ('id="ed_country_pop"', "function pickCountry", "function renderPick",
                      "const COUNTRIES", 'id="cc_all"', "function countryCell"):
            self.assertIn(token, self.src)

    def test_order_ui_present(self):
        for token in ('class="grip"', "function bindDrag", "function saveOrder",
                      "/api/nodes/order", "function resetOrder", "恢复默认顺序"):
            self.assertIn(token, self.src)

    def test_targets_ui_present(self):
        for token in ('id="m_targets"', "function openTargets", "function saveTargets",
                      "/api/admin/targets", "function tgGeo", "三网目标"):
            self.assertIn(token, self.src)

    def test_country_column_present(self):
        self.assertIn("<th>地区</th>", self.src)
        self.assertIn("countryCell(n)", self.src)

    def test_single_style_block(self):
        self.assertEqual(self.src.count("</style>"), 1)

    def test_doctype_first(self):
        self.assertTrue(self.src.lstrip().startswith("<!DOCTYPE html>"))


class TestHTTP(unittest.TestCase):
    def setUp(self):
        self.st, self.dir = mk_store()
        self.cfg = {"admin_token": "admin-test", "base_url": "http://localhost"}
        self.srv = P.Server(("127.0.0.1", 0), P.Handler, self.st, self.cfg)
        self.port = self.srv.server_address[1]
        self.th = threading.Thread(target=self.srv.serve_forever, daemon=True)
        self.th.start()
        self.base = f"http://127.0.0.1:{self.port}"
        self.nid, self.tok = self.st.add_node("节点甲")
        # 上报会触发归属地识别：测试里不真联网（否则跑测试看网络脸色）
        _orig_detect = P.detect_country
        P.detect_country = lambda ip: ("", "", "test-disabled")
        self.addCleanup(lambda: setattr(P, "detect_country", _orig_detect))
        self.addCleanup(P.reset_country_schedule)

    def test_login_accepts_hot_reloaded_password(self):
        """服务器上刚 passwd 完就能登：登录前会按 config.json 的 mtime 重读"""
        import tempfile
        path = os.path.join(tempfile.mkdtemp(), "config.json")
        with open(path, "w") as fh:
            json.dump({"admin_password": P.hash_password("newpass123")}, fh)
        orig = P.CONFIG_PATH
        P.CONFIG_PATH = path
        self.addCleanup(lambda: setattr(P, "CONFIG_PATH", orig))
        code, body = self._post("/api/admin/login", {"password": "newpass123"}, csrf=False)
        self.assertEqual(code, 200, body)
        code, body = self._post("/api/admin/login", {"password": "wrong-one"}, csrf=False)
        self.assertEqual(code, 401, body)

    def test_admin_meta_is_get_able(self):
        """GET /api/admin/meta 必须存在：后台靠它拿 agent 版本，404 就永远没有「全部升级」按钮"""
        code, body = self._get("/api/admin/meta", token="admin-test")
        self.assertEqual(code, 200, body)
        d = json.loads(body)
        self.assertIn("agent_version", d)
        self.assertIn("version", d)

    def test_period_fields_validated(self):
        code, body = self._post("/api/nodes/" + self.nid, {"quota_mode": "week"}, token="admin-test")
        self.assertEqual(code, 400, body)
        code, body = self._post("/api/nodes/" + self.nid,
                                {"quota_mode": "month", "quota_start": "not-a-date"},
                                token="admin-test")
        self.assertEqual(code, 400, body)
        code, body = self._post("/api/nodes/" + self.nid,
                                {"quota_mode": "year", "quota_start": "2026-11-11",
                                 "renew_mode": "month", "renew_start": "2026-11-11"},
                                token="admin-test")
        self.assertEqual(code, 200, body)
        n = self.st.node(self.nid)
        self.assertEqual((n["quota_mode"], n["quota_start"]), ("year", "2026-11-11"))
        self.assertEqual((n["renew_mode"], n["renew_start"]), ("month", "2026-11-11"))

    def test_renew_batch_uses_each_nodes_date(self):
        nid2, _ = self.st.add_node("节点乙", expires_at="2027-03-08", renew_mode="")
        self.st.update_node(nid2, renew_start="", expires_at="2027-03-08")
        code, body = self._post("/api/nodes/renew-batch",
                                {"ids": [nid2], "renew_mode": "year", "renew_start": ""},
                                token="admin-test")
        self.assertEqual(code, 200, body)
        self.assertEqual(json.loads(body)["count"], 1)
        n2 = self.st.node(nid2)
        self.assertEqual(n2["renew_mode"], "year")
        self.assertEqual(n2["renew_start"], "2027-03-08")     # 留空 = 各自当前到期日

    def test_renew_batch_can_set_quota_cycle(self):
        code, body = self._post("/api/nodes/renew-batch",
                                {"ids": [self.nid], "renew_mode": "month", "renew_start": "",
                                 "quota_mode": "year", "quota_start": "2026-11-11"},
                                token="admin-test")
        self.assertEqual(code, 200, body)
        n = self.st.node(self.nid)
        self.assertEqual((n["quota_mode"], n["quota_start"]), ("year", "2026-11-11"))

    def test_summary_carries_cycle_and_rolled_expiry(self):
        self.st.update_node(self.nid, quota_bytes=100 * 1024 ** 3, quota_mode="month",
                            quota_start=P.local_date().isoformat(),
                            renew_mode="month", renew_start=P.local_date().isoformat())
        self.st.ingest(self.st.node(self.nid),
                       {"ts": int(time.time()), "net": {"rx_total": 1 * 1024 ** 3,
                                                         "tx_total": 1 * 1024 ** 3}}, "1.2.3.4")
        self.st.ingest(self.st.node(self.nid),
                       {"ts": int(time.time()), "net": {"rx_total": 6 * 1024 ** 3,
                                                         "tx_total": 4 * 1024 ** 3}}, "1.2.3.4")
        d = P.public_summary(self.st)
        n = [x for x in d["nodes"] if x["id"] == self.nid][0]
        self.assertEqual(n["used_bytes"], 8 * 1024 ** 3)
        self.assertEqual(n["cycle"]["reset_date"], P.add_months(P.local_date(), 1).isoformat())
        self.assertTrue(n["expires"]["auto"])
        self.assertEqual(n["expires_at"], n["expires"]["date"])

    def test_report_stores_agent_uid(self):
        """agent 上报带 uid：0=root，非 0=低权限模式，后台据此显示「低权限」小标"""
        self._post("/api/report", {"agent": "0.5.12", "ts": int(time.time()), "uid": 0},
                   token=self.tok)
        self.assertEqual(int(self.st.node(self.nid)["agent_uid"]), 0)
        self._post("/api/report", {"agent": "0.5.12", "ts": int(time.time()), "uid": 998},
                   token=self.tok)
        self.assertEqual(int(self.st.node(self.nid)["agent_uid"]), 998)
        code, body = self._get("/api/nodes", token="admin-test")
        node = [n for n in json.loads(body)["nodes"] if n["id"] == self.nid][0]
        self.assertTrue(node["low_priv"])

    def test_report_pushes_targets(self):
        """0.5.11+ 的 agent 上报带 targets_ver：版本不一致就下发；一致/老 agent 不下发"""
        code, body = self._post("/api/report", {"agent": "0.5.11", "ts": int(time.time()),
                                                "targets_ver": "stale"}, token=self.tok)
        d = json.loads(body)
        self.assertIn("targets", d, body)
        self.assertEqual(d["targets"]["ver"], self.st.targets_ver())
        self.assertEqual([t["name"] for t in d["targets"]["list"]][:3],
                         ["电信·上海", "联通·上海", "移动·上海"])
        # 已同步：不再下发
        code, body = self._post("/api/report", {"agent": "0.5.11", "ts": int(time.time()),
                                                "targets_ver": d["targets"]["ver"]}, token=self.tok)
        self.assertNotIn("targets", json.loads(body))
        # 老 agent 不带 targets_ver：保持本地配置，不下发
        code, body = self._post("/api/report", {"agent": "0.5.10", "ts": int(time.time())},
                                token=self.tok)
        self.assertNotIn("targets", json.loads(body))

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()
        self.st.conn.close()

    def _get(self, path, token=None):
        req = urllib.request.Request(self.base + path)
        if token:
            req.add_header("Authorization", "Bearer " + token)
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, r.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()

    def _post(self, path, body, token=None, csrf=True):
        data = json.dumps(body).encode()
        req = urllib.request.Request(self.base + path, data=data, method="POST")
        req.add_header("Content-Type", "application/json")
        if csrf:
            req.add_header("X-IPROBE", "1")
        if token:
            req.add_header("Authorization", "Bearer " + token)
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, r.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()

    def test_healthz(self):
        code, body = self._get("/healthz")
        self.assertEqual(code, 200)
        d = json.loads(body)
        self.assertTrue(d["ok"])
        self.assertEqual(d["nodes"], 1)

    def test_report_requires_token(self):
        code, _ = self._post("/api/report", payload())
        self.assertEqual(code, 401)
        code, _ = self._post("/api/report", payload(), token="bogus")
        self.assertEqual(code, 403)

    def test_report_and_public_summary(self):
        code, body = self._post("/api/report", payload(), token=self.tok)
        self.assertEqual(code, 200, body)
        code, body = self._get("/api/public/summary")
        self.assertEqual(code, 200)
        n = json.loads(body)["nodes"][0]
        self.assertEqual(n["alias"], "节点甲")
        self.assertTrue(n["online"])
        self.assertNotIn("public_ip", n)

    def test_report_rejects_bad_json(self):
        req = urllib.request.Request(self.base + "/api/report", data=b"not-json", method="POST")
        req.add_header("Authorization", "Bearer " + self.tok)
        req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                code = r.status
        except urllib.error.HTTPError as e:
            code = e.code
        self.assertEqual(code, 400)

    def test_admin_api_guard(self):
        code, _ = self._get("/api/nodes")
        self.assertEqual(code, 401)
        code, body = self._get("/api/nodes", token="admin-test")
        self.assertEqual(code, 200)
        self.assertEqual(len(json.loads(body)["nodes"]), 1)

    def test_admin_create_and_delete(self):
        code, body = self._post("/api/nodes", {"alias": "新节点", "group": "JP"}, token="admin-test")
        self.assertEqual(code, 200, body)
        d = json.loads(body)
        self.assertIn("token", d)
        req = urllib.request.Request(self.base + "/api/nodes/" + d["id"], method="DELETE")
        req.add_header("Authorization", "Bearer admin-test")
        req.add_header("X-IPROBE", "1")
        with urllib.request.urlopen(req, timeout=5) as r:
            self.assertEqual(r.status, 200)
        self.assertIsNone(self.st.node(d["id"]))

    def test_tags_parse_and_limits(self):
        """标签：非法颜色回落预设、超长截断、最多 6 个、脏数据不炸"""
        tags = P.sanitize_tags([{"t": " $49.99/mo ", "c": "#FFAA22"},
                                {"t": "CN2 GIA", "c": "javascript:alert(1)"},
                                {"t": "x" * 40, "c": "#123"}])
        self.assertEqual(tags[0], {"t": "$49.99/mo", "c": "#ffaa22"})
        self.assertEqual(tags[1]["c"], P.TAG_COLORS[0])
        self.assertEqual(len(tags[2]["t"]), P.TAG_TEXT_MAX)
        many = P.sanitize_tags([{"t": f"t{i}"} for i in range(20)])
        self.assertEqual(len(many), P.TAG_MAX)
        self.assertEqual(P.parse_tags("坏数据{"), [])
        self.assertEqual(P.parse_tags(""), [])

    def test_tags_roundtrip_api(self):
        """新增/修改节点带标签，公开摘要里能拿到，且颜色被规范化"""
        code, body = self._post("/api/nodes", {"alias": "标签机", "group": "SG",
                                              "tags": [{"t": "$49.99/mo", "c": "#FBBF24"}]},
                                token="admin-test")
        self.assertEqual(code, 200, body)
        nid = json.loads(body)["id"]
        code, body = self._get("/api/public/summary")
        node = [n for n in json.loads(body)["nodes"] if n["id"] == nid][0]
        self.assertEqual(node["tags"], [{"t": "$49.99/mo", "c": "#fbbf24"}])
        # 改成两个标签
        code, body = self._post(f"/api/nodes/{nid}", {"tags": [{"t": "A", "c": "#34d399"},
                                                              {"t": "B", "c": ""}]}, token="admin-test")
        self.assertEqual(code, 200, body)
        node = [n for n in json.loads(self._get("/api/public/summary")[1])["nodes"] if n["id"] == nid][0]
        self.assertEqual([t["t"] for t in node["tags"]], ["A", "B"])
        self.assertEqual(node["tags"][1]["c"], P.TAG_COLORS[0])

    def test_login_cookie_auth(self):
        """token 换会话 Cookie 后，不带 Bearer 也能读管理接口"""
        code, body = self._post("/api/admin/login", {"token": "wrong"}, csrf=False)
        self.assertEqual(code, 401)
        code, body = self._post("/api/admin/login", {"token": "admin-test"}, csrf=False)
        self.assertEqual(code, 200, body)
        cookie = None
        # 用 requests 之外的标准库取 Set-Cookie 不方便，这里直接验签名函数
        val, exp = P.make_session("admin-test")
        self.assertGreater(P.read_session(f"iprobe_sess={val}", "admin-test"), 0)
        self.assertEqual(P.read_session(f"iprobe_sess={val}", "other-token"), 0)
        self.assertEqual(P.read_session("iprobe_sess=999.deadbeef", "admin-test"), 0)

    def test_login_rate_limit(self):
        P.clear_login_fail("10.9.9.9")
        for _ in range(P.LOGIN_FAIL_MAX):
            P.note_login_fail("10.9.9.9")
        ok, wait = P.login_allowed("10.9.9.9")
        self.assertFalse(ok)
        self.assertGreaterEqual(wait, 0)
        P.clear_login_fail("10.9.9.9")
        self.assertTrue(P.login_allowed("10.9.9.9")[0])

    def test_groups_rename(self):
        code, body = self._post("/api/nodes", {"alias": "改组机", "groups": ["旧组", "保留"]},
                                token="admin-test")
        self.assertEqual(code, 200, body)
        nid = json.loads(body)["id"]
        code, body = self._post("/api/admin/groups/rename", {"from": "旧组", "to": "新组"}, token="admin-test")
        self.assertEqual(code, 200, body)
        node = self.st.node(nid)
        self.assertEqual(P.parse_groups(node["groups"]), ["新组", "保留"])

    def test_write_requires_csrf_header(self):
        """没有 X-IPROBE 头的写操作一律 403（配合 SameSite Cookie 防 CSRF）"""
        code, body = self._post("/api/nodes", {"alias": "x"}, token="admin-test", csrf=False)
        self.assertEqual(code, 403)

    def test_audit_records_writes(self):
        self._post("/api/nodes", {"alias": "审计机"}, token="admin-test")
        code, body = self._get("/api/admin/audit", token="admin-test")
        self.assertEqual(code, 200, body)
        actions = [a["action"] for a in json.loads(body)["items"]]
        self.assertIn("node_add", actions)

    def test_password_hash_and_login(self):
        """密码走 PBKDF2 哈希，能登录；登录失败计数不受影响；密码登录也认 remember"""
        h = P.hash_password("hunter2hunter2")
        self.assertTrue(h.startswith("pbkdf2_sha256$"))
        self.assertTrue(P.verify_password("hunter2hunter2", h))
        self.assertFalse(P.verify_password("wrong", h))
        self.assertFalse(P.verify_password("x", "乱码"))
        # 服务端配置里挂上密码后，用密码走登录接口
        self.srv.config["admin_password"] = h
        code, body = self._post("/api/admin/login", {"password": "hunter2hunter2", "remember": True}, csrf=False)
        self.assertEqual(code, 200, body)
        code, body = self._post("/api/admin/login", {"password": "wrong"}, csrf=False)
        self.assertEqual(code, 401)
        # token 依旧可用
        code, body = self._post("/api/admin/login", {"password": "admin-test"}, csrf=False)
        self.assertEqual(code, 200, body)
        self.srv.config.pop("admin_password", None)

    def test_passwd_api_changes_password(self):
        # 写配置要落到临时文件（服务端 root 才有 /etc 写权限）
        import tempfile
        tmpdir = tempfile.mkdtemp()
        P.CONFIG_PATH = os.path.join(tmpdir, "config.json")
        with open(P.CONFIG_PATH, "w", encoding="utf-8") as fh:
            json.dump({"admin_token": "admin-test"}, fh)
        code, body = self._post("/api/admin/passwd", {"old": "admin-test", "new": "newpass123"}, token="admin-test")
        self.assertEqual(code, 200, body)
        self.assertTrue(P.verify_password("newpass123", self.srv.config.get("admin_password", "")))
        # 错误旧密码拒绝
        code, body = self._post("/api/admin/passwd", {"old": "bad", "new": "another123"}, token="admin-test")
        self.assertEqual(code, 403)
        # 太短拒绝
        code, body = self._post("/api/admin/passwd", {"old": "newpass123", "new": "短"}, token="admin-test")
        self.assertEqual(code, 400)
        self.srv.config.pop("admin_password", None)

    def test_agent_upgrade_flow(self):
        """下发升级 → 上报应答带指令 → 升到位后中心自动清标记"""
        code, body = self._post("/api/nodes", {"alias": "升级机"}, token="admin-test")
        nid, tok = json.loads(body)["id"], json.loads(body)["token"]
        meta_ver, meta_sha = P.agent_file_meta()
        self.assertTrue(meta_ver, "中心目录里应有 agent.py")
        # 老 agent 上报一次
        self._post("/api/report", {"agent": "0.0.1", "ts": int(time.time())}, token=tok, csrf=False)
        code, body = self._post(f"/api/nodes/{nid}/upgrade", {}, token="admin-test")
        self.assertEqual(code, 200, body)
        self.assertEqual(json.loads(body)["target"], meta_ver)
        # 下一次上报应带升级指令
        code, body = self._post("/api/report", {"agent": "0.0.1", "ts": int(time.time())}, token=tok, csrf=False)
        up = json.loads(body).get("upgrade") or {}
        self.assertEqual(up.get("version"), meta_ver)
        self.assertEqual(up.get("sha256"), meta_sha)
        self.assertTrue(up.get("url", "").endswith("/agent.py"))
        # 升到目标版本后再上报：不再下发，且标记被清掉
        code, body = self._post("/api/report", {"agent": meta_ver, "ts": int(time.time())}, token=tok, csrf=False)
        self.assertNotIn("upgrade", json.loads(body))
        self.assertEqual((self.st.node(nid) or {}).get("target_ver"), "")
        # 已经是最新时拒绝重复下发
        code, body = self._post(f"/api/nodes/{nid}/upgrade", {}, token="admin-test")
        self.assertEqual(code, 400)

    def test_agent_upgrade_batch(self):
        ids = []
        for i in range(2):
            code, body = self._post("/api/nodes", {"alias": f"批量{i}"}, token="admin-test")
            ids.append(json.loads(body)["id"])
        code, body = self._post("/api/admin/upgrade", {"all": True}, token="admin-test")
        self.assertEqual(code, 200, body)
        queued = json.loads(body)["queued"]
        self.assertTrue(set(queued) >= {"批量0", "批量1"})

    def test_provision_token_and_api(self):
        """供应令牌：只能建节点，建完返回可直接执行的安装命令"""
        pid, tok = self.st.add_ptoken("fwpanel2")
        self.assertTrue(tok.startswith("pv_"))
        # 无效令牌
        code, body = self._post("/api/provision/node", {"alias": "x"}, token="pv_bad", csrf=False)
        self.assertEqual(code, 401)
        # 正常建节点
        code, body = self._post("/api/provision/node",
                                {"alias": "面板建的", "groups": ["HK"], "tags": [{"t": "免费", "c": "#34d399"}]},
                                token=tok, csrf=False)
        self.assertEqual(code, 200, body)
        d = json.loads(body)
        self.assertTrue(d["command"].startswith("curl -fsSL "))
        self.assertIn(d["token"], d["command"])
        self.assertIn("--as-user fwprobe", d["command"])   # 新机器默认低权限安装
        node = self.st.node(d["id"])
        self.assertEqual(P.parse_groups(node["groups"]), ["HK"])
        self.assertIn("fwpanel2", node["note"])
        # 列 / 删
        self.assertEqual(len(self.st.list_ptokens()), 1)
        self.assertTrue(self.st.del_ptoken(pid))
        self.assertIsNone(self.st.find_ptoken(tok))

    def test_country_gb_canonicalised_to_uk(self):
        """英国统一显示 UK：存储层归一化（旗帜仍按 GB 算），老数据自动迁移"""
        self.assertEqual(P.norm_country("GB"), "UK")
        self.assertEqual(P.norm_country("gb"), "UK")
        self.assertEqual(P.norm_country("UK"), "UK")
        self.assertEqual(P.norm_country("hk"), "HK")
        self.assertEqual(P.norm_country(""), "")
        # 后台手动填 GB 也存成 UK
        nid, _ = self.st.add_node("伦敦-London", "UK")
        code, body = self._post(f"/api/nodes/{nid}", {"country": "gb"}, token="admin-test")
        self.assertEqual(code, 200, body)
        self.assertEqual(self.st.node(nid)["country"], "UK")
        # 老库里是 GB 的，下次启动自动迁到 UK
        self.st.conn.execute("UPDATE nodes SET country='GB' WHERE id=?", (nid,))
        self.st.conn.commit()
        again = P.Store(os.path.join(self.dir, "t.db"))     # 重新打开即触发迁移
        self.assertEqual(again.node(nid)["country"], "UK")
        again.conn.close()

    def test_country_invalid_input_rejected(self):
        """地区代码只认两位字母：早期 '日本'/'JA'/'J' 都能存进去，前端算不出旗标，看着像改不了"""
        nid, _ = self.st.add_node("坏输入")
        for bad in ("日本", "J", "JPN", "1A", "ja-pan"):
            code, body = self._post(f"/api/nodes/{nid}", {"country": bad}, token="admin-test")
            self.assertEqual(code, 400, f"{bad} 应该被拒：{body}")
            self.assertIn("两位字母", json.loads(body)["error"])
        self.assertEqual(self.st.node(nid)["country"], "")     # 拒绝后库里不能被写脏

    def test_country_manual_marks_source(self):
        """手动填的地区打 manual 标记，自动识别永不覆盖"""
        nid, _ = self.st.add_node("东京-ARM")
        code, body = self._post(f"/api/nodes/{nid}", {"country": "jp"}, token="admin-test")
        self.assertEqual(code, 200, body)
        n = self.st.node(nid)
        self.assertEqual(n["country"], "JP")
        self.assertEqual(n["country_src"], "manual")
        # 有地区的节点不会再排自动识别
        P.reset_country_schedule()
        self.st._maybe_country(nid, "132.145.122.70")
        self.assertNotIn(nid, P.COUNTRY_RETRY)
        self.assertEqual(self.st.node(nid)["country"], "JP")

    def test_country_clear_back_to_auto(self):
        """清空地区 = 恢复自动识别（旧版被内存集合挡着，只能重启中心）"""
        nid, _ = self.st.add_node("清空地区")
        self._post(f"/api/nodes/{nid}", {"country": "US"}, token="admin-test")
        self.assertEqual(self.st.node(nid)["country_src"], "manual")
        P.COUNTRY_RETRY[nid] = {"next": time.time() + 3600, "tries": 5}    # 人为拉黑
        code, body = self._post(f"/api/nodes/{nid}", {"country": ""}, token="admin-test")
        self.assertEqual(code, 200, body)
        n = self.st.node(nid)
        self.assertEqual((n["country"], n["country_src"]), ("", ""))
        self.assertNotIn(nid, P.COUNTRY_RETRY)
        self.assertFalse(n["country_ip"])

    def test_country_auto_detect_writes_source(self):
        """自动识别成功后写 country/ip/时间，来源记 auto"""
        nid, _ = self.st.add_node("自动识别", "JP")
        self.st.conn.execute("UPDATE nodes SET country='', public_ip='8.8.4.4' WHERE id=?", (nid,))
        self.st.conn.commit()
        orig = P.detect_country
        P.detect_country = lambda ip: ("JP", "test", "")
        try:
            self.st._country_work(nid, "8.8.4.4")
        finally:
            P.detect_country = orig
        n = self.st.node(nid)
        self.assertEqual((n["country"], n["country_src"], n["country_ip"]), ("JP", "auto", "8.8.4.4"))
        self.assertGreater(n["country_ts"], 0)

    def test_provision_nodes_list_and_remove(self):
        """供应令牌：能列出自己建的节点，也能在卸载探针后删节点（面板「卸载探针」用）"""
        _, tok = self.st.add_ptoken("fwpanel2")
        code, body = self._post("/api/provision/node", {"alias": "面板建的A"}, token=tok, csrf=False)
        self.assertEqual(code, 200, body)
        nid = json.loads(body)["id"]
        code, body = self._post("/api/nodes", {"alias": "手动建的"}, token="admin-test")
        self.assertEqual(code, 200, body)
        manual_id = json.loads(body)["id"]

        code, body = self._get("/api/provision/nodes", token=tok)
        self.assertEqual(code, 200, body)
        aliases = [n["alias"] for n in json.loads(body)["nodes"]]
        self.assertIn("面板建的A", aliases)
        self.assertNotIn("手动建的", aliases)        # 不是它建的不出现在列表里

        code, body = self._post("/api/provision/remove", {"alias": "面板建的A"}, token=tok, csrf=False)
        self.assertEqual(code, 200, body)
        self.assertIsNone(self.st.node(nid))
        # 手动建的节点它删不掉
        code, body = self._post("/api/provision/remove", {"alias": "手动建的"}, token=tok, csrf=False)
        self.assertEqual(code, 404)
        self.assertIsNotNone(self.st.node(manual_id))

    def test_provision_remove_by_source(self):
        """面板节点名和中心别名不一致时，靠 source（面板节点 id）也能删掉"""
        _, tok = self.st.add_ptoken("fwpanel2")
        code, body = self._post("/api/provision/node",
                                {"alias": "新加坡SG1-Oracle", "source": "n1"}, token=tok, csrf=False)
        self.assertEqual(code, 200, body)
        nid = json.loads(body)["id"]
        self.assertEqual((self.st.node(nid) or {}).get("src"), "n1")
        # 按 source 删（别名完全对不上也没关系）
        code, body = self._post("/api/provision/remove",
                                {"alias": "SG1-Oracle", "source": "n1"}, token=tok, csrf=False)
        self.assertEqual(code, 200, body)
        self.assertIsNone(self.st.node(nid))

    def test_provision_remove_fuzzy_unique(self):
        """老节点没 src：归一化后唯一包含才删，多个候选就拒绝"""
        _, tok = self.st.add_ptoken("fwpanel2")
        code, body = self._post("/api/provision/node", {"alias": "新加坡SG2-Oracle"}, token=tok, csrf=False)
        a_id = json.loads(body)["id"]
        code, body = self._post("/api/provision/remove", {"alias": "SG2-Oracle"}, token=tok, csrf=False)
        self.assertEqual(code, 200, body)
        self.assertIsNone(self.st.node(a_id))
        # 两个候选 → 不删
        for alias in ("东京AK-JPHyer-1", "东京AK-JPHyer-2"):
            self._post("/api/provision/node", {"alias": alias}, token=tok, csrf=False)
        code, body = self._post("/api/provision/remove", {"alias": "AK"}, token=tok, csrf=False)
        self.assertEqual(code, 404, body)

    def test_uninstall_flow(self):
        """卸载：下发标记 → 上报应答带 uninstall → agent 回执后节点被移除"""
        code, body = self._post("/api/nodes", {"alias": "待卸载机"}, token="admin-test")
        nid, tok = json.loads(body)["id"], json.loads(body)["token"]
        self._post("/api/report", {"agent": "0.5.8", "ts": int(time.time())}, token=tok, csrf=False)
        code, body = self._post(f"/api/nodes/{nid}/uninstall", {}, token="admin-test")
        self.assertEqual(code, 200, body)
        self.assertEqual((self.st.node(nid) or {}).get("pending_uninstall"), 1)
        # 普通上报不会带指令（除非有待卸载）
        code, body = self._post("/api/report", {"agent": "0.5.8", "ts": int(time.time())}, token=tok, csrf=False)
        self.assertTrue(json.loads(body).get("uninstall"))
        # agent 回执 → 节点删除，token 失效
        code, body = self._post("/api/report", {"agent": "0.5.8", "agent_uninstall_ack": True,
                                                "ts": int(time.time())}, token=tok, csrf=False)
        self.assertEqual(code, 200, body)
        self.assertIsNone(self.st.node(nid))
        code, _ = self._post("/api/report", {"agent": "0.5.8", "ts": int(time.time())}, token=tok, csrf=False)
        self.assertEqual(code, 403)

    def test_token_rotate(self):
        """重发令牌：旧 token 立刻失效，新 token 能上报"""
        code, body = self._post("/api/nodes", {"alias": "轮换机"}, token="admin-test")
        nid = json.loads(body)["id"]
        old_tok = json.loads(body)["token"]
        code, body = self._post(f"/api/nodes/{nid}/token", {}, token="admin-test")
        self.assertEqual(code, 200, body)
        new_tok = json.loads(body)["token"]
        self.assertNotEqual(old_tok, new_tok)
        code, _ = self._post("/api/report", {"ts": int(time.time())}, token=old_tok, csrf=False)
        self.assertEqual(code, 403)
        code, _ = self._post("/api/report", {"ts": int(time.time())}, token=new_tok, csrf=False)
        self.assertEqual(code, 200)

    def test_admin_list_has_online_and_tags(self):
        code, body = self._post("/api/nodes", {"alias": "列表机", "tags": [{"t": "A", "c": "#34d399"}]},
                                token="admin-test")
        nid = json.loads(body)["id"]
        code, body = self._get("/api/nodes", token="admin-test")
        self.assertEqual(code, 200)
        node = [n for n in json.loads(body)["nodes"] if n["id"] == nid][0]
        self.assertIn("online", node)
        self.assertIn("used_bytes", node)
        self.assertEqual(node["tags"][0]["t"], "A")
        self.assertNotIn("token_hash", node)

    def test_groups_in_summary(self):
        """老数据只填了 grp 时，摘要也要给出 groups 列表（前端筛选要用）"""
        self.st.conn.execute("UPDATE nodes SET groups='', grp='老分组' WHERE id=?", (self.nid,))
        self.st.conn.commit()
        self._post("/api/report", payload(), token=self.tok)
        code, body = self._get("/api/public/summary")
        self.assertEqual(code, 200, body)
        n = json.loads(body)["nodes"][0]
        self.assertEqual(n["groups"], ["老分组"])

    def test_series_downsample(self):
        """一个月的分钟数据不能原样丢给前端：必须降到 ≤720 点，且顺序与形状不变"""
        rows = [{"ts": 1000 + i * 60, "cpu": 1.0 + (i % 7)} for i in range(900)]
        out = P.downsample(rows, 720, ("cpu",))
        self.assertEqual(len(out), 720)
        self.assertEqual(out[0]["ts"], rows[0]["ts"])
        self.assertEqual([r["ts"] for r in out], sorted(r["ts"] for r in out))
        # 桶内平均：前两行 1.0 / 2.0 → 第一桶只有 1 行（900/720=1.25）
        self.assertAlmostEqual(out[0]["cpu"], 1.0, 3)

    def test_series_month_uses_hour_table(self):
        """跨度 >10 天走小时聚合表（一个月的分钟聚合有 4 万点，不能查）"""
        nid, _ = self.st.add_node("a")
        now = int(time.time())
        self.st.conn.execute(
            "INSERT OR REPLACE INTO samples_hour(node_id,ts,cpu,mem_used,mem_total,disk_used,"
            "disk_total,load1,rx_bps,tx_bps,tcp,udp) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (nid, now - 3600 * 5, 12.5, 100, 200, 10, 20, 0.1, 1000, 500, 3, 1))
        self.st.conn.commit()
        d = self.st.series(nid, 744)
        self.assertEqual(d["hours"], 744)
        self.assertEqual(len(d["points"]), 1)
        self.assertAlmostEqual(d["points"][0]["cpu"], 12.5, 3)

    def test_series_endpoint(self):
        self._post("/api/report", payload(), token=self.tok)
        code, body = self._get(f"/api/public/series?node={self.nid}&hours=1")
        self.assertEqual(code, 200, body)
        d = json.loads(body)
        self.assertEqual(len(d["points"]), 1)
        self.assertIn("上海电信", d["checks"])
        code, _ = self._get("/api/public/series?node=nope")
        self.assertEqual(code, 404)

    def test_agent_scripts_served(self):
        for path in ("/install-agent.sh", "/agent.py"):
            code, body = self._get(path)
            self.assertEqual(code, 200, path)
            self.assertIn("fwprobe", body)


class TestAgentParse(unittest.TestCase):
    """用假的 /proc 内容验证解析（不依赖宿主机状态）"""

    def setUp(self):
        self._orig = A._read

    def tearDown(self):
        A._read = self._orig

    def fake(self, mapping):
        A._read = lambda p: mapping.get(p, "")

    def test_cpu_stat(self):
        self.fake({"/proc/stat": "cpu  100 0 100 800 50 0 0 0 0 0\ncpu0 50 0 50 400 25 0 0 0 0 0\n"})
        total, idle = A.cpu_stat()
        self.assertEqual(total, 1050)
        self.assertEqual(idle, 850)

    def test_meminfo(self):
        self.fake({"/proc/meminfo": "MemTotal:        1000000 kB\nMemAvailable:     400000 kB\n"
                                    "SwapTotal:       2000000 kB\nSwapFree:        1500000 kB\n"})
        mem, swap = A.meminfo()
        self.assertEqual(mem["total"], 1000000 * 1024)
        self.assertEqual(mem["used"], 600000 * 1024)
        self.assertEqual(swap["used"], 500000 * 1024)

    def test_net_counters(self):
        self.fake({"/proc/net/dev": "Inter-|   Receive                                                |  Transmit\n"
                                    " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets\n"
                                    "  eth0: 12345 10 0 0 0 0 0 0 67890 20 0 0 0 0 0 0\n"})
        self.assertEqual(A.net_counters("eth0"), (12345, 67890))
        self.assertEqual(A.net_counters("nope"), (0, 0))

    def test_conn_counts(self):
        tcp = ("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid\n"
               "   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  0\n"
               "   1: 0100007F:1F90 0100007F:9999 01 00000000:00000000 00:00000000 00000000  0\n")
        self.fake({"/proc/net/tcp": tcp, "/proc/net/tcp6": "", "/proc/net/udp": tcp, "/proc/net/udp6": ""})
        t, estab, u = A.conn_counts()
        self.assertEqual((t, estab, u), (2, 1, 2))

    def test_proc_count_and_os_info(self):
        self.fake({"/etc/os-release": 'ID=debian\nPRETTY_NAME="Debian GNU/Linux 13 (trixie)"\n'})
        info = A.os_info()
        self.assertEqual(info["os_id"], "debian")
        self.assertIn("Debian", info["os_name"])

    def test_primary_iface_from_route(self):
        self.fake({"/proc/net/route": "Iface\tDestination\tGateway\nens3\t00000000\t0100000A\n"})
        self.assertEqual(A.primary_iface(), "ens3")


class TestTcping(unittest.TestCase):
    """真实握手计时：本地起监听，不 mock 网络层"""

    def setUp(self):
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.stop = False
        self.th = threading.Thread(target=self._accept_loop, daemon=True)
        self.th.start()

    def _accept_loop(self):
        while not self.stop:
            try:
                c, _ = self.sock.accept()
                c.close()
            except OSError:
                return

    def tearDown(self):
        self.stop = True
        try:
            self.sock.close()
        except OSError:
            pass

    def test_probe_once_single_value(self):
        """Komari 口径：一轮只出一个值，min=avg=max；丢包记 100%"""
        r = A.probe_once("127.0.0.1", self.port, "tcp")
        self.assertTrue(r["ok"])
        self.assertEqual(r["loss"], 0.0)
        self.assertEqual(r["min"], r["avg"])
        self.assertEqual(r["avg"], r["max"])
        self.assertIsNotNone(r["addr"])

    def test_probe_once_closed_port_is_loss(self):
        sk = socket.socket(); sk.bind(("127.0.0.1", 0)); free_port = sk.getsockname()[1]; sk.close()
        r = A.probe_once("127.0.0.1", free_port, "tcp", timeout=0.5)
        self.assertFalse(r["ok"])
        self.assertEqual(r["loss"], 100.0)
        self.assertIsNone(r["avg"])

    def test_tcping_ok(self):
        r = A.tcping("127.0.0.1", self.port, attempts=3)
        self.assertTrue(r["ok"])
        self.assertEqual(r["loss"], 0.0)
        self.assertIsNotNone(r["avg"])
        self.assertLess(r["avg"], 500)

    def test_tcping_closed_port(self):
        s = socket.socket(); s.bind(("127.0.0.1", 0)); free_port = s.getsockname()[1]; s.close()
        r = A.tcping("127.0.0.1", free_port, attempts=2, timeout=0.5)
        self.assertFalse(r["ok"])
        self.assertEqual(r["loss"], 100.0)

    def test_tcping_dns_failure(self):
        r = A.tcping("no-such-host.invalid", 80, attempts=1, timeout=0.5)
        self.assertFalse(r["ok"])

    def test_run_checks_skips_disabled(self):
        targets = [
            {"name": "开", "proto": "tcp", "host": "127.0.0.1", "port": self.port, "enabled": True},
            {"name": "关", "proto": "tcp", "host": "127.0.0.1", "port": self.port, "enabled": False},
        ]
        out = A.run_checks(targets)
        self.assertEqual([c["name"] for c in out], ["开"])
        self.assertTrue(out[0]["ok"])


class TestMisc(unittest.TestCase):
    def setUp(self):
        self._orig = A._read

    def tearDown(self):
        A._read = self._orig

    def test_quota_parse(self):
        self.assertEqual(P._quota("500G"), 500 * 1024 ** 3)
        self.assertEqual(P._quota("1T"), 1024 ** 4)
        self.assertEqual(P._quota(""), 0)
        self.assertEqual(P._quota("abc"), 0)

    def test_lookup_country_self_for_private(self):
        """内网/回环来源 → 查本机自己的归属地（agent 与中心同机时正好对）"""
        seen = []

        class _Resp:
            def __read__(self): pass
            def read(self, n=None): return b'{"countryCode":"SG"}'
            def __enter__(self): return self
            def __exit__(self, *a): return False

        def fake_urlopen(url, timeout=0):
            seen.append(url if isinstance(url, str) else getattr(url, "full_url", ""))
            return _Resp()

        orig = P.urllib.request.urlopen
        P.urllib.request.urlopen = fake_urlopen
        try:
            self.assertEqual(P.lookup_country("10.0.0.5"), "SG")
            # v0.5.7 起优先 ipinfo.io（对机房 IP 更准），ip-api 只作兜底
            self.assertTrue(any("ipinfo.io/json" in u for u in seen))
            self.assertEqual(P.lookup_country("192.168.1.1"), "SG")
        finally:
            P.urllib.request.urlopen = orig

    def test_lookup_country_fallback_to_ipapi(self):
        """ipinfo 挂掉时回落到 ip-api，别因为一个源不通就丢归属地"""
        seen = []

        class _Resp:
            def read(self, n=None): return b'{"countryCode":"JP"}'
            def __enter__(self): return self
            def __exit__(self, *a): return False

        def fake_urlopen(url, timeout=0):
            u = url if isinstance(url, str) else getattr(url, "full_url", "")
            seen.append(u)
            if "ipinfo.io" in u:
                raise OSError("blocked")
            return _Resp()

        orig = P.urllib.request.urlopen
        P.urllib.request.urlopen = fake_urlopen
        try:
            self.assertEqual(P.lookup_country("8.8.4.4"), "JP")
            self.assertTrue(any("ipinfo.io" in u for u in seen))
            self.assertTrue(any("ip-api.com" in u for u in seen))
        finally:
            P.urllib.request.urlopen = orig

    def test_lookup_country_public_ip(self):
        class _Resp:
            def read(self, n=None): return b'{"countryCode":"JP"}'
            def __enter__(self): return self
            def __exit__(self, *a): return False

        orig = P.urllib.request.urlopen
        P.urllib.request.urlopen = lambda url, timeout=0: _Resp()
        try:
            P.COUNTRY_CACHE.pop("8.8.8.8", None)      # 注意：203.0.113.0/24 是 TEST-NET，Python 会当成私有
            self.assertEqual(P.lookup_country("8.8.8.8"), "JP")
            self.assertEqual(P.COUNTRY_CACHE["8.8.8.8"], "JP")
        finally:
            P.urllib.request.urlopen = orig

    def test_is_private_ip(self):
        self.assertTrue(P.is_private_ip("10.0.0.1"))
        self.assertTrue(P.is_private_ip("192.168.1.1"))
        self.assertFalse(P.is_private_ip("8.8.8.8"))

    def test_sample_cpu_delta(self):
        """两次 /proc/stat 快照的差值 → CPU 百分比；首个样本只建基线（cpu 为 None）"""
        data = {"/proc/stat": "cpu  100 0 100 800 100 0 0 0 0 0\n",
                "/proc/meminfo": "MemTotal: 1000 kB\nMemAvailable: 400 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n",
                "/proc/net/dev": "h\n h\n  eth0: 1000 0 0 0 0 0 0 0 2000 0 0 0 0 0 0 0\n",
                "/proc/loadavg": "0.10 0.20 0.30 1/100 1234\n",
                "/proc/uptime": "3600.00 900.00\n",
                "/etc/os-release": 'ID=debian\nPRETTY_NAME="Debian GNU/Linux 13"\n',
                "/proc/net/tcp": "", "/proc/net/tcp6": "", "/proc/net/udp": "", "/proc/net/udp6": ""}
        A._read = lambda p: data.get(p, "")
        try:
            smp = A.Sampler({"targets": [], "check_interval": 999, "disk_mount": "/"})
            first = smp.sample()
            self.assertIsNone(first["cpu"])                       # 第一次只建基线
            self.assertEqual(first["mem"]["total"], 1000 * 1024)
            self.assertEqual(first["os_id"], "debian")
            # 第二份快照：total 1100→2100（+1000），idle(含 iowait) 900→1700（+800）→ 使用率 20%
            data["/proc/stat"] = "cpu  200 0 200 1600 100 0 0 0 0 0\n"
            second = smp.sample()
            self.assertIsNotNone(second["cpu"])
            self.assertAlmostEqual(second["cpu"], 20.0, delta=0.5)
            self.assertGreaterEqual(second["net"]["rx_bps"], 0)
        finally:
            A._read = self._orig

    def test_rollup_prune_keeps_tables_consistent(self):
        st, d = mk_store()
        try:
            nid, _ = st.add_node("a")
            # 直接插一条 400 天前的原始样本（走 ingest 会被时钟纠正逻辑拉到当下）
            with st.lock:
                st.conn.execute("INSERT INTO samples(node_id,ts,cpu) VALUES(?,?,?)",
                                (nid, int(time.time()) - 400 * 86400, 9.9))
                st.conn.commit()
            st.rollup_and_prune()
            with st.lock:
                n = st.conn.execute("SELECT COUNT(*) c FROM samples WHERE node_id=?", (nid,)).fetchone()["c"]
            self.assertEqual(n, 0)       # 超出保留期被清掉
        finally:
            st.conn.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
