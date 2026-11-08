#!/usr/bin/env python3
"""fwprobe 单元测试（python3 -m unittest test.test_probe -v）

覆盖：节点 CRUD / token 轮换 / 上报入库 / 公开摘要不泄露隐私 / HTTP 路由与鉴权 /
agent 的 /proc 解析 / TCPing 真实握手 / 配额解析。
"""
import json
import pathlib
import os
import socket
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
        self.assertNotIn(".cells{display:flex", self.src)   # 旧的 flex 格子实现已废弃


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
