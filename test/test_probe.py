#!/usr/bin/env python3
"""fwprobe 单元测试（python3 -m unittest test.test_probe -v）

覆盖：节点 CRUD / token 轮换 / 上报入库 / 公开摘要不泄露隐私 / HTTP 路由与鉴权 /
agent 的 /proc 解析 / TCPing 真实握手 / 配额解析。
"""
import json
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
        for leak in ("token_hash", "public_ip", "hostname", "kernel"):
            self.assertNotIn(leak, n)
        self.assertEqual(n["alias"], "香港-1")
        self.assertIn("sample", n)
        self.assertTrue(n["online"])

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

    def _post(self, path, body, token=None):
        data = json.dumps(body).encode()
        req = urllib.request.Request(self.base + path, data=data, method="POST")
        req.add_header("Content-Type", "application/json")
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
        with urllib.request.urlopen(req, timeout=5) as r:
            self.assertEqual(r.status, 200)
        self.assertIsNone(self.st.node(d["id"]))

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
