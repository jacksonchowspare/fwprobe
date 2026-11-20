#!/usr/bin/env python3
"""按原始样本重算每台机器的「本周期用量」（修被污染的历史值）。

背景：v0.5.24 起 cyc_rx/cyc_tx 靠增量累加，旧代码把 last_*_total 的 0（=未知）当成上次读数，
于是 rx_total - 0 把整条网卡计数器（机器开机以来的几百 GB）一次性记进本周期，
面板出现「1.85 TB / 实际 12 GB」这种量级错误。v0.5.36 修好了逻辑，但库里已经被写坏的值
不会自己回去——用这个脚本按 7 天原始样本（正增量求和）重算一遍。

用法（中心机上）：
    sudo python3 recount_traffic.py            # 只打印，不改库
    sudo python3 recount_traffic.py --apply    # 真写库
可选：--db /var/lib/fwprobe/probe.db --since <ts>
"""
import argparse
import os
import sqlite3
import sys
import time

DB = "/var/lib/fwprobe/probe.db"


def gb(n):
    return "%.2f GB" % (n / 1e9)


def recount(conn, nid, since=None):
    """正增量求和；计数器变小（重启）从 0 起算；0/空样本视为无效读数跳过。"""
    rows = conn.execute(
        "SELECT ts, rx_total, tx_total FROM samples WHERE node_id=? AND rx_total IS NOT NULL"
        " ORDER BY ts ASC", (nid,)).fetchall()
    last_rx = last_tx = None
    rx = tx = 0
    first_ts = None
    for ts, r, t in rows:
        if since and ts < since:
            continue
        r, t = int(r or 0), int(t or 0)
        if r <= 0 and t <= 0:
            continue                      # 网卡没读到的那一条，跳过且不动基准
        if first_ts is None:
            first_ts = ts
        if r > 0 and last_rx is not None:
            if r >= last_rx:
                rx += r - last_rx
            elif r <= last_rx // 2:       # 腰斩 = 重启归零；小幅回退是抖动，不入账
                rx += r
        if t > 0 and last_tx is not None:
            if t >= last_tx:
                tx += t - last_tx
            elif t <= last_tx // 2:
                tx += t
        if r > 0:
            last_rx = r
        if t > 0:
            last_tx = t
    return rx, tx, first_ts


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default=DB)
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--since", type=int, default=0)
    a = ap.parse_args()
    if not os.path.exists(a.db):
        sys.exit("找不到数据库：%s" % a.db)
    conn = sqlite3.connect(a.db)
    conn.row_factory = sqlite3.Row
    print("%-26s %14s %14s %14s" % ("节点", "面板现在", "重算后", "差"))
    for n in conn.execute("SELECT id, alias, cyc_rx, cyc_tx FROM nodes ORDER BY created"):
        rx, tx, first_ts = recount(conn, n["id"], a.since or None)
        old = int(n["cyc_rx"] or 0) + int(n["cyc_tx"] or 0)
        new = rx + tx
        print("%-26s %14s %14s %14s" % ((n["alias"] or n["id"])[:26],
                                        gb(old), gb(new), gb(old - new)))
        if a.apply:
            conn.execute("UPDATE nodes SET cyc_rx=?,cyc_tx=? WHERE id=?", (rx, tx, n["id"]))
    if a.apply:
        conn.commit()
        print("\n已写库。样本覆盖不到的部分（装探针之前的流量）无法回补，需要的话在后台手填。")
    else:
        print("\n只预览，没有改库；确认无误后加 --apply。")


if __name__ == "__main__":
    main()
