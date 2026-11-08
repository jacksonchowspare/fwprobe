# fwprobe

自建的 VPS 探针：**agent 主动上报 + 公开状态页**。零第三方依赖（只用 Python 标准库 + 内置 sqlite3），
服务端与采集端都是单文件脚本，一个 systemd 服务管住。

- 采集：CPU / 内存 / Swap / 磁盘 / 负载 / 网络上下行速率与累计 / TCP·UDP 连接数 / 进程数 / 在线时长
- 探测：三网（电信 / 联通 / 移动）TCPing 或 ICMP，每目标可选，记 min / avg / max 与丢包率
- 展示：公开状态页（节点卡片 + 三网时延），后台管理（别名、分组、流量配额、到期日、token 轮换）
- 存储：原始 30s 数据保 7 天，1 分钟聚合保 30 天，1 小时聚合保 1 年，自动降采样与清理

> agent 只往外上报，**不监听任何端口**，被监控机器不需要开放入站。

## 架构

```
  被监控机 (agent)                探针中心 (fwprobe)              nginx
  ┌──────────────┐   HTTPS POST  ┌──────────────────┐   反代      ┌─────────┐
  │ 每 30s 采样  │ ────────────▶ │ 127.0.0.1:17899  │ ◀────────── │ 80/443  │ ◀── 浏览器
  │ 每 60s 探测  │  Bearer token │ sqlite + 公开页  │             └─────────┘
  └──────────────┘               └──────────────────┘
```

- 中心不主动连节点 → 节点在内网 / NAT 后面也能上报
- 每台节点一个 token，中心只存 sha256，可单独轮换（旧 agent 立即失效）
- 断网时 agent 把样本写入本地 spool（上限 200 条），恢复后补发

## 安装（中心）

```bash
curl -fsSL https://raw.githubusercontent.com/jacksonchowspare/fwprobe/main/install.sh | sudo bash
```

装完会打印：

- 监听地址 `127.0.0.1:17899`（不对公网暴露）
- 数据库 `/var/lib/fwprobe/probe.db`
- 管理 token 的位置（`/etc/fwprobe/config.json`，仅 root 可读）

然后在 nginx 里为公开域名加一个 server 块，反代到 `127.0.0.1:17899`（示例见下）。

### nginx 示例

```nginx
server {
    listen 80;
    server_name status.example.com;
    location /.well-known/acme-challenge/ { root /var/www/fwpanel-acme; }
    location / { return 301 https://$host$request_uri; }
}

server {
    listen 443 ssl;
    server_name status.example.com;
    ssl_certificate     /etc/letsencrypt/live/status.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/status.example.com/privkey.pem;
    client_max_body_size 2m;

    location / {
        proxy_pass http://127.0.0.1:17899;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## 添加节点 / 安装 agent

在中心机器上：

```bash
sudo python3 /usr/local/lib/fwprobe/probe.py addnode --alias "香港-1" --group HK \
     --quota 500G --expires 2026-12-31
```

会输出一条只显示一次的安装命令：

```bash
curl -fsSL https://status.example.com/install-agent.sh | sudo bash -s -- \
     --token <节点token> --server https://status.example.com
```

在被监控机器上执行即可。agent 装到 `/usr/local/lib/fwprobe-agent/`，
配置在 `/etc/fwprobe-agent/config.json`（600），服务名 `fwprobe-agent`。

常用命令：

```bash
sudo python3 /usr/local/lib/fwprobe/probe.py listnodes      # 节点与在线状态
sudo python3 /usr/local/lib/fwprobe/probe.py rmtoken <id>   # 轮换 token
sudo python3 /usr/local/lib/fwprobe/probe.py delnode <id>   # 删除节点（含历史）
curl -fsSL https://status.example.com/install-agent.sh | sudo bash -s -- --uninstall
```

## 探测目标

默认三条（IPv4，已实测可用）：

| 线路 | 目标 |
| --- | --- |
| 上海电信 | `sh-ct-v4.ip.zstaticcdn.com:80` |
| 上海联通 | `sh-cu-v4.ip.zstaticcdn.com:80` |
| 上海移动 | `sh-cm-v4.ip.zstaticcdn.com:80` |

IPv6 的 `sh-{ct,cu,cm}-v6.ip.zstaticcdn.com` 在公共 DNS 上**没有 AAAA 记录**（`NOERROR` 但零记录），
所以默认以 `enabled: false` 留位，等有能解析的 v6 地址再启用；节点没有 IPv6 出口时该列显示不可用而非失败。

每条目标的结构：

```json
{"name": "上海电信", "proto": "tcp", "host": "sh-ct-v4.ip.zstaticcdn.com",
 "port": 80, "family": "auto", "enabled": true}
```

`proto` 可改 `icmp`（需要 root 或 CAP_NET_RAW），`family` 可选 `auto|4|6`（auto 优先 AAAA，无则回落 A）。

## 常用运维

```bash
systemctl status fwprobe --no-pager
journalctl -u fwprobe -n 50 --no-pager
curl -s http://127.0.0.1:17899/healthz        # 本机自检：版本 / 节点数 / 库大小
```

## 卸载

```bash
sudo bash install.sh --uninstall     # 保留配置与数据库
sudo bash install.sh --purge         # 连配置和数据库一起删
```

## 已知边界

- 中心与被监控机是「单向上报」模型：中心那台机器自己挂了，状态页和后续告警都看不到 —— 要覆盖这种情况需要独立的第三个探测点（尚未实现）
- 目前没有告警推送，告警表结构已预留
