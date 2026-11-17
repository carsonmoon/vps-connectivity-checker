# 📡 VPS 连通性检测台

一个跑在**国内家宽网络**里的本地网页工具：检测你的家庭宽带到境外 VPS 的连通性（IPv4 / IPv6、TCP / UDP 端口），核心用途是判断「这个 VPS 国内能不能访问、能不能支撑 hy2（Hysteria2 / QUIC over UDP）」。

- 后端：Python 3 纯标准库，**零第三方依赖**
- 前端：单文件 HTML，零构建
- 部署：Docker（推荐跑在 NAS 上），也可在任意常驻设备直跑
- 术语与语义约定见 [GLOSSARY.md](GLOSSARY.md)

## 快速开始

### 方式一：NAS 直接拉镜像（推荐，NAS 上零构建）

镜像由 GitHub Actions 自动构建并发布，双架构（`linux/amd64` + `linux/arm64`）：

```bash
docker run -d --name vps-check --network host --restart unless-stopped \
  -v /vol1/1000/docker/vps-check/data:/data \
  ghcr.io/carsonmoon/vps-connectivity-checker:latest
```

或用 compose 管理（源码在 NAS 上时，`pull` 拉现成镜像、不触发构建）：

```bash
git clone https://github.com/carsonmoon/vps-connectivity-checker.git && cd vps-connectivity-checker
docker compose pull && docker compose up -d
```

然后家里任何设备浏览器打开：`http://<NAS的IP>:52000`

> 使用 `network_mode: host`：容器直接继承 NAS 的网络栈（含 IPv6 出口）。若 NAS 或路由器没有 IPv6，页面会如实显示「IPv6 无出口」——这本身就是你宽带环境的答案。

### 方式二：源码本地构建（无外网 / 私有化场景）

把源码放到 NAS 后，在项目目录执行：

```bash
docker compose build && docker compose up -d
```

### 方式三：Mac / 任意有 Python 3 的机器（调试直跑）

```bash
python3 server.py
# 打开 http://127.0.0.1:52000
```

> macOS 下 UDP「端口关闭」检测能力弱于 Linux 容器（无 `IP_RECVERR`），且需要系统 `ping`/`ping6`——调试够用，生产建议跑在 Docker 里。

## 使用说明

1. 页面顶部地址栏填入 VPS 的域名或 IP，TCP / UDP 端口留空则默认测 `22, 80, 443` / `443`
2. 点「▶ 开始检测」，几秒后 IPv4 / IPv6 两族的 Ping、TCP 可达性、UDP 三态、DNS 解析与综合解读全部显示
3. 每次检测相互独立、不落盘；页面顶栏始终显示观测点当前的公网出口 IPv4 / IPv6

### 每轮检测的五类项目

| 检测项 | 说明 |
|---|---|
| Ping (ICMP) | IPv4 / IPv6 各 4 包，报告平均延迟与丢包率 |
| TCP 端口 | 对每个端口发起真实 TCP 连接，5 秒超时 |
| UDP 端口 | 三态探测（见下） |
| DNS 解析 | 域名的 A / AAAA 记录；字面 IP 则跳过 |
| 出口网络 | 观测点当前的公网 IPv4 / IPv6、有无 IPv6 出口路由 |

### 结果状态语义（重要）

| 状态 | 含义 |
|---|---|
| TCP ✅ 可连通 | 连接成功，路径完全正常 |
| TCP 🔵 拒绝 | 收到 RST：**数据包能往返（路径是通的）**，只是该端口没有服务监听 |
| TCP ⚠️ 超时 | 无任何回包：端口被防火墙 DROP 或路径被墙，两者无法区分 |
| UDP ✅ 有响应 | 对端服务回了包：UDP 完全可用 |
| UDP 🔵 端口关闭 | 收到 ICMP 端口不可达：**UDP 路径是通的**，只是该端口无服务 |
| UDP ⚠️ 无响应 | 服务静默 / 防火墙丢弃 / 被墙，**三者无法区分** |

### UDP 三态 + 对照端口

QUIC / hy2 服务器按协议规范**对无效数据包必须静默丢弃**，所以往 hy2 端口发探测包永远「无响应」，这不是服务坏了。本工具的处理方式：

1. **三态如实报告**，不给出误导性的「通/不通」二值结论
2. **自动对照端口**：每轮向目标一个随机高位端口（VPS 上必然无服务）也发探测包——
   - 对照端口返回「端口关闭」+ hy2 端口「无响应」 ⇒ UDP 路径通畅，服务大概率在监听，请直接真实连接 hy2 验证
   - 对照端口也「无响应」 ⇒ VPS 防火墙丢 UDP 或路径问题，无法判定
3. **自定义载荷**（可选）：给会回包的 UDP 服务（如 DNS 53）配一段十六进制报文，让「无响应」升级为「有响应」。示例 DNS 查询（查 example.com 的 A 记录）：
   ```
   53:000101000001000000000000076578616d706c6503636f6d0000010001
   ```

## 常见问题

- **Ping 不通但 TCP 通**：服务器禁 ICMP 或 ICMP 被限速，不影响 TCP/UDP 服务，很常见
- **IPv6 检测全部「无路由」**：观测点没有 IPv6 出口（宽带没分配 v6 或路由器没开 PD），工具会如实标注而不是报「不通」
- **TCP 全超时但 VPS 明明有服务**：先到 VPS 控制台确认服务在监听、防火墙（ufw / 云安全组）放行，再怀疑被墙
- **手机能打开页面吗**：能，访问 `http://NAS的IP:52000`——但检测结果始终来自 NAS 的网络，不是手机的
- **群晖提示 ping 权限错误**：在容器设置里补 `cap_add: [NET_RAW]`（默认 Docker 已含，个别精简环境会裁掉）

## 安全提醒

⚠️ 服务无密码、监听 `0.0.0.0`，仅限**家庭内网**使用，**不要把 52000 端口映射到公网**。

## 环境变量

| 变量 | 默认 | 说明 |
|---|---|---|
| `PORT` | `52000` | 监听端口 |
| `BIND` | `0.0.0.0` | 监听地址（仅本机用可设 `127.0.0.1`） |
| `DATA_DIR` | `./data`（容器内 `/data`） | targets.json 存放目录 |
| `TCP_TIMEOUT` / `UDP_TIMEOUT` | `5` | 单次探测超时（秒） |
| `EGRESS_V4_URLS` / `EGRESS_V6_URLS` | 内置多源 | 公网出口 IP 查询源，逗号分隔；内置默认依次尝试 ipify → myip.ipip.net → ident.me |
