#!/usr/bin/env python3
"""VPS 连通性检测台 —— 零第三方依赖后端。

从观测点（家宽内的常驻设备）对目标 VPS 做五类检测：
Ping / TCP 端口 / UDP 端口（三态 + 对照端口）/ DNS 解析 / 出口网络，
并按结果组合生成中文综合解读。术语与语义见 GLOSSARY.md，用法见 README.md。
"""

import errno
import ipaddress
import json
import os
import random
import re
import shutil
import ssl
import socket
import subprocess
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse
from urllib import request as urlrequest

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
DATA_DIR = Path(os.environ.get("DATA_DIR", str(BASE_DIR / "data")))
TARGETS_FILE = DATA_DIR / "targets.json"

BIND = os.environ.get("BIND", "0.0.0.0")
PORT = int(os.environ.get("PORT", "52000"))

TCP_TIMEOUT = float(os.environ.get("TCP_TIMEOUT", "5"))
UDP_TIMEOUT = float(os.environ.get("UDP_TIMEOUT", "5"))
PING_COUNT = 4
PING_SUBPROCESS_TIMEOUT = 12

# Linux 特有的 socket 选项（设置失败会被忽略；已连接 UDP 在 macOS/BSD 上同样会上报 ICMP 错误）
IP_RECVERR = 11    # linux/in.h
IPV6_RECVERR = 25  # linux/in6.h
ROUTE_ERRNOS = {errno.ENETUNREACH, errno.EHOSTUNREACH, errno.ENETDOWN, errno.EHOSTDOWN}

_targets_lock = threading.Lock()
_round_lock = threading.Lock()
_run_gate = threading.Semaphore(1)  # 串行化检测轮次，避免并发双跑
LAST_ROUND = None


# ---------------- 目标存储 ----------------

def load_targets():
    if not TARGETS_FILE.exists():
        return []
    try:
        return json.loads(TARGETS_FILE.read_text("utf-8")).get("targets", [])
    except (json.JSONDecodeError, OSError):
        return []


def save_targets(targets):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    tmp = TARGETS_FILE.with_suffix(".json.tmp")
    with _targets_lock:
        tmp.write_text(json.dumps({"targets": targets}, ensure_ascii=False, indent=2), "utf-8")
        tmp.replace(TARGETS_FILE)


def normalize_target(body, keep_id=None):
    name = str(body.get("name", "")).strip()
    host = str(body.get("host", "")).strip().strip("[]")
    if not name:
        raise ValueError("名称不能为空")
    if not host:
        raise ValueError("主机（域名或 IP）不能为空")

    def _ports(raw):
        out = set()
        for p in raw or []:
            p = int(p)
            if not 1 <= p <= 65535:
                raise ValueError(f"端口 {p} 超出 1-65535")
            out.add(p)
        return sorted(out)

    payloads = {}
    for k, v in (body.get("udp_payloads") or {}).items():
        try:
            port = int(k)
        except (TypeError, ValueError):
            raise ValueError(f"载荷端口 {k} 不合法")
        hexstr = str(v).strip().replace(" ", "").lower()
        try:
            bytes.fromhex(hexstr)
        except ValueError:
            raise ValueError(f"端口 {port} 的自定义载荷不是合法十六进制")
        payloads[str(port)] = hexstr

    return {
        "id": keep_id or uuid.uuid4().hex[:8],
        "name": name,
        "host": host,
        "tcp_ports": _ports(body.get("tcp_ports")),
        "udp_ports": _ports(body.get("udp_ports")),
        "udp_payloads": payloads,
    }


# ---------------- 检测实现 ----------------

def resolve_host(host):
    """返回 (适用协议族列表, DNS 信息)。字面 IP 只保留对应族；域名解析 A + AAAA。"""
    dns = {"v4": [], "v6": [], "error": None}
    try:
        addr = ipaddress.ip_address(host)
        return (["v4"] if addr.version == 4 else ["v6"]), dns
    except ValueError:
        pass
    for fam, af in (("v4", socket.AF_INET), ("v6", socket.AF_INET6)):
        try:
            infos = socket.getaddrinfo(host, None, af, socket.SOCK_STREAM)
            dns[fam] = sorted({info[4][0] for info in infos})
        except socket.gaierror:
            dns[fam] = []
    if not dns["v4"] and not dns["v6"]:
        dns["error"] = "没有可用的 A / AAAA 记录（DNS 故障、被污染或域名不存在）"
    fams = [f for f in ("v4", "v6") if dns[f]]
    return fams, dns


_PING_SENT_RE = re.compile(r"(\d+) packets? transmitted, (\d+)(?: packets)? received")
_PING_LOSS_RE = re.compile(r"([\d.]+)% packet loss")
_PING_AVG_RE = re.compile(r"(?:rtt|round-trip) min/avg/max[^=]*=\s*[\d.]+/([\d.]+)/")


def do_ping(ip, family):
    binary = "ping6" if family == "v6" and shutil.which("ping6") else "ping"
    cmd = [binary, "-c", str(PING_COUNT), ip]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=PING_SUBPROCESS_TIMEOUT)
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "sent": PING_COUNT, "recv": 0, "loss_pct": 100.0, "avg_ms": None}
    out = proc.stdout or ""
    m = _PING_SENT_RE.search(out)
    if m:
        sent, recv = int(m.group(1)), int(m.group(2))
        loss = _PING_LOSS_RE.search(out)
        if recv == 0:
            loss_pct = float(loss.group(1)) if loss else 100.0
            return {"status": "dead", "sent": sent, "recv": 0, "loss_pct": loss_pct, "avg_ms": None}
        avg = _PING_AVG_RE.search(out)
        loss_pct = float(loss.group(1)) if loss else round((1 - recv / sent) * 100, 1)
        return {"status": "ok", "sent": sent, "recv": recv, "loss_pct": loss_pct,
                "avg_ms": float(avg.group(1)) if avg else None}
    err = (proc.stderr or "").lower()
    if "unreachable" in err or "no route" in err or "cannot resolve" in err:
        return {"status": "no_route", "sent": 0, "recv": 0, "loss_pct": 100.0, "avg_ms": None}
    detail = next((ln for ln in reversed((proc.stderr or proc.stdout or "").strip().splitlines())
                   if ln.strip()), "ping 执行失败")
    return {"status": "error", "error": detail[:200], "sent": 0, "recv": 0,
            "loss_pct": 100.0, "avg_ms": None}


def tcp_check(ip, port):
    family = socket.AF_INET6 if ipaddress.ip_address(ip).version == 6 else socket.AF_INET
    t0 = time.monotonic()
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        sock.settimeout(TCP_TIMEOUT)
        sock.connect((ip, port))
        return {"status": "open", "ms": round((time.monotonic() - t0) * 1000)}
    except ConnectionRefusedError:
        return {"status": "refused"}
    except TimeoutError:
        return {"status": "timeout"}
    except OSError as e:
        if e.errno in ROUTE_ERRNOS:
            return {"status": "no_route"}
        return {"status": "error", "error": os.strerror(e.errno) if e.errno else str(e)}
    finally:
        sock.close()


def _set_udp_recv_err(sock, family):
    try:
        if family == socket.AF_INET:
            sock.setsockopt(socket.SOL_IP, IP_RECVERR, 1)
        else:
            sock.setsockopt(socket.IPPROTO_IPV6, IPV6_RECVERR, 1)
    except OSError:
        pass  # 非 Linux：已连接 UDP 仍会以 ECONNREFUSED 上报 ICMP 端口不可达


def udp_check(ip, port, payload_hex=None):
    """UDP 三态探测：有响应 / 端口关闭 / 无响应。

    默认发 1 字节 0x00（无意义载荷）；自定义 payload_hex 优先。
    「端口关闭」= 收到 VPS 的 ICMP 端口不可达，说明 UDP 路径本身是通的。
    """
    family = socket.AF_INET6 if ipaddress.ip_address(ip).version == 6 else socket.AF_INET
    payload = bytes.fromhex(payload_hex) if payload_hex else b"\x00"
    sock = socket.socket(family, socket.SOCK_DGRAM)
    _set_udp_recv_err(sock, family)
    t0 = time.monotonic()
    try:
        sock.settimeout(UDP_TIMEOUT)
        sock.connect((ip, port))
        sock.send(payload)
    except OSError as e:
        if e.errno in ROUTE_ERRNOS:
            return {"status": "no_route"}
        return {"status": "error", "error": os.strerror(e.errno) if e.errno else str(e)}

    deadline = t0 + UDP_TIMEOUT
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return {"status": "no_response"}
        sock.settimeout(remaining)
        try:
            data, _ = sock.recvfrom(65535)
            return {"status": "response", "ms": round((time.monotonic() - t0) * 1000),
                    "reply_preview": data[:48].hex() or "(空包)"}
        except TimeoutError:
            return {"status": "no_response"}
        except ConnectionRefusedError:
            return {"status": "closed", "ms": round((time.monotonic() - t0) * 1000)}
        except OSError as e:
            if e.errno in (errno.ECONNREFUSED, errno.ECONNRESET):
                return {"status": "closed", "ms": round((time.monotonic() - t0) * 1000)}
            if e.errno in ROUTE_ERRNOS:
                return {"status": "unreachable", "error": os.strerror(e.errno)}
            if e.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                continue
            return {"status": "error", "error": os.strerror(e.errno) if e.errno else str(e)}


# ---------------- 出口网络 ----------------

def _ca_context():
    for ca in ("/etc/ssl/cert.pem",                    # macOS
               "/etc/ssl/certs/ca-certificates.crt",   # Debian / Ubuntu
               "/etc/pki/tls/certs/ca-bundle.crt"):    # RHEL 系
        if os.path.exists(ca):
            try:
                return ssl.create_default_context(cafile=ca)
            except ssl.SSLError:
                pass
    return ssl.create_default_context()


def _http_get(url, timeout=6):
    req = urlrequest.Request(url, headers={"User-Agent": "vps-check/1.0"})
    try:
        with urlrequest.urlopen(req, timeout=timeout, context=_ca_context()) as resp:
            return resp.read(256).decode("utf-8", "replace").strip()
    except ssl.SSLCertVerificationError:
        # 系统 CA 缺失（macOS python.org 安装包常见）：仅对只读 IP 回显端点降级重试
        try:
            with urlrequest.urlopen(req, timeout=timeout, context=ssl._create_unverified_context()) as resp:
                return resp.read(256).decode("utf-8", "replace").strip()
        except Exception:
            return None
    except Exception:
        return None


def _has_v6_route():
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        try:
            s.connect(("2606:4700:4700::1111", 443))  # UDP connect 只做路由查找，不发包
            return True
        finally:
            s.close()
    except OSError:
        return False


DEFAULT_V4_SOURCES = ["https://api4.ipify.org", "https://myip.ipip.net", "https://v4.ident.me"]
DEFAULT_V6_SOURCES = ["https://api6.ipify.org", "https://v6.ident.me", "https://ipv6.icanhazip.com"]


def _fetch_public_ip(family, sources):
    """并发尝试多个查询源，按优先级取第一个成功者。ipip.net 返回整句文本需提取。"""
    def _try(url):
        text = _http_get(url, timeout=4)
        if not text:
            return None
        m = re.search(r"IP\D*?(\d{1,3}(?:\.\d{1,3}){3})", text) if "ipip" in url else None
        cand = m.group(1) if m else text.strip().splitlines()[0].strip()
        try:
            return cand if ipaddress.ip_address(cand).version == family else None
        except ValueError:
            return None

    with ThreadPoolExecutor(max_workers=len(sources)) as ex:
        for res in ex.map(_try, sources):
            if res:
                return res
    return None


def check_egress():
    v4_sources = [u.strip() for u in os.environ.get("EGRESS_V4_URLS", "").split(",") if u.strip()] \
        or DEFAULT_V4_SOURCES
    v6_sources = [u.strip() for u in os.environ.get("EGRESS_V6_URLS", "").split(",") if u.strip()] \
        or DEFAULT_V6_SOURCES
    route = _has_v6_route()
    with ThreadPoolExecutor(max_workers=2) as ex:
        v4_fut = ex.submit(_fetch_public_ip, 4, v4_sources)
        v6_fut = ex.submit(_fetch_public_ip, 6, v6_sources)
        return {"v4": v4_fut.result(), "v6": v6_fut.result(), "v6_route": route}


# ---------------- 一轮检测与综合解读 ----------------

def check_target(t, ex):
    t0 = time.monotonic()
    fams, dns = resolve_host(t["host"])
    probe_ip = {}
    jobs = {}

    for fam in fams:
        ip = dns[fam][0] if dns[fam] else t["host"]
        probe_ip[fam] = ip
        jobs[ex.submit(do_ping, ip, fam)] = ("ping", fam)
        for port in t["tcp_ports"]:
            jobs[ex.submit(tcp_check, ip, port)] = ("tcp", (fam, port))
        for port in t["udp_ports"]:
            payload = t["udp_payloads"].get(str(port))
            jobs[ex.submit(udp_check, ip, port, payload)] = ("udp", (fam, port))
        ctrl_port = random.randrange(40000, 60000)
        jobs[ex.submit(udp_check, ip, ctrl_port, None)] = ("control", (fam, ctrl_port))

    ping, tcp, udp, control = {}, [], [], []
    for fut, (kind, key) in jobs.items():
        res = fut.result()
        if kind == "ping":
            ping[key] = res
        elif kind == "tcp":
            fam, port = key
            tcp.append({"family": fam, "port": port, **res})
        elif kind == "udp":
            fam, port = key
            udp.append({"family": fam, "port": port,
                        "payload": "custom" if t["udp_payloads"].get(str(port)) else "empty",
                        **res})
        else:
            fam, port = key
            control.append({"family": fam, "port": port, **res})

    tcp.sort(key=lambda r: (r["family"], r["port"]))
    udp.sort(key=lambda r: (r["family"], r["port"]))
    control.sort(key=lambda r: (r["family"], r["port"]))
    verdicts = make_verdicts(t, fams, dns, ping, tcp, udp, control)
    return {
        "target_id": t["id"], "name": t["name"], "host": t["host"],
        "families": fams, "dns": dns, "probe_ip": probe_ip,
        "ping": ping, "tcp": tcp, "udp": udp, "control": control,
        "verdicts": verdicts,
        "checked_at": datetime.now().isoformat(timespec="seconds"),
        "duration_ms": round((time.monotonic() - t0) * 1000),
    }


def _fam_label(fam):
    return "IPv4" if fam == "v4" else "IPv6"


def _ports_str(rows):
    return ", ".join(str(r["port"]) for r in sorted(rows, key=lambda r: r["port"]))


def make_verdicts(t, fams, dns, ping, tcp, udp, control):
    """规则引擎：按结果组合生成人话解读。level ∈ good/info/warn/bad/unknown。"""
    v = []
    is_domain = bool(dns["v4"] or dns["v6"] or dns["error"])

    if dns["error"]:
        v.append(("bad", f"域名「{t['host']}」解析失败：{dns['error']}"))
    else:
        if is_domain and "v4" not in fams:
            v.append(("warn", "域名没有 A 记录，无法通过 IPv4 访问"))
        if is_domain and "v6" not in fams:
            v.append(("info", "域名没有 AAAA 记录，无法通过 IPv6 访问"))

    for fam in fams:
        L = _fam_label(fam)
        p = ping.get(fam)
        ctrl = next((r for r in control if r["family"] == fam), None)
        tcpf = [r for r in tcp if r["family"] == fam]
        udpf = [r for r in udp if r["family"] == fam]

        if p and p["status"] == "no_route":
            v.append(("bad", f"{L}：观测点没有 {L} 出口路由，本族结果均不可用"))

        if ctrl:
            if ctrl["status"] == "closed":
                v.append(("good", f"{L} 对照端口返回「端口关闭」：UDP 路径完整可用（包能到 VPS，ICMP 也能回来）"))
            elif ctrl["status"] == "response":
                v.append(("info", f"{L} 对照端口 {ctrl['port']} 竟有响应？请确认 VPS 上该高位端口确实无服务"))
            elif ctrl["status"] == "no_response":
                v.append(("warn", f"{L} 对照端口无响应：VPS 防火墙可能丢弃了所有 UDP（含 ICMP 不可达），UDP 连通性无法判定"))
            elif ctrl["status"] in ("unreachable", "no_route"):
                v.append(("bad", f"{L} 对照端口探测不可达：观测点可能没有 {L} 出口"))

        if p and p["status"] == "ok":
            avg = f"平均 {p['avg_ms']:.1f} ms" if p.get("avg_ms") is not None else "平均延迟未知"
            v.append(("good", f"{L} Ping 通：{avg}，丢包 {p['loss_pct']}%"))
        elif p and p["status"] in ("dead", "timeout"):
            v.append(("warn", f"{L} Ping 无回包：可能是服务器禁 ICMP、路径被过滤或机器宕机（若 TCP 可通则多半只是禁 ping）"))

        if tcpf:
            opened = [r for r in tcpf if r["status"] == "open"]
            refused = [r for r in tcpf if r["status"] == "refused"]
            if opened:
                v.append(("good", f"{L} TCP 可连通的端口：{_ports_str(opened)}"))
            if refused:
                v.append(("info", f"{L} TCP 端口 {_ports_str(refused)} 返回「拒绝」：数据包能往返，路径是通的，只是这些端口没有服务监听"))
            if not opened and not refused and tcpf and \
                    all(r["status"] in ("timeout", "unreachable", "no_route") for r in tcpf):
                v.append(("warn", f"{L} 所有 TCP 端口均无回包：若这些端口在 VPS 上确实有监听，则该协议路径有被墙或防火墙拦截的嫌疑"))

        for r in udpf:
            if r["status"] == "response":
                v.append(("good", f"{L} UDP/{r['port']} 有响应：UDP 完全可用"))
            elif r["status"] == "closed":
                v.append(("info", f"{L} UDP/{r['port']} 返回「端口关闭」：UDP 路径通，但该端口没有服务监听"))
            elif r["status"] == "no_response":
                if ctrl and ctrl["status"] == "closed":
                    v.append(("info", f"{L} UDP/{r['port']} 无响应：但对照端口能返回关闭，说明 UDP 路径通畅。"
                                      "服务不回包是 QUIC/hy2 的正常行为——请直接真实连接 hy2 验证"))
                elif ctrl and ctrl["status"] == "no_response":
                    v.append(("unknown", f"{L} UDP/{r['port']} 无响应，对照端口也无响应："
                                         "无法区分「服务静默」与「UDP 被拦」。建议在 VPS 上临时跑一个会回包的 UDP 服务再测"))
                else:
                    v.append(("unknown", f"{L} UDP/{r['port']} 无响应"))

    statuses = [r["status"] for r in tcp + udp + control] + [p["status"] for p in ping.values()]
    if not statuses:
        v.append(("unknown", "没有可执行的检测项，请检查目标配置"))
    elif any(s in ("open", "ok", "response") for s in statuses):
        v.append(("good", "总体：目标可达，IP 大概率没有被封锁"))
    elif any(s in ("refused", "closed") for s in statuses):
        v.append(("info", "总体：VPS 有回包（RST / ICMP 不可达），路径部分可用，被完全封锁的可能性较低"))
    elif all(s in ("timeout", "dead", "no_response") for s in statuses):
        v.append(("bad", "总体：所有探测均无回包——IP 可能被墙，或 VPS 宕机 / 防火墙全丢。建议先到 VPS 控制台确认机器在线"))
    else:
        v.append(("unknown", "总体：结果混合，请逐项查看"))
    return v


def run_quick_check(body):
    """一次性快速检测：地址 + 端口清单直接开测，不落盘。返回与轮次相同的结构。"""
    with _run_gate:
        t = normalize_target({**body, "name": str(body.get("host", "quick"))}, keep_id="quick")
        started = datetime.now().isoformat(timespec="seconds")
        t0 = time.monotonic()
        ex = ThreadPoolExecutor(max_workers=48)
        try:
            eg_fut = ex.submit(check_egress)
            res_fut = ex.submit(check_target, t, ex)
            egress = eg_fut.result()
            result = res_fut.result()
        finally:
            ex.shutdown(wait=True)
        return {"started": started, "duration_ms": round((time.monotonic() - t0) * 1000),
                "egress": egress, "targets": [result]}


def run_round(target_ids=None):
    with _run_gate:
        targets = [t for t in load_targets() if not target_ids or t["id"] in target_ids]
        started = datetime.now().isoformat(timespec="seconds")
        t0 = time.monotonic()
        ex = ThreadPoolExecutor(max_workers=48)
        try:
            eg_fut = ex.submit(check_egress)
            target_futs = [ex.submit(check_target, t, ex) for t in targets]
            egress = eg_fut.result()
            results = [f.result() for f in target_futs]
        finally:
            ex.shutdown(wait=True)

        global LAST_ROUND
        round_data = {"started": started, "duration_ms": round((time.monotonic() - t0) * 1000),
                      "egress": egress, "targets": results}
        with _round_lock:
            if target_ids and LAST_ROUND:
                merged = {r["target_id"]: r for r in LAST_ROUND["targets"]}
                for r in results:
                    merged[r["target_id"]] = r
                LAST_ROUND = {**LAST_ROUND, "started": started, "targets": list(merged.values())}
            else:
                LAST_ROUND = round_data
        return LAST_ROUND


# ---------------- HTTP 服务 ----------------

class Handler(BaseHTTPRequestHandler):
    server_version = "VPSCheck/1.0"

    def log_message(self, fmt, *args):
        pass

    def _send_json(self, code, obj):
        data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _serve_index(self):
        f = STATIC_DIR / "index.html"
        if not f.exists():
            return self._send_json(404, {"ok": False, "error": "找不到 static/index.html"})
        data = f.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _path(self):
        return urlparse(self.path).path

    def _read_body(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        try:
            obj = json.loads(raw.decode("utf-8")) if raw else {}
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise ValueError("请求体不是合法 JSON")
        if not isinstance(obj, dict):
            raise ValueError("请求体应为 JSON 对象")
        return obj

    def do_GET(self):
        p = self._path()
        if p == "/":
            return self._serve_index()
        if p == "/api/targets":
            return self._send_json(200, {"ok": True, "data": load_targets()})
        if p == "/api/egress":
            return self._send_json(200, {"ok": True, "data": check_egress()})
        if p == "/api/round":
            with _round_lock:
                data = LAST_ROUND
            return self._send_json(200, {"ok": True, "data": data})
        return self._send_json(404, {"ok": False, "error": "not found"})

    def do_POST(self):
        p = self._path()
        try:
            if p == "/api/targets":
                t = normalize_target(self._read_body())
                targets = load_targets()
                targets.append(t)
                save_targets(targets)
                return self._send_json(200, {"ok": True, "data": t})
            if p == "/api/check":
                body = self._read_body()
                if not str(body.get("host", "")).strip():
                    return self._send_json(400, {"ok": False, "error": "请填写目标地址"})
                return self._send_json(200, {"ok": True, "data": run_quick_check(body)})
            if p == "/api/run":
                tid = self._read_body().get("target_id")
                return self._send_json(200, {"ok": True, "data": run_round([tid] if tid else None)})
            return self._send_json(404, {"ok": False, "error": "not found"})
        except ValueError as e:
            return self._send_json(400, {"ok": False, "error": str(e)})
        except Exception as e:
            return self._send_json(500, {"ok": False, "error": f"{type(e).__name__}: {e}"})

    def do_PUT(self):
        m = re.fullmatch(r"/api/targets/([^/]+)", self._path())
        if not m:
            return self._send_json(404, {"ok": False, "error": "not found"})
        tid = m.group(1)
        try:
            updated = normalize_target(self._read_body(), keep_id=tid)
            targets = load_targets()
            for i, t in enumerate(targets):
                if t["id"] == tid:
                    targets[i] = updated
                    save_targets(targets)
                    return self._send_json(200, {"ok": True, "data": updated})
            return self._send_json(404, {"ok": False, "error": "目标不存在"})
        except ValueError as e:
            return self._send_json(400, {"ok": False, "error": str(e)})

    def do_DELETE(self):
        m = re.fullmatch(r"/api/targets/([^/]+)", self._path())
        if not m:
            return self._send_json(404, {"ok": False, "error": "not found"})
        tid = m.group(1)
        targets = load_targets()
        remaining = [t for t in targets if t["id"] != tid]
        if len(remaining) == len(targets):
            return self._send_json(404, {"ok": False, "error": "目标不存在"})
        save_targets(remaining)
        return self._send_json(200, {"ok": True})


def main():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    srv = ThreadingHTTPServer((BIND, PORT), Handler)
    display = "本机所有网卡" if BIND == "0.0.0.0" else BIND
    print(f"✅ VPS 连通性检测台已启动: http://127.0.0.1:{PORT}  (监听 {display}:{PORT})", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
