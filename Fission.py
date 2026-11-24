# CloudflareCDNFission -- 裂变扩源 + 验证（2026-11-25 改造）
#
# 一轮流程：
#   种子 IP（seeds.txt，可直接放 FOFA 导出的 CSV）
#     -> 反查同 IP 域名（AlienVault OTX passive DNS + ip138 + ipchaxun，取并集）
#     -> DoH 解析回 IPv4
#     -> 丢掉 Cloudflare 公开段、私网/保留地址、种子本身、已知来源里已有的 IP
#     -> 验证：TLS(SNI=VERIFY_HOST) + GET /cdn-cgi/trace，拿到 colo 才算活
#     -> 打标签：cf-asn（CF ASN 代播，只能当优选）/ proxyip-XX（过 ProxyIP 检测，XX=出口国家）/ relay
#     -> 输出 output/alive.txt（ip:443#标签-colo），活 IP 另写 output/seeds_next.txt
#
# 与原版的区别：
#   * 候选和种子分开：未验证的 IP 不回灌成下一轮种子（原版越跑越多的大多是死 IP）。
#   * CF ASN（13335 / 209242）不再丢弃，改成标签：这类 IP 当优选入口实测可用，只是不能当 ProxyIP。
#   * 反查源取并集，OTX 走 JSON API，ip138 / ipchaxun 抓页面，按站限速。
#   * 不做全网扫描，只验证裂变出的候选。
#
# 环境变量：
#   VERIFY_HOST   验证用 SNI / Host，默认 speed.cloudflare.com（可换成自己的 Worker 域名）
#   CHECK_API     ProxyIP 检测接口，形如 https://example.com/check（调用 ?proxyip=ip:443），留空则跳过
#   KNOWN_URLS    已知来源 URL，逗号分隔；其中出现过的 IP 视为非新增
#   MAX_SEEDS     每轮最多用多少个种子（按 /24 去重后），默认 200
#   OTX_TIMEOUT   OTX 单次请求超时秒数，默认 60（passive_dns 常要 40s 左右）
#   OTX_BUDGET    本轮花在 OTX 上的总秒数上限，默认 1500；超了或冷却等不起就停用 OTX
#   OTX_API_KEY   AlienVault OTX 的免费 API key（可选；不填也能用，但很快会被 429 限流）

import concurrent.futures as cf
import ipaddress
import json
import os
import re
import datetime
import email.utils
import socket
import ssl
import sys
import threading
import time

import requests
from lxml import etree

SEEDS_FILE = "seeds.txt"
KNOWN_FILE = "known.txt"
OUT_DIR = "output"

VERIFY_HOST = os.environ.get("VERIFY_HOST", "speed.cloudflare.com")
CHECK_API = os.environ.get("CHECK_API", "").strip()
KNOWN_URLS = [u.strip() for u in os.environ.get("KNOWN_URLS", "").split(",") if u.strip()]
MAX_SEEDS = int(os.environ.get("MAX_SEEDS", "200"))
OTX_API_KEY = os.environ.get("OTX_API_KEY", "").strip()
OTX_TIMEOUT = float(os.environ.get("OTX_TIMEOUT", "60"))
OTX_BUDGET = float(os.environ.get("OTX_BUDGET", "1500"))

DOH_URL = "https://dns.google/resolve"
CF_IPS_URL = "https://www.cloudflare.com/ips-v4/"
CF_IPV4_FALLBACK = [
    "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "104.16.0.0/13", "104.24.0.0/14", "108.162.192.0/18",
    "131.0.72.0/22", "141.101.64.0/18", "162.158.0.0/15",
    "172.64.0.0/13", "173.245.48.0/20", "188.114.96.0/20",
    "190.93.240.0/20", "197.234.240.0/22", "198.41.128.0/17",
]
CF_ASNS = {13335, 209242}

USER_AGENT = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/120.0 Safari/537.36")
IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
DOMAIN_RE = re.compile(r"^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")

session = requests.Session()
session.headers.update({"User-Agent": USER_AGENT, "Accept": "*/*"})


# ---------- 工具 ----------

def log(*a):
    print(*a, flush=True)


def read_ips(path):
    """从任意文本（含 FOFA CSV）里抽 IPv4，保持首次出现顺序。"""
    if not os.path.exists(path):
        return []
    seen, out = set(), []
    with open(path, encoding="utf-8", errors="ignore") as f:
        for ip in IPV4_RE.findall(f.read()):
            if ip not in seen:
                seen.add(ip)
                out.append(ip)
    return out


def dedupe_by_24(ips):
    seen, out = set(), []
    for ip in ips:
        key = ip.rsplit(".", 1)[0]
        if key not in seen:
            seen.add(key)
            out.append(ip)
    return out


def is_public(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def load_cf_networks():
    try:
        r = session.get(CF_IPS_URL, timeout=15)
        r.raise_for_status()
        nets = [ipaddress.ip_network(l.strip()) for l in r.text.splitlines() if l.strip()]
        if nets:
            return nets
    except Exception as e:
        log(f"CF 段拉取失败，用内置清单：{e}")
    return [ipaddress.ip_network(c) for c in CF_IPV4_FALLBACK]


def in_networks(ip, nets):
    addr = ipaddress.ip_address(ip)
    return any(addr in n for n in nets)


def load_known():
    known = set(read_ips(KNOWN_FILE))
    for url in KNOWN_URLS:
        try:
            r = session.get(url, timeout=30)
            r.raise_for_status()
            got = set(IPV4_RE.findall(r.text))
            known |= got
            log(f"已知来源 {url}: {len(got)}")
        except Exception as e:
            log(f"已知来源拉取失败 {url}: {e}")
    return known


# ---------- 反查 ----------

class RateLimiter:
    def __init__(self, interval):
        self.interval = interval
        self.lock = threading.Lock()
        self.last = 0.0

    def wait(self):
        with self.lock:
            gap = self.interval - (time.monotonic() - self.last)
            if gap > 0:
                time.sleep(gap)
            self.last = time.monotonic()


_limits = {"otx": RateLimiter(1.0), "ip138": RateLimiter(1.0), "ipchaxun": RateLimiter(1.0)}


def clean_domains(names):
    out = set()
    for n in names:
        n = (n or "").strip().lower().rstrip(".")
        if n.startswith("*."):
            n = n[2:]
        if DOMAIN_RE.match(n):
            out.add(n)
    return out


class OtxStopped(Exception):
    """OTX 要求的冷却超过本轮预算，或预算已用完：本轮不再查 OTX。"""


_otx_state = {"deadline": None, "stopped": None}


def retry_after_seconds(value, now=None):
    """解析 Retry-After：秒数或 HTTP-date；无法解析返回 None。"""
    if not value:
        return None
    value = value.strip()
    if value.isdigit():
        return float(value)
    try:
        when = email.utils.parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=datetime.timezone.utc)
    now = now or datetime.datetime.now(datetime.timezone.utc)
    return max(0.0, (when - now).total_seconds())


def _otx_remaining():
    if _otx_state["deadline"] is None:
        _otx_state["deadline"] = time.monotonic() + OTX_BUDGET
    return _otx_state["deadline"] - time.monotonic()


def _otx_stop(reason):
    if not _otx_state["stopped"]:
        _otx_state["stopped"] = reason
        log(f"OTX 本轮停用：{reason}")
    raise OtxStopped(reason)


def reverse_otx(ip):
    if _otx_state["stopped"]:
        raise OtxStopped(_otx_state["stopped"])
    if _otx_remaining() <= 0:
        _otx_stop(f"超过预算 {OTX_BUDGET}s")
    headers = {"X-OTX-API-KEY": OTX_API_KEY} if OTX_API_KEY else {}
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/passive_dns"
    for attempt in range(4):
        _limits["otx"].wait()
        r = session.get(url, headers=headers, timeout=OTX_TIMEOUT)
        if r.status_code not in (429, 502, 503, 504):
            break
        # 限流或网关超时：按服务端给的 Retry-After 等满；等不起就停用 OTX，不提前重试
        wait = retry_after_seconds(r.headers.get("Retry-After"))
        if wait is None:
            wait = 15.0 * (attempt + 1)
        if wait > _otx_remaining():
            _otx_stop(f"HTTP {r.status_code}，要求等待 {int(wait)}s，超过剩余预算")
        _limits["otx"].interval = min(_limits["otx"].interval * 2, 10.0)
        time.sleep(wait)
    r.raise_for_status()
    rows = r.json().get("passive_dns", [])
    return clean_domains(x.get("hostname") for x in rows if x.get("record_type") in (None, "A"))


def _scrape(key, url, xpath):
    _limits[key].wait()
    r = session.get(url, timeout=20)
    r.raise_for_status()
    tree = etree.fromstring(r.text, etree.HTMLParser())
    return clean_domains(a.text for a in tree.xpath(xpath) if a.text)


def reverse_ip138(ip):
    return _scrape("ip138", f"https://site.ip138.com/{ip}/", '//ul[@id="list"]/li/a')


def reverse_ipchaxun(ip):
    return _scrape("ipchaxun", f"https://ipchaxun.com/{ip}/", '//div[@id="J_domain"]/p/a')


REVERSE_SOURCES = {"otx": reverse_otx, "ip138": reverse_ip138, "ipchaxun": reverse_ipchaxun}


def _run_source(name, fn, ip):
    try:
        return name, fn(ip)
    except OtxStopped:
        return name, "skipped"
    except Exception as e:
        return name, f"err:{type(e).__name__}"


def reverse_lookup(ip):
    """三个源并行查同一个种子（各自限速），结果取并集。"""
    domains, stats = set(), {}
    with cf.ThreadPoolExecutor(len(REVERSE_SOURCES)) as ex:
        futs = [ex.submit(_run_source, n, fn, ip) for n, fn in REVERSE_SOURCES.items()]
        for f in futs:
            name, got = f.result()
            if isinstance(got, set):
                stats[name] = len(got)
                domains |= got
            else:
                stats[name] = got
    return ip, domains, stats


def doh_a(domain):
    for attempt in range(3):
        try:
            r = session.get(DOH_URL, params={"name": domain, "type": "A"}, timeout=10)
            r.raise_for_status()
            return domain, [a["data"] for a in r.json().get("Answer", []) if a.get("type") == 1]
        except Exception:
            time.sleep(1 + attempt)
    return domain, []


def asn_of(ip):
    rev = ".".join(reversed(ip.split(".")))
    try:
        r = session.get(DOH_URL, params={"name": f"{rev}.origin.asn.cymru.com", "type": "TXT"}, timeout=10)
        r.raise_for_status()
        asns = set()
        for a in r.json().get("Answer", []):
            first = a.get("data", "").strip('"').split("|")[0]
            asns |= {int(t) for t in first.split() if t.isdigit()}
        return asns
    except Exception:
        return set()


# ---------- 验证 ----------

_ctx = ssl.create_default_context()


def parse_trace(buf):
    """只接受 2xx 响应里的 colo。"""
    head, _, body = buf.partition(b"\r\n\r\n")
    m = re.match(rb"HTTP/\d(?:\.\d)? (\d{3})", head)
    if not m or not 200 <= int(m.group(1)) < 300:
        return None
    m = re.search(rb"(?m)^colo=([A-Z]{3})\s*$", body)
    return m.group(1).decode() if m else None


def trace(ip, host=VERIFY_HOST, timeout=6):
    """TLS(SNI=host, 校验证书) 连 ip:443，GET /cdn-cgi/trace，返回 colo 或 None。"""
    try:
        with socket.create_connection((ip, 443), timeout=timeout) as raw:
            with _ctx.wrap_socket(raw, server_hostname=host) as s:
                s.settimeout(timeout)
                s.sendall(f"GET /cdn-cgi/trace HTTP/1.1\r\nHost: {host}\r\n"
                          f"User-Agent: {USER_AGENT}\r\nConnection: close\r\n\r\n".encode())
                buf = b""
                while len(buf) < 8192:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
        return parse_trace(buf)
    except Exception:
        return None


def check_proxyip(ip):
    if not CHECK_API:
        return None
    try:
        r = session.get(CHECK_API, params={"proxyip": f"{ip}:443"}, timeout=30)
        if not r.ok:
            return None
        j = r.json()
        if not j.get("success"):
            return None
        exit_ = (j.get("probe_results", {}).get("ipv4") or {}).get("exit") or {}
        return exit_.get("country") or "XX"
    except Exception:
        return None


def classify(ip, colo, asns, proxy_country):
    if asns & CF_ASNS:
        tag = "cf-asn"
    elif proxy_country:
        tag = f"proxyip-{proxy_country}"
    else:
        tag = "relay"
    return f"{ip}:443#{tag}-{colo}"


# ---------- 主流程 ----------

def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    seeds_all = [ip for ip in read_ips(SEEDS_FILE) if is_public(ip)]
    seeds = dedupe_by_24(seeds_all)[:MAX_SEEDS]
    if not seeds:
        log(f"{SEEDS_FILE} 里没有可用种子（可直接放 FOFA 导出的 CSV）")
        return 1
    log(f"种子 {len(seeds_all)}，按 /24 去重后用 {len(seeds)}")

    cf_nets = load_cf_networks()
    known = load_known()

    # 1. 反查（每个种子三源并行、各自限速；种子之间并发 8，OTX 慢所以要并发）
    domains, per_seed = set(), {}
    with cf.ThreadPoolExecutor(8) as ex:
        for ip, doms, stats in ex.map(reverse_lookup, seeds):
            per_seed[ip] = stats
            domains |= doms
    log(f"反查域名 {len(domains)}")

    # 2. DoH 解析
    resolved = {}
    with cf.ThreadPoolExecutor(16) as ex:
        for d, ips in ex.map(doh_a, sorted(domains)):
            resolved[d] = ips
    all_ips = {ip for ips in resolved.values() for ip in ips}

    # 3. 过滤
    seed_set = set(seeds_all)
    stats = {"resolved_ips": len(all_ips)}
    cands = []
    for ip in sorted(all_ips):
        if not is_public(ip) or ip in seed_set:
            continue
        if in_networks(ip, cf_nets):
            stats["cf_range"] = stats.get("cf_range", 0) + 1
            continue
        if ip in known:
            stats["known"] = stats.get("known", 0) + 1
            continue
        cands.append(ip)
    stats["new_candidates"] = len(cands)
    log(f"过滤：{stats}")

    # 4. 验证
    alive = {}
    with cf.ThreadPoolExecutor(32) as ex:
        for ip, colo in zip(cands, ex.map(trace, cands)):
            if colo:
                alive[ip] = colo
    stats["alive"] = len(alive)

    lines = []
    with cf.ThreadPoolExecutor(8) as ex:
        ips = sorted(alive)
        asn_list = list(ex.map(asn_of, ips))
        proxy_list = list(ex.map(lambda i, a: None if a & CF_ASNS else check_proxyip(i), ips, asn_list))
    for ip, asns, pc in zip(ips, asn_list, proxy_list):
        lines.append(classify(ip, alive[ip], asns, pc))
    stats["proxyip"] = sum(1 for l in lines if "#proxyip-" in l)
    log(f"验证：活 {stats['alive']}，ProxyIP 可用 {stats['proxyip']}")

    with open(f"{OUT_DIR}/candidates.txt", "w") as f:
        f.write("\n".join(cands) + ("\n" if cands else ""))
    with open(f"{OUT_DIR}/alive.txt", "w") as f:
        f.write("\n".join(lines) + ("\n" if lines else ""))
    with open(f"{OUT_DIR}/seeds_next.txt", "w") as f:
        f.write("\n".join(sorted(alive)) + ("\n" if alive else ""))
    with open(f"{OUT_DIR}/report.json", "w") as f:
        json.dump({"verify_host": VERIFY_HOST, "seeds_used": len(seeds), "domains": len(domains),
                   "stats": stats, "per_seed": per_seed}, f, ensure_ascii=False, indent=1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
