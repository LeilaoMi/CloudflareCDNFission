# CloudflareCDNFission -- 只采集 IP（2026-11-25 改造）
#
# 本仓库只负责“找 IP”，不做可用性验证；验证交给下游（如 preferred-sub-generator）或使用者自己。
#
# 一轮流程：
#   1. Netlas（可选，需 NETLAS_API_KEY）：按 IP 段切片下载“美国、server=cloudflare、443、403”的主机，
#      进度存在 output/netlas_state.json，每轮只花 NETLAS_MAX_REQUESTS 次请求，几轮轮完一遍再从头开始
#   2. 种子 = seeds.txt + secret FISSION_SEEDS + 本轮 Netlas 新 IP，按 /24 去重
#   3. 反查同 IP 域名（AlienVault OTX passive DNS + ip138 + ipchaxun，取并集）
#   4. DoH 解析回 IPv4
#   5. 丢掉 Cloudflare 官方段和私网/保留地址
#   6. 并进 output/ips.txt（一行一个 IP，累积去重），写 output/report.json
#
# 环境变量：
#   NETLAS_API_KEY       Netlas key（可选）；不填就跳过 Netlas
#   NETLAS_QUERY         Netlas 查询，默认见 NETLAS_DEFAULT_QUERY
#   NETLAS_MAX_REQUESTS  本轮最多调多少次 Netlas API，默认 45（免费版约 50 次/天）
#   MAX_SEEDS            每轮最多用多少个种子做裂变（/24 去重后），默认 200；0 表示不裂变
#   OTX_API_KEY          AlienVault OTX 免费 key（可选；不填很快会被 429 限流）
#   OTX_TIMEOUT          OTX 单次请求超时秒数，默认 60
#   OTX_BUDGET           本轮花在 OTX 上的总秒数上限，默认 1500

import concurrent.futures as cf
import ipaddress
import json
import os
import re
import datetime
import email.utils
import sys
import threading
import time

import requests
from lxml import etree

SEEDS_FILE = "seeds.txt"
OUT_DIR = "output"
IPS_FILE = f"{OUT_DIR}/ips.txt"
NETLAS_STATE_FILE = f"{OUT_DIR}/netlas_state.json"

NETLAS_API_KEY = os.environ.get("NETLAS_API_KEY", "").strip()
NETLAS_DEFAULT_QUERY = ('http.headers.server:"cloudflare" AND port:443 AND http.status_code:403 '
                        'AND geo.country:US AND host_type:ip')
NETLAS_QUERY = os.environ.get("NETLAS_QUERY", "").strip() or NETLAS_DEFAULT_QUERY
NETLAS_MAX_REQUESTS = int(os.environ.get("NETLAS_MAX_REQUESTS", "45"))
NETLAS_API = "https://app.netlas.io/api"
NETLAS_PAGE = 200          # 免费版单次下载上限
NETLAS_MIN_PREFIX = 24     # 切到 /24 还超就只拿前 200 条
NETLAS_DEADLINE = float(os.environ.get("NETLAS_DEADLINE", "900"))  # Netlas 阶段最多花多少秒
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
        addr = ipaddress.ip_address(ip)
        return addr.version == 4 and addr.is_global and not addr.is_multicast
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


_otx_state = {"deadline": None, "stopped": None, "cooldown_until": 0.0}
_otx_lock = threading.Lock()


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
        # 所有线程共用同一个冷却截止时间；等待后再查一次预算
        cool = _otx_state["cooldown_until"] - time.monotonic()
        if cool > 0:
            if cool > _otx_remaining():
                _otx_stop(f"冷却还需 {int(cool)}s，超过剩余预算")
            time.sleep(cool)
        if _otx_state["stopped"]:
            raise OtxStopped(_otx_state["stopped"])
        if _otx_remaining() <= 0:
            _otx_stop(f"超过预算 {OTX_BUDGET}s")
        r = session.get(url, headers=headers, timeout=min(OTX_TIMEOUT, max(1.0, _otx_remaining())))
        if r.status_code not in (429, 502, 503, 504):
            break
        # 限流或网关超时：按服务端给的 Retry-After 等满；等不起就停用 OTX，不提前重试
        wait = retry_after_seconds(r.headers.get("Retry-After"))
        if wait is None:
            wait = 15.0 * (attempt + 1)
        if wait > _otx_remaining():
            _otx_stop(f"HTTP {r.status_code}，要求等待 {int(wait)}s，超过剩余预算")
        with _otx_lock:
            _otx_state["cooldown_until"] = max(_otx_state["cooldown_until"], time.monotonic() + wait)
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


# ---------- Netlas ----------

def _netlas(method, path, **kw):
    headers = {"X-API-Key": NETLAS_API_KEY}
    r = session.request(method, f"{NETLAS_API}{path}", headers=headers, timeout=120, **kw)
    if r.status_code == 429:
        raise RuntimeError("Netlas 429 限流")
    r.raise_for_status()
    return r.json()


def split_cidr(cidr):
    net = ipaddress.ip_network(cidr)
    return [str(n) for n in net.subnets(prefixlen_diff=1)]


def load_netlas_state():
    try:
        with open(NETLAS_STATE_FILE, encoding="utf-8") as f:
            st = json.load(f)
        if st.get("query") == NETLAS_QUERY and isinstance(st.get("queue"), list):
            return st
    except (OSError, ValueError):
        pass
    return {"query": NETLAS_QUERY, "queue": ["0.0.0.0/0"], "cycles_done": 0, "pending": None}


def save_netlas_state(st):
    if st is None:
        return
    with open(NETLAS_STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(st, f, ensure_ascii=False, indent=1)


def netlas_slice_query(cidr):
    return f'({NETLAS_QUERY}) AND ip:"{cidr}"'


def collect_netlas():
    """按 IP 段切片：段内 <=200 条就整段下载，否则对半切再排队。

    返回 (本轮 IPv4 集合, 统计, 新状态)。状态由调用方在结果写盘后保存。
    已数过但没来得及下载的切片记在 pending，下轮直接下载。
    """
    if not NETLAS_API_KEY or NETLAS_MAX_REQUESTS <= 0:
        return set(), {"skipped": True}, None
    st = load_netlas_state()
    st.setdefault("pending", None)
    got, used = set(), 0
    stats = {"count_calls": 0, "downloads": 0, "slices_done": 0}
    stop_at = time.monotonic() + NETLAS_DEADLINE
    while used < NETLAS_MAX_REQUESTS and time.monotonic() < stop_at:
        try:
            if st["pending"]:
                cidr, n = st["pending"]["cidr"], st["pending"]["count"]
                body = {"q": netlas_slice_query(cidr), "fields": ["ip"], "source_type": "include",
                        "size": min(n, NETLAS_PAGE), "type": "json", "indices": ""}
                rows = _netlas("POST", "/responses/download/", json=body)
                used += 1
                stats["downloads"] += 1
                got |= {r.get("data", {}).get("ip") for r in rows} - {None}
                st["pending"] = None
                stats["slices_done"] += 1
                continue
            if not st["queue"]:
                st["queue"] = ["0.0.0.0/0"]
                st["cycles_done"] = st.get("cycles_done", 0) + 1
                break
            cidr = st["queue"][0]
            n = _netlas("GET", "/responses_count/", params={"q": netlas_slice_query(cidr)})["count"]
            used += 1
            stats["count_calls"] += 1
            st["queue"].pop(0)
            if n > NETLAS_PAGE and ipaddress.ip_network(cidr).prefixlen < NETLAS_MIN_PREFIX:
                st["queue"] = split_cidr(cidr) + st["queue"]
            elif n:
                st["pending"] = {"cidr": cidr, "count": n}
            else:
                stats["slices_done"] += 1
        except Exception as e:
            log(f"Netlas 停止：{e}")
            stats["error"] = str(e)[:200]
            break
    stats.update(requests=used, ips=len(got), queue_left=len(st["queue"]) + bool(st["pending"]),
                 cycles_done=st.get("cycles_done", 0))
    log(f"Netlas：{stats}")
    return {ip for ip in got if IPV4_RE.fullmatch(ip)}, stats, st


# ---------- 主流程 ----------

def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    cf_nets = load_cf_networks()

    def keep(ip):
        return is_public(ip) and not in_networks(ip, cf_nets)

    # 1. Netlas
    netlas_ips, netlas_stats, netlas_state = collect_netlas()
    netlas_ips = {ip for ip in netlas_ips if keep(ip)}

    # 2. 种子
    seeds_all = [ip for ip in read_ips(SEEDS_FILE) + sorted(netlas_ips) if is_public(ip)]
    seeds = dedupe_by_24(seeds_all)[:MAX_SEEDS] if MAX_SEEDS > 0 else []
    log(f"种子 {len(seeds_all)}，按 /24 去重后裂变 {len(seeds)}")

    # 3. 反查 + 4. DoH 解析
    domains, per_seed, fission_ips = set(), {}, set()
    if seeds:
        with cf.ThreadPoolExecutor(8) as ex:
            for ip, doms, st in ex.map(reverse_lookup, seeds):
                per_seed[ip] = st
                domains |= doms
        log(f"反查域名 {len(domains)}")
        with cf.ThreadPoolExecutor(16) as ex:
            for _, ips in ex.map(doh_a, sorted(domains)):
                fission_ips.update(ip for ip in ips if keep(ip))

    # 5. 合并输出（累积去重）
    old = {ip for ip in read_ips(IPS_FILE) if keep(ip)}
    found = netlas_ips | fission_ips | {ip for ip in seeds_all if keep(ip)}
    merged = sorted(old | found, key=ipaddress.ip_address)
    with open(IPS_FILE, "w") as f:
        f.write("\n".join(merged) + ("\n" if merged else ""))
    save_netlas_state(netlas_state)  # 结果落盘后再推进 Netlas 进度
    stats = {"netlas": netlas_stats, "seeds_used": len(seeds), "domains": len(domains),
             "netlas_ips": len(netlas_ips), "fission_ips": len(fission_ips),
             "new_this_run": len(found - old), "total": len(merged)}
    with open(f"{OUT_DIR}/report.json", "w") as f:
        json.dump({"stats": stats, "per_seed": per_seed}, f, ensure_ascii=False, indent=1)
    log(f"完成：{stats}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
