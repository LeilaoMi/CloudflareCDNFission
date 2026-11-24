# CloudflareCDNFission -- Route C 最小改造（2026-11-25）
#
# 改动（只改裂变候选池的产出质量，不加验证层）：
#   1. 域名 -> IP 改用 DoH（dns.google）代替本地 nslookup 子进程。
#      沙箱 / 容器里的本地 DNS 常被合成，nslookup 在那种环境下会返回
#      198.18.0.0/15 这类不可路由地址；DoH 直接问公开解析器，结果可复现。
#   2. 先滤再验：IP 写回 Fission_ip.txt 之前先过两道过滤 --
#      (a) Cloudflare 官方 IPv4 段（下面 CF_IPV4_RANGES）；
#      (b) ASN 13335 / 209242（Cloudflare 自身 ASN），用 Team Cymru 的
#          DNS ASN 查询（同样走 DoH，不新增依赖）。
#      查不到 ASN 时不丢弃该 IP（宁可留给下游验证器判，不静默丢数），
#      只有确认为 13335 / 209242 时才丢弃。过滤结果会打印计数。
#   3. 反查站点只留 ip138 与 ipchaxun，删掉已死的 dnsdblookup
#      （2026-11-25 实测：dnsdblookup.com 15 秒超时，0 字节）。
#      两个站的请求改为串行 + 每次间隔至少 1 秒，失败自动换站重试，
#      两站都失败返回空列表，不抛异常中断整批。
#   4. 去掉 fake_useragent（它启动时要拉远程 UA 列表），改用固定 UA。
#
# 不做的事：不加延迟 / TLS / SNI 验证层，不改输出文件名，
# 不碰 Fission_ip.txt 之外的任何文件。候选池仍只是候选池，
# 能不能当 ProxyIP 用，由下游的 checker / Globalping 说了算。
# 本文件在沙箱里没有被执行过（安全策略：不直接运行 fork 代码），
# 请以 CodeRabbit 审查 + 审阅者的人工阅读为准。

# 标准库
import concurrent.futures
import ipaddress
import os
import threading
import time

# 第三方库
import requests
from lxml import etree
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# 文件配置
ips = "Fission_ip.txt"
domains = "Fission_domain.txt"
dns_result = "dns_result.txt"

# 并发数配置（反查站点从 20 降到 5；DoH 解析 10，解析器是公开服务不是被爬站点）
max_workers_request = 5    # 并发反查请求数量
max_workers_doh = 10       # 并发 DoH 查询数量

# 反查站点之间的最小间隔（秒），两个站共用一把锁，串行请求
MIN_INTERVAL_PER_SITE = 1.0
_site_lock = threading.Lock()

# DoH 解析器（与 preferred-sub-generator 的 cmliu-dns 来源同一路）
DOH_URL = "https://dns.google/resolve"

# Cloudflare 官方 IPv4 段（https://www.cloudflare.com/ips/ 公开清单）
# 只是过滤“已知的 CF 边缘 IP”，不是优选 IP 的白名单；清单若有新增需同步更新。
CF_IPV4_RANGES = [
    "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "104.16.0.0/13", "104.24.0.0/14", "108.162.192.0/18",
    "131.0.72.0/22", "141.101.64.0/18", "162.158.0.0/15",
    "172.64.0.0/13", "173.245.48.0/20", "188.114.96.0/20",
    "190.93.240.0/20", "197.234.240.0/22", "198.41.128.0/17",
]
_CF_NETWORKS = [ipaddress.ip_network(c) for c in CF_IPV4_RANGES]

# Cloudflare 自身 ASN：13335（主）/ 209242（Cloudflare London）
CF_ASNS = {13335, 209242}

# 反查网站配置：dnsdblookup 已死（2026-11-25 实测超时），删掉
sites_config = {
    "site_ip138": {
        "url": "https://site.ip138.com/",
        "xpath": '//ul[@id="list"]/li/a'
    },
    "ipchaxun": {
        "url": "https://ipchaxun.com/",
        "xpath": '//div[@id="J_domain"]/p/a'
    }
}

# 固定 UA：不再用 fake_useragent 拉远程 UA 列表
USER_AGENT = "Mozilla/5.0 (compatible; CloudflareCDNFission/route-c)"


# 设置会话
def setup_session():
    session = requests.Session()
    retries = Retry(total=5, backoff_factor=0.3, status_forcelist=[500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retries)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session


# 生成请求头
def get_headers():
    return {
        'User-Agent': USER_AGENT,
        'Accept': '*/*',
        'Connection': 'keep-alive',
    }


# 查询域名的函数，自动重试和切换网站（两站都失败返回空列表）
def fetch_domains_for_ip(ip_address, session, attempts=0, used_sites=None):
    print(f"Fetching domains for {ip_address}...")
    if used_sites is None:
        used_sites = []
    if attempts >= len(sites_config):  # 每个站最多试一次
        return []

    # 选择一个未使用的网站进行查询
    available_sites = {key: value for key, value in sites_config.items() if key not in used_sites}
    if not available_sites:
        return []

    # 固定按字典顺序取站，不再随机挑：行为可复现，出问题先查 ip138
    site_key = sorted(available_sites.keys())[0]
    site_info = available_sites[site_key]
    used_sites.append(site_key)

    try:
        # 串行 + 限速：同一时间只有一个反查请求在跑，间隔至少 1 秒
        with _site_lock:
            time.sleep(MIN_INTERVAL_PER_SITE)
            url = f"{site_info['url']}{ip_address}/"
            headers = get_headers()
            response = session.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            html_content = response.text

        parser = etree.HTMLParser()
        tree = etree.fromstring(html_content, parser)
        a_elements = tree.xpath(site_info['xpath'])
        found = [a.text.strip().lower() for a in a_elements
                 if a.text and a.text.strip() and '.' in a.text.strip()]

        if found:
            print(f"succeed to fetch domains for {ip_address} from {site_info['url']}")
            return found
        raise Exception("No domains found")

    except Exception as e:
        print(f"Error fetching domains for {ip_address} from {site_info['url']}: {e}")
        return fetch_domains_for_ip(ip_address, session, attempts + 1, used_sites)


# 并发处理所有IP地址
def fetch_domains_concurrently(ip_addresses):
    session = setup_session()
    domains = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers_request) as executor:
        future_to_ip = {executor.submit(fetch_domains_for_ip, ip, session): ip for ip in ip_addresses}
        for future in concurrent.futures.as_completed(future_to_ip):
            domains.extend(future.result())

    return list(set(domains))


# DoH 查询单个域名，返回它的 A 记录 IP 列表（代替原来的 nslookup 子进程）
def doh_lookup(domain, session):
    try:
        response = session.get(DOH_URL, params={"name": domain, "type": "A"}, timeout=10)
        response.raise_for_status()
        data = response.json()
        if data.get("Status") != 0:
            return domain, []
        ips = [a["data"] for a in data.get("Answer", [])
               if a.get("type") == 1 and a.get("data")]
        return domain, ips
    except Exception as e:
        print(f"Error DoH lookup for {domain}: {e}")
        return domain, []


# Team Cymru DNS ASN 查询（走 DoH）：查不到返回 None，调用方不丢弃该 IP
_asn_cache = {}

def lookup_asn(ip, session):
    if ip in _asn_cache:
        return _asn_cache[ip]
    asn = None
    try:
        reversed_ip = '.'.join(reversed(ip.split('.')))
        response = session.get(
            DOH_URL,
            params={"name": f"{reversed_ip}.origin.asn.cymru.com", "type": "TXT"},
            timeout=10,
        )
        response.raise_for_status()
        data = response.json()
        for answer in data.get("Answer", []):
            if answer.get("type") == 16:
                first_field = answer.get("data", "").strip('"').split("|")[0].strip()
                if first_field.isdigit():
                    asn = int(first_field)
                    break
    except Exception as e:
        print(f"Error ASN lookup for {ip}: {e}")
    _asn_cache[ip] = asn
    return asn


def is_cloudflare_ip(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True  # 非法地址按 CF 段处理：直接丢弃
    return any(addr in net for net in _CF_NETWORKS)


# 先滤再验：公网 IP -> 去 CF 段 -> 去 CF ASN（13335 / 209242）
# 返回（保留的 IP 集合，各阶段丢弃数），供日志与调用方核对
def filter_candidate_ips(ip_set, session):
    kept = set()
    dropped_non_global = 0
    dropped_cf_range = 0
    dropped_cf_asn = 0
    for ip in sorted(ip_set):
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            dropped_non_global += 1
            continue
        if not addr.is_global:
            dropped_non_global += 1
            continue
        if is_cloudflare_ip(ip):
            dropped_cf_range += 1
            continue
        asn = lookup_asn(ip, session)
        if asn is not None and asn in CF_ASNS:
            dropped_cf_asn += 1
            continue
        kept.add(ip)
    return kept, dropped_non_global, dropped_cf_range, dropped_cf_asn


# 通过域名列表获取绑定过的所有 ip（DoH 版）
def perform_dns_lookups(domain_filename, result_filename, unique_ipv4_filename):
    try:
        # 读取域名列表
        with open(domain_filename, 'r') as file:
            domains = file.read().splitlines()

        session = setup_session()

        # DoH 查询每个域名
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers_doh) as executor:
            results = list(executor.map(lambda d: doh_lookup(d, session), domains))

        # 写入查询结果到文件（格式改为 "域名: ip1, ip2"，不再是 nslookup 原始输出）
        with open(result_filename, 'w') as output_file:
            for domain, ips in results:
                output_file.write(f"{domain}: {', '.join(ips)}\n")

        # 从结果中提取所有 IPv4 地址
        ipv4_addresses = set()
        for _, ips in results:
            ipv4_addresses.update(ips)

        with open(unique_ipv4_filename, 'r') as file:
            exist_list = {ip.strip() for ip in file}

        # 先滤再验：只把非 CF 段、非 CF ASN 的公网 IP 写回
        filtered, dropped_non_global, dropped_cf_range, dropped_cf_asn = \
            filter_candidate_ips(ipv4_addresses, session)
        print(f"filter: kept {len(filtered)}, dropped non-global {dropped_non_global}, "
              f"dropped CF range {dropped_cf_range}, dropped CF ASN {dropped_cf_asn}")
        filtered.update(exist_list)

        # 保存 IP 地址（排序后写回，结果可复现）
        with open(unique_ipv4_filename, 'w') as output_file:
            for address in sorted(filtered):
                output_file.write(address + '\n')

    except Exception as e:
        print(f"Error performing DNS lookups: {e}")


# 主函数
def main():
    # 判断是否存在 IP 文件
    if not os.path.exists(ips):
        with open(ips, 'w') as file:
            file.write("")

    # 判断是否存在域名文件
    if not os.path.exists(domains):
        with open(domains, 'w') as file:
            file.write("")

    # IP 反查域名
    with open(ips, 'r') as ips_txt:
        ip_list = [ip.strip() for ip in ips_txt if ip.strip()]

    domain_list = fetch_domains_concurrently(ip_list)
    print("域名列表为")
    print(domain_list)
    with open("Fission_domain.txt", "r") as file:
        exist_list = [domain.strip() for domain in file if domain.strip()]

    domain_list = list(set(domain_list + exist_list))

    with open("Fission_domain.txt", "w") as output:
        for domain in sorted(domain_list):
            output.write(domain + "\n")
    print("IP -> 域名 已完成")

    # 域名解析 IP（DoH + 先滤再验）
    perform_dns_lookups(domains, dns_result, ips)
    print("域名 -> IP 已完成")


# 程序入口
if __name__ == '__main__':
    main()
