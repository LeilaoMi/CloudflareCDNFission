import ipaddress
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import Fission as F  # noqa: E402


def test_read_ips_from_fofa_csv(tmp_path):
    p = tmp_path / "s.csv"
    p.write_text("host,ip,port\nexample.com,1.2.3.4,443\nfoo,1.2.3.4,443\nbar,5.6.7.8,443\n")
    assert F.read_ips(str(p)) == ["1.2.3.4", "5.6.7.8"]


def test_dedupe_by_24():
    assert F.dedupe_by_24(["1.2.3.4", "1.2.3.9", "1.2.4.1"]) == ["1.2.3.4", "1.2.4.1"]


def test_is_public():
    assert F.is_public("8.8.8.8")
    assert not F.is_public("198.18.0.1")
    assert not F.is_public("10.0.0.1")
    assert not F.is_public("nope")


def test_in_networks():
    nets = [ipaddress.ip_network(c) for c in F.CF_IPV4_FALLBACK]
    assert F.in_networks("104.16.1.1", nets)
    assert not F.in_networks("135.84.76.120", nets)


def test_clean_domains():
    got = F.clean_domains(["WWW.Example.COM.", "*.foo.org", "1.2.3.4", "bad_domain", "", None])
    assert got == {"www.example.com", "foo.org"}


def test_classify():
    assert F.classify("1.1.1.1", "SJC", {13335}, "US") == "1.1.1.1:443#cf-asn-SJC"
    assert F.classify("2.2.2.2", "LAX", {36352}, "US") == "2.2.2.2:443#proxyip-US-LAX"
    assert F.classify("3.3.3.3", "PDX", set(), None) == "3.3.3.3:443#relay-PDX"


def test_parse_trace_requires_2xx():
    ok = b"HTTP/1.1 200 OK\r\nServer: cloudflare\r\n\r\nfl=1\nh=x\ncolo=SJC\n"
    bad = b"HTTP/1.1 503 Service Unavailable\r\n\r\ncolo=SJC\n"
    assert F.parse_trace(ok) == "SJC"
    assert F.parse_trace(bad) is None
    assert F.parse_trace(b"garbage colo=SJC") is None


def test_retry_after_seconds_and_http_date():
    import datetime
    now = datetime.datetime(2026, 11, 25, 0, 0, 0, tzinfo=datetime.timezone.utc)
    assert F.retry_after_seconds("600") == 600.0
    assert F.retry_after_seconds("Wed, 25 Nov 2026 00:10:00 GMT", now=now) == 600.0
    assert F.retry_after_seconds("nonsense") is None
    assert F.retry_after_seconds(None) is None


def test_check_proxyip_rejects_non_2xx(monkeypatch):
    class Resp:
        ok = False
        def json(self):
            return {"success": True, "probe_results": {"ipv4": {"exit": {"country": "US"}}}}
    monkeypatch.setattr(F, "CHECK_API", "https://example.invalid/check")
    monkeypatch.setattr(F.session, "get", lambda *a, **k: Resp())
    assert F.check_proxyip("192.0.2.1") is None
