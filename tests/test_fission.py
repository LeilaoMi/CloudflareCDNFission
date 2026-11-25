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


def test_retry_after_seconds_and_http_date():
    import datetime
    now = datetime.datetime(2026, 11, 25, 0, 0, 0, tzinfo=datetime.timezone.utc)
    assert F.retry_after_seconds("600") == 600.0
    assert F.retry_after_seconds("Wed, 25 Nov 2026 00:10:00 GMT", now=now) == 600.0
    assert F.retry_after_seconds("nonsense") is None
    assert F.retry_after_seconds(None) is None


def test_split_cidr():
    assert F.split_cidr("0.0.0.0/0") == ["0.0.0.0/1", "128.0.0.0/1"]
    assert F.split_cidr("64.0.0.0/8") == ["64.0.0.0/9", "64.128.0.0/9"]


def test_netlas_state_resets_on_query_change(tmp_path, monkeypatch):
    p = tmp_path / "st.json"
    p.write_text('{"query": "old", "queue": ["1.0.0.0/8"], "cycles_done": 2}')
    monkeypatch.setattr(F, "NETLAS_STATE_FILE", str(p))
    assert F.load_netlas_state()["queue"] == ["0.0.0.0/0"]
    p.write_text('{"query": %s, "queue": ["1.0.0.0/8"]}' % __import__("json").dumps(F.NETLAS_QUERY))
    assert F.load_netlas_state()["queue"] == ["1.0.0.0/8"]


def test_collect_netlas_splits_and_downloads(tmp_path, monkeypatch):
    monkeypatch.setattr(F, "NETLAS_STATE_FILE", str(tmp_path / "st.json"))
    monkeypatch.setattr(F, "NETLAS_API_KEY", "k")
    monkeypatch.setattr(F, "NETLAS_MAX_REQUESTS", 10)
    counts = {"0.0.0.0/0": 300, "0.0.0.0/1": 150, "128.0.0.0/1": 0}

    def fake(method, path, **kw):
        if path == "/responses_count/":
            cidr = kw["params"]["q"].rsplit('ip:"', 1)[1].rstrip('"')
            return {"count": counts[cidr]}
        return [{"data": {"ip": "64.1.2.3"}}, {"data": {"ip": "64.1.2.3"}}]

    monkeypatch.setattr(F, "_netlas", fake)
    ips, st, state = F.collect_netlas()
    assert ips == {"64.1.2.3"}
    assert st["count_calls"] == 3 and st["downloads"] == 1
    assert state["pending"] is None


def test_collect_netlas_keeps_pending_when_budget_runs_out(tmp_path, monkeypatch):
    monkeypatch.setattr(F, "NETLAS_STATE_FILE", str(tmp_path / "st.json"))
    monkeypatch.setattr(F, "NETLAS_API_KEY", "k")
    monkeypatch.setattr(F, "NETLAS_MAX_REQUESTS", 1)
    calls = []

    def fake(method, path, **kw):
        calls.append(path)
        if path == "/responses_count/":
            return {"count": 5}
        return [{"data": {"ip": "64.1.2.3"}}]

    monkeypatch.setattr(F, "_netlas", fake)
    _, _, state = F.collect_netlas()
    assert state["pending"] == {"cidr": "0.0.0.0/0", "count": 5}
    F.save_netlas_state(state)
    ips, _, state = F.collect_netlas()
    assert ips == {"64.1.2.3"} and calls == ["/responses_count/", "/responses/download/"]


def test_slice_query_is_grouped(monkeypatch):
    monkeypatch.setattr(F, "NETLAS_QUERY", "port:443 OR port:8443")
    assert F.netlas_slice_query("1.0.0.0/8") == '(port:443 OR port:8443) AND ip:"1.0.0.0/8"'


def test_is_public_rejects_multicast():
    assert not F.is_public("224.0.0.1")

