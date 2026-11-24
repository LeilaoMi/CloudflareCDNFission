# CloudflareCDNFission（LeilaoMi 改造版）

只做一件事：**找 IP**。从测绘平台和反查裂变里收集“美国、走 Cloudflare 的反代”候选 IP，去掉 Cloudflare 官方段，输出一个纯 IP 列表。

**不做可用性验证。** 列表里的 IP 可能已失效，请在自己的工具里验证后再用（例如 [preferred-sub-generator](https://github.com/LeilaoMi/preferred-sub-generator) 的美国初筛 + 国内三网实测）。

原版思路来自 [snowfal1/CloudflareCDNFission](https://github.com/snowfal1/CloudflareCDNFission)。

## 输出

| 文件 | 内容 |
|---|---|
| `output/ips.txt` | 一行一个 IPv4，累积去重，已剔除 Cloudflare 官方段和私网地址 |
| `output/report.json` | 本轮各来源的数量 |
| `output/netlas_state.json` | Netlas 切片进度 |

直接引用：`https://raw.githubusercontent.com/LeilaoMi/CloudflareCDNFission/main/output/ips.txt`

## 一轮做什么

1. **Netlas**（有 `NETLAS_API_KEY` 时）：查询 `http.headers.server:"cloudflare" AND port:443 AND http.status_code:403 AND geo.country:US AND host_type:ip`。免费版单次最多 200 条，所以按 IP 段对半切片，段内 ≤200 条就整段下载；进度存 `netlas_state.json`，每轮最多 `NETLAS_MAX_REQUESTS` 次请求，几天轮完一遍后从头再来。
2. **种子**：`seeds.txt` + secret `FISSION_SEEDS`（一行一个 IP，或直接贴 FOFA CSV）+ 本轮 Netlas 拿到的 IP，按 /24 去重。
3. **裂变**：反查同 IP 绑定过的域名（AlienVault OTX passive DNS + site.ip138.com + ipchaxun.com，取并集），再经 DoH（dns.google）解析回 IPv4。
4. **过滤合并**：剔除 Cloudflare 官方段、私网 / 保留地址，并进 `output/ips.txt`。

## GitHub Actions

`Fission` 工作流每天北京时间 04:30 跑一次，也可手动触发；结果提交回仓库。

- Secret `NETLAS_API_KEY`（推荐）：netlas.io 免费注册，Community 版约 50 次请求/天。
- Secret `OTX_API_KEY`（推荐）：otx.alienvault.com 免费注册；不填很快会被 429 限流。
- Secret `FISSION_SEEDS`（可选）：额外种子。
- Variable `NETLAS_QUERY`（可选）：换查询语句（换了会从头切片）。

## 本地运行

```bash
pip install --require-hashes -r requirements.txt
NETLAS_API_KEY=... OTX_API_KEY=... python Fission.py
```

| 环境变量 | 默认 | 说明 |
|---|---|---|
| `NETLAS_API_KEY` | 空（跳过 Netlas） | Netlas key |
| `NETLAS_QUERY` | 见上 | Netlas 查询 |
| `NETLAS_MAX_REQUESTS` | `45` | 每轮最多调 Netlas 多少次 |
| `MAX_SEEDS` | `200` | 每轮最多裂变多少个种子，`0` = 不裂变 |
| `OTX_API_KEY` | 空 | OTX key |
| `OTX_TIMEOUT` | `60` | OTX 单次超时秒数 |
| `OTX_BUDGET` | `1500` | 本轮花在 OTX 上的总秒数上限 |

在有 HTTP 代理的环境里，ip138 / ipchaxun 可能拒绝代理连接，需要直连。

## 边界

只查询公开测绘数据和被动 DNS，不做任何主动扫描。
