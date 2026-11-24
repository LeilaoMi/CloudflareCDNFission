# CloudflareCDNFission（LeilaoMi 改造版）

从一批**已验证可用**的反代 IP 出发，反查同 IP 绑定过的域名，再把域名解析回 IP，筛出新的 Cloudflare 反代 / ProxyIP 候选，并当场验证。

原版思路来自 [snowfal1/CloudflareCDNFission](https://github.com/snowfal1/CloudflareCDNFission)。

## 一轮做什么

1. **种子**：`seeds.txt`，一行一个 IP，也可以直接放 FOFA 导出的 CSV（自动抽 IPv4）。按 /24 去重。
2. **反查**：AlienVault OTX passive DNS（JSON API）+ site.ip138.com + ipchaxun.com，三源取并集，每源每秒最多 1 次。
3. **解析**：域名走 DoH（dns.google）解析回 IPv4。
4. **过滤**：丢掉 Cloudflare 公开段、私网 / 保留地址、种子本身、`known.txt` 和 `KNOWN_URLS` 里已有的 IP。
5. **验证**：对候选做 TLS（SNI=`VERIFY_HOST`，校验证书）+ `GET /cdn-cgi/trace`，拿到 colo 才算活。
6. **打标签**：
   - `cf-asn`：由 Cloudflare ASN（13335 / 209242）代播，能当优选入口，不能当 ProxyIP
   - `proxyip-XX`：通过 `CHECK_API` 的 ProxyIP 检测，XX 为出口国家
   - `relay`：其余活的反代

输出在 `output/`：

| 文件 | 内容 |
|---|---|
| `alive.txt` | `ip:443#标签-colo`，可直接给订阅生成器用 |
| `seeds_next.txt` | 本轮活的 IP，可并进下一轮种子 |
| `candidates.txt` | 过滤后、验证前的新 IP |
| `report.json` | 各阶段计数和每个种子各反查源的命中数 |

和原版最大的不同：**未验证的 IP 不会回灌成种子**。原版“越跑越多”的大部分是死 IP。种子质量决定产出，用 FOFA 这类按特征筛出的活反代做种子效果最好。

## 本地运行

```bash
pip install --require-hashes -r requirements.txt
# seeds.txt 放种子；可选 known.txt 放已知 IP 用于去重
CHECK_API=https://your-checker/check python Fission.py
```

| 环境变量 | 默认 | 说明 |
|---|---|---|
| `VERIFY_HOST` | `speed.cloudflare.com` | 验证用 SNI / Host，可换成自己的 Worker 域名 |
| `CHECK_API` | 空（跳过） | ProxyIP 检测接口，调用 `?proxyip=ip:443` |
| `KNOWN_URLS` | 空 | 已知来源 URL，逗号分隔，用于去重 |
| `MAX_SEEDS` | `200` | 每轮最多用多少个种子 |
| `OTX_API_KEY` | 空 | OTX 免费 key；不填会很快被 429 限流，自动退避但会变慢、少查 |

注意：在有 HTTP 代理的环境里，ip138 / ipchaxun 可能拒绝代理连接，需要直连。

## GitHub Actions

`Fission` 工作流只能手动触发，结果以 artifact 形式保存 3 天，不提交回仓库。

- Secret `FISSION_SEEDS`：种子（一行一个 IP 或 FOFA CSV）。放 secret 而不是仓库文件，避免公开活 IP。
- Secret `OTX_API_KEY`（可选，强烈建议）：在 otx.alienvault.com 免费注册后拿到。
- Variables（可选）：`VERIFY_HOST`、`CHECK_API`、`KNOWN_URLS`。

## 边界

只验证裂变出的小候选集，不做全网扫描。第三方反代能看到 SNI 和流量时序，扫到的 IP 先隔离验证，不要直接填进生产配置。
