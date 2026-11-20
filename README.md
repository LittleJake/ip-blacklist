# IP Blacklist

[![IP Blacklist](https://github.com/LittleJake/ip-blacklist/actions/workflows/blacklist.yml/badge.svg)](https://github.com/LittleJake/ip-blacklist/actions/workflows/blacklist.yml)
[![Hits](https://hits.seeyoufarm.com/api/count/incr/badge.svg?url=https%3A%2F%2Fgithub.com%2FLittleJake%2Fip-blacklist&count_bg=%2379C83D&title_bg=%23555555&icon=&icon_color=%23E7E7E7&title=hits&edge_flat=false)](https://hits.seeyoufarm.com)

自动汇总并更新多个公开威胁情报与黑名单源的恶意 IP / CIDR 列表，经 CIDR 合并优化与私网地址过滤，每 6 小时自动更新。

Automated multi-source threat intelligence IP blacklist aggregator. Normalized, filtered for bogons/private IPs, deduplicated, and CIDR-merged. Updated 4 times a day via GitHub Actions.

---

## 威胁情报源与列表文件 / Blacklist Feeds

> **提示 / Tip**: 推荐配合 Linux `ipset` 或防火墙规则定时拉取并导入。

| 文件名称 Filename | 来源 Source | 说明 Description |
| :--- | :--- | :--- |
| [all_blacklist.txt](https://cdn.jsdelivr.net/gh/LittleJake/ip-blacklist/all_blacklist.txt) | **ALL (Active)** | 当前所有活跃威胁源聚合去重与 CIDR 合并列表 (推荐) |
| [all_blacklist_append.txt.gz](https://github.com/LittleJake/ip-blacklist/raw/main/all_blacklist_append.txt.gz) | **ALL (Historical)** | 历史累计恶意 IP 库 (Gzip 压缩，谨慎全量阻断) |
| [blocklist_de.txt](https://cdn.jsdelivr.net/gh/LittleJake/ip-blacklist/blocklist_de.txt) | **Blocklist.de** | 过去 48 小时被 Fail2ban 节点上报的攻击 IP |
| [cinsscore_badguys.txt](https://cdn.jsdelivr.net/gh/LittleJake/ip-blacklist/cinsscore_badguys.txt) | **CINS Army** | Sentinel IPS 高确信度恶意威胁名单 |
| [feodotracker_c2.txt](https://cdn.jsdelivr.net/gh/LittleJake/ip-blacklist/feodotracker_c2.txt) | **abuse.ch Feodo Tracker** | 活跃 Botnet 僵尸网络 C2 控制端 IP |
| [emerging_threats_compromised.txt](https://cdn.jsdelivr.net/gh/LittleJake/ip-blacklist/emerging_threats_compromised.txt) | **Emerging Threats** | Proofpoint ET 失陷受控主机列表 |
| [greensnow.txt](https://cdn.jsdelivr.net/gh/LittleJake/ip-blacklist/greensnow.txt) | **GreenSnow** | 全球蜜罐收集的暴力破解与攻击源 IP |
| [ustc_blacklist_ip.txt](https://cdn.jsdelivr.net/gh/LittleJake/ip-blacklist/ustc_blacklist_ip.txt) | **USTC** | 中国科学技术大学黑名单 (IPv4 + IPv6) |
| [abuseipdb_blacklist_ip_score_100.txt](https://cdn.jsdelivr.net/gh/LittleJake/ip-blacklist/abuseipdb_blacklist_ip_score_100.txt) | **AbuseIPDB** | 威胁确信度 100% |
| [abuseipdb_blacklist_ip_score_75.txt](https://cdn.jsdelivr.net/gh/LittleJake/ip-blacklist/abuseipdb_blacklist_ip_score_75.txt) | **AbuseIPDB** | 威胁确信度 ≥ 75% |
| [neucert_blacklist_ip.txt](https://cdn.jsdelivr.net/gh/LittleJake/ip-blacklist/neucert_blacklist_ip.txt) | **NEUCERT** | 东北大学历史源 (服务已离线归档) |

---

## 特性与优化 / Features

1. **自动 CIDR 合并与去重**: 使用高效的 `cidr-merger` 对重叠网段及相邻 IP 进行自动聚合计算。
2. **私网与保留地址过滤**: 自动剔除 RFC 1918 私网网段、回环地址 (`127.0.0.0/8`, `::1`)、组播、本地链路等非公网地址，避免意外阻断内网通信。
3. **高可用容错机制**: 单个威胁源异常或不可达时，保留原有列表数据，避免因网络抖动造成黑名单被清空。
4. **轻量工作流**: 采用模块化 Python 脚本与 GitHub Actions 原生流程驱动，去除了多余依赖。

---

## 使用指南 / Quick Start

### 1. 本地更新 / Local Run

```bash
# 赋予执行权限并执行更新
python3 update.py

# 如需配置 AbuseIPDB，可设置环境变量：
export ABUSEIPDB_TOKEN="your_token_here"
python3 update.py
```

### 2. Linux ipset 导入示例 / ipset Integration

```bash
#!/bin/bash
# 创建临时集合
ipset create blacklist_tmp hash:net family inet hashsize 16384 maxelem 1000000 2>/dev/null || ipset flush blacklist_tmp

# 下载最新聚合黑名单
curl -sSL https://cdn.jsdelivr.net/gh/LittleJake/ip-blacklist/all_blacklist.txt | while read -r line; do
  [[ -z "$line" || "$line" =~ ^# ]] && continue
  ipset add blacklist_tmp "$line" 2>/dev/null
done

# 如果正式集合不存在则创建，之后原子切换
ipset create blacklist hash:net family inet hashsize 16384 maxelem 1000000 2>/dev/null
ipset swap blacklist_tmp blacklist
ipset destroy blacklist_tmp

# 添加 iptables 规则 (只需执行一次)
iptables -C INPUT -m set --match-set blacklist src -j DROP 2>/dev/null || iptables -I INPUT -m set --match-set blacklist src -j DROP
```

---

## 鸣谢 / Acknowledgements

- [cidr-merger](https://github.com/zhanhb/cidr-merger)
- [AbuseIPDB](https://www.abuseipdb.com/)
- [USTC Network](https://blackip.ustc.edu.cn/)
- [Blocklist.de](https://www.blocklist.de/)
- [CINS Army](https://cinsscore.com/)
- [abuse.ch Feodo Tracker](https://feodotracker.abuse.ch/)
- [Emerging Threats](https://rules.emergingthreats.net/)
- [GreenSnow](https://greensnow.co/)

## License

[Apache-2.0 License](LICENSE)
