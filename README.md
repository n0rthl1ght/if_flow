# if_flow

Host-level network traffic accounting agent written in C. It captures TCP/UDP traffic plus selected IP protocols such as ICMP/ICMPv6, GRE, ESP, AH, OSPF, VRRP, IGMP, PIM, and SCTP, aggregates them in memory, enriches flows with optional process and application metadata, and exports minute-based records without storing raw packets.

Documentation:

- [README.ru.md](README.ru.md) - detailed documentation in Russian
- [README.en.md](README.en.md) - detailed documentation in English
- [clickhouse_uploader/README.md](clickhouse_uploader/README.md) - ClickHouse uploader, Docker stack and Grafana

Quick start:

```bash
make
./if_flow --selftest
./if_flow -i any --json-path ./if_flow.jsonl
```

For ClickHouse upload and dashboards, continue with [clickhouse_uploader/README.md](clickhouse_uploader/README.md).
