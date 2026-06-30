# Wazuh Integration

This directory contains a lightweight bridge from `ClickHouse` to `Wazuh` using a local JSON file.

Important:

- Wazuh integration is optional
- it is not installed by default in host deployment
- use the dedicated installer targets only when Wazuh alerting is actually needed

## Architecture

- `if_flow` collects and writes traffic records
- `clickhouse_uploader` ships all records into `ClickHouse`
- `if_flow_wazuh_bridge.py` reads only new `record_type='final'` rows
- the bridge emits selected alerts into a local JSONL file
- `Wazuh agent` reads that file through `localfile`

This keeps:

- full traffic history in `ClickHouse`
- only alert-worthy events in `Wazuh`

## Included files

- `if_flow_wazuh_bridge.py` - polling bridge
- `if_flow-wazuh.env.example` - environment template
- `run_wazuh_bridge_once.sh` - one-shot test run
- `run_wazuh_bridge_loop.sh` - loop mode
- `wazuh-localfile.xml.example` - `ossec.conf` snippet for Wazuh

## Quick start

```bash
cd wazuh_integration
cp if_flow-wazuh.env.example if_flow-wazuh.env
bash ./run_wazuh_bridge_once.sh
```

Loop mode:

```bash
bash ./run_wazuh_bridge_loop.sh
```

## Default rule groups

The first version emits alerts for:

- database traffic classes
- sensitive infrastructure classes such as `ldap`, `kerberos`, `vault`, `k8s_api`
- routing and tunnel classes such as `wireguard`, `bgp`, `bfdd`, `zebra`, `ospfd`
- `tcp_seen_without_syn`
- large transfers above `IF_FLOW_WAZUH_BYTES_THRESHOLD`

## Wazuh localfile

Add the snippet from [wazuh-localfile.xml.example](wazuh-localfile.xml.example) into the agent `ossec.conf`:

```xml
<localfile>
  <location>/opt/if_flow/wazuh/if_flow_alerts.jsonl</location>
  <log_format>json</log_format>
</localfile>
```

## Notes

- the bridge reads only `record_type='final'`
- state is tracked in `IF_FLOW_WAZUH_STATE_PATH`
- the alert file is append-only JSONL
- this is intended as a simple and reliable MVP for Wazuh alerting
