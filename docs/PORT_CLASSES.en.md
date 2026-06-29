# Classes and Ports

Classification in `if_flow` is heuristic: the agent reads `src_port` and `dst_port` from each `TCP/UDP` packet and maps them through an internal rule table. Stronger signals can override plain port mapping:

- `UDP 443/8443/9443` may be classified as `quic`
- multicast destination traffic may be classified as `multicast`
- flows with `TLS SNI` or `HTTP Host` may be classified as `https`, `http`, or `named_app`

Below is the current built-in `class -> ports` map.

## ICMP and ICMPv6

For `ICMP` and `ICMPv6`, the agent does not use ports: `src_port=0`, `dst_port=0`, and the class is derived from `type/code`.

- `icmp_echo`
- `icmp_echo_reply`
- `icmp_unreachable`
- `icmp_time_exceeded`
- `icmp_redirect`
- `icmpv6_nd`
- `icmpv6_router_advert`
- `icmpv6_echo`

For other messages, a more general fallback is used:

- `icmp`
- `icmpv6`

## Core network services

- `mdns`: `5353`
- `llmnr`: `5355`
- `dns`: `53`
- `dot`: `853`
- `ntp`: `123`
- `dhcp`: `67`, `68`
- `tftp`: `69`
- `snmp`: `161`, `162`
- `syslog`: `514`, `6514`
- `rpcbind`: `111`

## Web and application traffic

- `http`: `80`, `8000`, `8008`, `8080`, `8888`
- `https`: `443`, `8443`, `9443`
- `quic`: `443`, `8443`, `9443` for `UDP`
- `ipp`: `631`
- `rtsp`: `554`

## Access and remote administration

- `ssh`: `22`
- `telnet`: `23`
- `rdp`: `3389`
- `vnc`: `5900`
- `msrpc`: `135`, `593`
- `netbios`: `137`, `138`, `139`
- `smb`: `445`

## Mail and directory services

- `smtp`: `25`, `465`, `587`
- `pop3`: `110`, `995`
- `imap`: `143`, `993`
- `ldap`: `389`, `636`
- `kerberos`: `88`
- `kerberos_kpasswd`: `464`
- `kerberos_admin`: `749`
- `radius`: `1812`, `1813`
- `tacacs`: `49`

## File and backup services

- `ftp`: `21`
- `ftp_data`: `20`
- `rsync`: `873`
- `nfs`: `2049`
- `mountd`: `20048`
- `iscsi`: `3260`

## Databases and queues

- `mysql`: `3306`
- `postgres`: `5432`
- `mssql`: `1433`, `1434`
- `oracle`: `1521`
- `cassandra`: `9042`
- `cockroachdb`: `26257`
- `clickhouse`: `8123`, `9000`, `9004`, `9005`, `9440`
- `redis`: `6379`
- `mongodb`: `27017`, `27018`, `27019`
- `memcached`: `11211`
- `amqp`: `5671`, `5672`
- `rabbitmq_mgmt`: `15671`, `15672`
- `mqtt`: `1883`, `8883`
- `kafka`: `9092`
- `zookeeper`: `2181`
- `etcd`: `2379`, `2380`, `2381`, `2382`

## Containers and orchestration

- `docker_api`: `2375`, `2376`
- `k8s_api`: `6443`
- `kubelet`: `10250`
- `consul`: `8500`, `8502`, `8600`
- `vault`: `8200`, `8201`
- `nomad`: `4646`, `4647`, `4648`

## Monitoring and observability

- `prometheus`: `9090`
- `alertmanager`: `9093`
- `node_exporter`: `9100`
- `grafana`: `3000`
- `loki`: `3100`
- `logstash`: `5044`
- `fluentd`: `24224`
- `otlp`: `4317`, `4318`
- `tracing`: `6831`, `6832`, `14250`, `14268`, `16686`
- `zipkin`: `9411`
- `influxdb`: `8086`
- `statsd`: `8125`
- `datadog_apm`: `8126`
- `nrpe`: `5666`
- `netdata`: `19999`
- `zabbix`: `10050`, `10051`

## Routing, VPN, and overlay

- `bgp`: `179`
- `zebra`: `2601`
- `ripd`: `2602`
- `ripngd`: `2603`
- `ospfd`: `2604`
- `bgpd`: `2605`
- `ospf6d`: `2606`
- `isisd`: `2607`
- `babeld`: `2608`
- `pimd`: `2609`
- `ldpd`: `2610`
- `nhrpd`: `2611`
- `eigrpd`: `2612`
- `fabricd`: `2614`
- `pathd`: `2615`
- `staticd`: `2616`
- `bfdd`: `2613`, `2617`, `3784`, `3785`, `4784`
- `ipsec`: `500`, `4500`
- `openvpn`: `1194`
- `l2tp`: `1701`
- `pptp`: `1723`
- `wireguard`: `10000`, `10251`, `32223`, `35053`, `51820`, `51821`, `65100`
- `vxlan`: `4789`
- `geneve`: `6081`
- `tinc`: `655`
- `salt`: `4505`, `4506`
