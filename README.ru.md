# if_flow

`if_flow` - это агент host-level учета сетевого трафика на C с упором на низкое потребление ресурсов и отсутствие хранения raw-пакетов.

Проект собирает видимый `TCP/UDP` трафик на хосте, а также ряд IP-протоколов без портов, таких как `ICMP/ICMPv6`, `GRE`, `ESP`, `AH`, `OSPF`, `VRRP`, `IGMP`, `PIM` и `SCTP`, агрегирует его в памяти по `5-tuple` и минутным bucket'ам, обогащает flow дополнительными атрибутами и пишет результат в `JSONL`. При необходимости данные затем выгружаются в `ClickHouse`.

## Что умеет проект

- захват трафика через `libpcap`
- агрегация по `src_ip`, `src_port`, `dst_ip`, `dst_port`, `proto`
- minute-based accounting без хранения raw-пакетов
- потоковый `update`-вывод активных flow
- финальный `final`-вывод при закрытии минутного bucket
- определение направления `in`, `out`, `internal`, `transit`
- best-effort привязка flow к процессу через `eBPF` и fallback через `/proc`
- enrichment через `TLS SNI` и `HTTP Host`
- классификация flow по типу трафика на основе портов и именованных подсказок
- запись в локальный `JSONL`
- выгрузка в `ClickHouse` отдельным uploader-ом
- готовые systemd unit-файлы
- стартовый стек для визуализации через Grafana


Текущий прототип покрывает:

- `host` - имя хоста, где работает агент
- `src_ip`, `src_port`, `dst_ip`, `dst_port` - источник и получатель
- `proto` - IP protocol number
- `class` - прикладной класс трафика
- `packets`, `bytes`, `bytes_human` - счетчики трафика
- `connections` - число соединений в рамках текущей логики
- `minute_ts`, `minute_iso` - минутный интервал
- `record_type=update/final` - моментальная и финальная фиксация состояния

## Как работает агент

1. `libpcap` получает пакет с выбранного интерфейса.
2. Из пакета извлекается L3/L4 информация и строится canonical `5-tuple`.
3. При наличии payload агент пытается достать `TLS SNI` и `HTTP Host`.
4. Для process attribution используется:
   - сначала `eBPF` cache
   - затем `/proc` fallback resolver
5. Flow попадает в in-memory таблицу агрегатов.
6. Активные flow периодически пишутся как `update`.
7. Flow прошлых минут пишутся как `final` и удаляются из памяти.

## Структура проекта

- `src/main.c` - основной цикл, packet path, classification, emit
- `src/flow_table.c` - in-memory таблица flow и minute aggregation
- `src/ebpf_tracker.c` - eBPF attribution cache
- `src/resolver.c` - fallback attribution через `/proc`
- `src/parser.c` - lightweight парсинг `TLS SNI` и `HTTP Host`
- `src/writer_jsonl.c` - JSONL writer, day rotation, size rotation
- `src/config.c` - CLI и значения по умолчанию
- `bpf/if_flow.bpf.c` - eBPF programs
- `clickhouse_uploader/` - uploader, schema, Docker stack, Grafana
- `deploy/systemd/` - готовые unit-файлы и env templates
- `scripts/` - helper scripts для запуска и установки
- `tests/` - self-tests и smoke tests

## Сборка

Нужны пакеты:

- `clang`
- `bpftool`
- `libbpf` headers/dev package
- `libpcap` headers/dev package
- `libelf` / `zlib` dev package
- `pkg-config`

Примеры:

```bash
# Debian / Ubuntu
sudo apt-get install -y build-essential clang llvm bpftool libbpf-dev libpcap-dev libelf-dev zlib1g-dev pkg-config

# RHEL / Rocky / Alma / Fedora
sudo dnf install -y clang llvm bpftool libbpf-devel libpcap-devel elfutils-libelf-devel zlib-devel pkgconf-pkg-config
```

Сборка:

```bash
make
```

Если появляется ошибка вида `bpf/bpf_core_read.h file not found`, обычно не хватает пакета `libbpf-dev` или `libbpf-devel`.

## Проверка

Синтетическая проверка:

```bash
./if_flow --selftest
```

Полный test target:

```bash
make test
```

## Запуск

Минимальный live-запуск:

```bash
./if_flow -i any --json-path ./if_flow.jsonl
```

Рекомендуемый вариант:

```bash
./if_flow -i any --datapath --stream-flush-sec 1 --json-max-file-size-mb 256 --json-path ./if_flow.jsonl
```

Полезные аргументы:

- `--no-identity-fields` - не выводить `pid`, `attr_source`, `process`, `cmdline`
- `--no-ebpf` - отключить eBPF и оставить только `/proc` fallback
- `--no-datapath` - отключить datapath hooks и оставить connect-style attribution
- `--stream-flush-sec N` - частота `update`-вывода
- `--json-max-file-size-mb N` - ротация JSONL по размеру

## Формат вывода

Основные поля:

- `record_type` - `update` или `final`
- `host` - имя хоста
- `iface` - интерфейс захвата
- `minute_ts` - unix timestamp minute bucket
- `minute_iso` - локальное минутное время в ISO format
- `proto` - IP protocol number
- `class` - логический класс трафика
- `direction` - `in`, `out`, `internal`, `transit`
- `src_ip`, `src_port`, `dst_ip`, `dst_port`
- `packets`, `bytes`, `bytes_human`
- `connections`
- `connections_effective`
- `connection_inferred`
- `tcp_seen_without_syn`
- `first_seen_iso`, `last_seen_iso`

Опциональные identity fields:

- `pid`
- `attr_source`
- `process`
- `cmdline`
- `workload`

Дополнительный enrichment:

- `sni`
- `host_name`

## Классы и порты

Полная карта `class -> ports` вынесена в отдельный документ:

- [docs/PORT_CLASSES.ru.md](docs/PORT_CLASSES.ru.md)

Там же зафиксированы текущие эвристики, приоритеты, инфраструктурные порты и `ICMP/ICMPv6`-классы по `type/code`.

## Ограничения текущей версии

- для `TCP`, `UDP` и `SCTP` доступны `src_port` и `dst_port`
- для `ICMP/ICMPv6`, `GRE`, `ESP`, `AH`, `OSPF`, `VRRP`, `IGMP`, `PIM` порты выставляются в `0`, а класс определяется по номеру протокола или `type/code`
- `connections` в первой версии intentionally simplified
- при midstream TCP возможно отсутствие стартового `SYN`, тогда используются soft flags
- направление считается относительно IP-адресов текущего хоста
- payload не хранится, используется только для моментального enrichment

## systemd

Готовые файлы лежат в [deploy/systemd](deploy/systemd):

- [if_flow.service](deploy/systemd/if_flow.service)
- [if_flow-archive.service](deploy/systemd/if_flow-archive.service)
- [if_flow-archive.timer](deploy/systemd/if_flow-archive.timer)
- [if_flow-clickhouse-uploader.service](deploy/systemd/if_flow-clickhouse-uploader.service)
- [if_flow.env.example](deploy/systemd/if_flow.env.example)
- [if_flow-clickhouse.env.example](deploy/systemd/if_flow-clickhouse.env.example)

По умолчанию unit-файлы ожидают env-файлы здесь:

- `/opt/if_flow/deploy/systemd/if_flow.env`
- `/opt/if_flow/deploy/systemd/if_flow-clickhouse.env`

Установка:

```bash
sudo make install-systemd
sudo editor /opt/if_flow/deploy/systemd/if_flow.env
sudo editor /opt/if_flow/deploy/systemd/if_flow-clickhouse.env
sudo systemctl enable --now if_flow.service
sudo systemctl enable --now if_flow-archive.timer
sudo systemctl enable --now if_flow-clickhouse-uploader.service
```

Режимы установки:

- `make install-host` - host mode, без Wazuh
- `make bootstrap-host` - новый host, без Wazuh
- `make install-host-wazuh` - host mode с Wazuh bridge
- `make bootstrap-host-wazuh` - новый host с Wazuh bridge
- `make install-server` - server mode, только ClickHouse/Grafana stack assets
- `make install-server-wazuh` - server mode с дополнительной установкой Wazuh bridge

Совместимые алиасы сохранены:

- `make install-systemd` -> `make install-host`
- `make bootstrap-systemd` -> `make bootstrap-host`
- `make install-systemd-wazuh` -> `make install-host-wazuh`
- `make bootstrap-systemd-wazuh` -> `make bootstrap-host-wazuh`

Матрица команд:

| Сценарий | Команда | Что устанавливается |
| --- | --- | --- |
| Подготовленный host | `make install-host` | `if_flow`, uploader, host `systemd` units |
| Новый host | `sudo make bootstrap-host` | зависимости, сборка, `if_flow`, uploader, host `systemd` units |
| Подготовленный host + Wazuh | `make install-host-wazuh` | host stack + optional Wazuh bridge |
| Новый host + Wazuh | `sudo make bootstrap-host-wazuh` | зависимости, сборка, host stack + optional Wazuh bridge |
| Server | `make install-server` | `ClickHouse/Grafana` assets, dashboards, queries, compose files, локальные storage-каталоги |
| Server + Wazuh | `make install-server-wazuh` | server assets, локальные storage-каталоги + optional Wazuh bridge |

Bootstrap-режим для нового хоста:

```bash
sudo make bootstrap-host
```

Этот режим:

- ставит build/runtime зависимости через `apt-get` или `dnf`
- собирает `if_flow` и `bpf/if_flow.bpf.o`
- раскладывает файлы в `/opt/if_flow`
- копирует unit-файлы в `/etc/systemd/system`
- выполняет `systemctl daemon-reload`

Wazuh bridge по умолчанию не устанавливается. Он всегда опционален и включается только отдельными командами:

```bash
make install-host-wazuh
sudo make bootstrap-host-wazuh
make install-server-wazuh
```

Практический порядок для хоста:

1. На уже подготовленном хосте: `make` и `sudo make install-host`
2. На новом чистом хосте: `sudo make bootstrap-host`
3. Заполнить env-файлы в `/opt/if_flow/deploy/systemd/`
4. Запустить `if_flow.service`
5. При необходимости включить `if_flow-clickhouse-uploader.service`

Практический порядок для сервера:

1. Выполнить `sudo make install-server`
2. Перейти в `/opt/if_flow/clickhouse_uploader`
3. Скопировать `.env.example` в `.env`
4. Проверить, что созданы локальные каталоги:
   - `/opt/if_flow/clickhouse_uploader/storage/clickhouse/data`
   - `/opt/if_flow/clickhouse_uploader/storage/clickhouse/logs`
   - `/opt/if_flow/clickhouse_uploader/storage/grafana/data`
5. Запустить `docker compose up -d`

По умолчанию ClickHouse и Grafana в bundled `docker-compose.yml` используют bind mount-хранение на хосте, а не Docker named volumes. Данные БД лежат локально в каталоге проекта рядом с compose-файлом.

Практический порядок для сервера:

1. Разложить server assets: `make install-server`
2. Перейти в `/opt/if_flow/clickhouse_uploader`
3. Подготовить `.env`
4. Запустить `docker compose up -d --build`

Если серверу нужен только alerting bridge для Wazuh:

1. Выполнить `make install-server-wazuh`
2. Заполнить `/opt/if_flow/deploy/systemd/if_flow-wazuh.env`
3. Включить `if_flow-wazuh-bridge.service`

`if_flow-clickhouse-uploader.service` теперь запускает тот же wrapper-скрипт, что и ручной loop-run, и использует явный env-файл `/opt/if_flow/deploy/systemd/if_flow-clickhouse.env`. Это убирает расхождение между ручным запуском и systemd-запуском.

Для production-профиля на плотном потоке обычно достаточно:

- `IF_FLOW_ARGS=--datapath --stream-flush-sec 1 --json-max-file-size-mb 256`
- `IF_FLOW_JSON_PATH=/opt/if_flow/if_flow.jsonl`

## Архивация

Скрипт [scripts/if_flow_archive.sh](scripts/if_flow_archive.sh):

- не трогает активный файл текущего дня
- сжимает старые `*.jsonl` в `*.jsonl.gz`
- удаляет архивы старше retention window

Пример:

```bash
bash ./scripts/if_flow_archive.sh --base-path /opt/if_flow/if_flow.jsonl --retention-days 7
```

## ClickHouse и Grafana

Вся логика выгрузки и визуализации вынесена в отдельную папку:

- [clickhouse_uploader/README.md](clickhouse_uploader/README.md)

Там есть:

- uploader в `ClickHouse`
- `schema.sql` с `TTL`
- Docker Compose stack
- provisioning для Grafana
- стартовые SQL и dashboard для Grafana

### Почему основной UI здесь именно Grafana

Для `if_flow` именно `Grafana` является основным и рекомендуемым интерфейсом.

Она лучше подходит, если:

- нужен основной production dashboard
- данные уже большие или ожидается быстрый рост объема
- важнее time-series графики по минутам
- нужны быстрые панели `top N` по `src_ip`, `dst_ip`, `class`, `process`
- нужен постоянный operational monitoring

Если нужен только один UI, для `if_flow` почти всегда правильнее начинать именно с `Grafana`.
