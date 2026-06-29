# if_flow

`if_flow` - это агент host-level учета сетевого трафика на C с упором на низкое потребление ресурсов и отсутствие хранения raw-пакетов.

Проект собирает видимый `TCP/UDP` трафик на хосте, агрегирует его в памяти по `5-tuple` и минутным bucket'ам, обогащает flow дополнительными атрибутами и пишет результат в `JSONL`. При необходимости данные затем выгружаются в `ClickHouse`.

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

## Ограничения текущей версии

- пока учитывается только `TCP/UDP`
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

- `/opt/of_flow/deploy/systemd/if_flow.env`
- `/opt/of_flow/deploy/systemd/if_flow-clickhouse.env`

Установка:

```bash
sudo make install-systemd
sudo systemctl enable --now if_flow.service
sudo systemctl enable --now if_flow-archive.timer
```

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
