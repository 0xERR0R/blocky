# Integration in Grafana

## Prometheus

### Prometheus export

Blocky can optionally export metrics for [Prometheus](https://prometheus.io/).

Following metrics will be exported:

| name                                             |   Description                                            |
| ------------------------------------------------ | -------------------------------------------------------- |
| blocky_denylist_cache_entries                    | Gauge of entries in the denylist cache, partitioned by group |
| blocky_allowlist_cache_entries                   | Gauge of entries in the allowlist cache, partitioned by group |
| blocky_error_total                               | Counter of total queries that ended in error for any reason |
| blocky_query_total                               | Counter of total queries, partitioned by client and DNS request type (A, AAAA, PTR, etc) |
| blocky_blocky_request_duration_seconds           | Histogram of request duration, partitioned by response type (Blocked, cached, etc)  |
| blocky_response_total                            | Counter of responses, partitioned by response type (Blocked, cached, etc), DNS response code, and reason |
| blocky_blocking_enabled                          | Boolean 1 if blocking is enabled, 0 otherwise |
| blocky_cache_entries                             | Gauge of entries in cache |
| blocky_cache_hits_total                          | Counter of the number of cache hits |
| blocky_cache_miss_count                          | Counter of the number of Cache misses |
| blocky_last_list_group_refresh_timestamp_seconds | Timestamp of last list refresh |
| blocky_prefetches_total                          | Counter of prefetched DNS responses |
| blocky_prefetch_hits_total                       | Counter of requests that hit the prefetch cache |
| blocky_prefetch_domain_name_cache_entries        | Gauge of domain names being prefetched |
| blocky_failed_downloads_total                    | Counter of failed list downloads |

### Grafana dashboard

Example [Grafana](https://grafana.com/) dashboard
definition [as JSON](blocky-grafana.json)
or [at grafana.com](https://grafana.com/grafana/dashboards/13768)
![grafana-dashboard](grafana-dashboard.png).

This dashboard shows all relevant statistics and allows enabling and disabling the blocking status.

### Grafana configuration

Please install `grafana-piechart-panel` and
set [disable_sanitize_html](https://grafana.com/docs/grafana/latest/installation/configuration/#disable_sanitize_html)
in config or as env to use control buttons to enable/disable the blocking status.

### Grafana and Prometheus example project

This [repo](https://github.com/0xERR0R/blocky-grafana-prometheus-example) contains example docker-compose.yml with
blocky, prometheus (with configured scraper for blocky) and grafana with prometheus datasource.

## MySQL / MariaDB

If database query logging is activated (see [Query logging](configuration.md#query-logging)), you can use following
Grafana Dashboard [as JSON](blocky-query-grafana.json)
or [at grafana.com](https://grafana.com/grafana/dashboards/14980)

![grafana-dashboard](grafana-query-dashboard.png).

Please define the MySQL source in Grafana, which points to the database with blocky's log entries.

## Postgres

The JSON for a Grafana dashboard equivalent to the MySQL/MariaDB version is located [here](blocky-query-grafana-postgres.json)

--8<-- "docs/includes/abbreviations.md"
