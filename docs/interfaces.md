# Interfaces

## REST API


??? abstract "OpenAPI specification"

    ```yaml
    --8<-- "api/openapi.yaml"
    ```

If http listener is enabled, blocky provides REST API. You can download the [OpenAPI YAML](api/openapi.yaml) interface specification. 

You can also browse the interactive API documentation (RapiDoc) documentation [online](rapidoc.html).

### Common endpoints

| Method | Path                  | Purpose                                              |
| ------ | --------------------- | ---------------------------------------------------- |
| GET    | `/api/blocking/enable`  | Enable blocking globally.                          |
| GET    | `/api/blocking/disable` | Disable blocking globally (optional `duration`, `groups` query params). |
| GET    | `/api/blocking/status`  | Return current blocking status as JSON.            |
| POST   | `/api/lists/refresh`    | Refresh all allow/denylists.                       |
| POST   | `/api/cache/flush`      | Clear the entire DNS response cache.               |
| POST   | `/api/query`            | Run a DNS query through Blocky and return the result as JSON. |
| GET    | `/api/stats`            | In-memory DNS statistics over a rolling 24h window as JSON. Requires [statistics](configuration.md#statistics) to be enabled; returns `503` otherwise. |

!!! example "Flush the DNS cache"

    ```sh
    curl -X POST http://<blocky-host>:<http-port>/api/cache/flush
    ```

    Returns HTTP `200` on success. Useful after editing `customDNS`
    or `hostsFile` entries that may already be cached.

!!! note "Statistics semantics"

    For `/api/stats`, the `summary` fields are server-computed categories (e.g. `blocked` =
    `BLOCKED` + `FILTERED` + `NOTFQDN`, `forwarded` = `RESOLVED` + `CONDITIONAL`), so callers
    never interpret a raw response type. The `lists` and `cache` objects are point-in-time gauges
    (current values, not affected by the 24h window), while `start`/`end` bound the windowed fields
    only. All timestamps (`start`, `end`, `perHour[].hour`) are always returned in UTC (RFC 3339,
    `Z` suffix), regardless of the server's local time zone. Statistics are independent of Prometheus
    and work with plain JSON.

## CLI

Blocky provides a CLI interface to control. This interface uses internally the REST API.

To run the CLI, please ensure, that blocky DNS server is running, then execute `blocky help` for help or

- `./blocky blocking enable` to enable blocking
- `./blocky blocking disable` to disable blocking
- `./blocky blocking disable --duration [duration]` to disable blocking for a certain amount of time (30s, 5m, 10m30s,
  ...)
- `./blocky blocking disable --groups ads,othergroup` to disable blocking only for special groups
- `./blocky blocking status` to print current status of blocking
- `./blocky query <domain>` execute DNS query (A) (simple replacement for dig, useful for debug purposes)
- `./blocky query <domain> --type <queryType>` execute DNS query with passed query type (A, AAAA, MX, ...)
- `./blocky lists refresh` reloads all allow/denylists
- `./blocky stats` shows DNS statistics (requires `statistics.enable: true`)
- `./blocky validate [--config /path/to/config.yaml]` validates configuration file

!!! tip 

    To run this inside docker run `docker exec blocky ./blocky blocking status`
