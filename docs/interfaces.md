# Interfaces

## REST API


??? abstract "OpenAPI specification"

    ```yaml
    --8<-- "docs/api/openapi.yaml"
    ```

If http listener is enabled, blocky provides REST API. You can download the [OpenAPI YAML](api/openapi.yaml) interface specification. 

You can also browse the interactive API documentation (RapiDoc) documentation [online](rapidoc.html).

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
- `./blocky validate [--config /path/to/config.yaml]` validates configuration file

!!! tip 

    To run this inside docker run `docker exec blocky ./blocky blocking status`

--8<-- "docs/includes/abbreviations.md"
