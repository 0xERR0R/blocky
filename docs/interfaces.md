# Interfaces

## REST API

If http listener is enabled, blocky provides REST API. You can browse the API documentation (Swagger) documentation
under [https://0xERR0R.github.io/blocky/swagger.html](https://0xERR0R.github.io/blocky/swagger.html).

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
- `./blocky lists refresh` reloads all white and blacklists

!!! tip 

    To run this inside docker run `docker exec blocky ./blocky blocking status`

--8<-- "docs/includes/abbreviations.md"
