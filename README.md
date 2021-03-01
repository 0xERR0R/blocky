[![GitHub Workflow Status](https://img.shields.io/github/workflow/status/0xERR0R/blocky/CI%20Build?label=CI%20Build "CI Build")](#)
[![GitHub Workflow Status](https://img.shields.io/github/workflow/status/0xERR0R/blocky/Release?label=Release "Release")](#)
[![GitHub latest version](https://img.shields.io/github/v/release/0xERR0R/blocky "Latest version")](https://github.com/0xERR0R/blocky/releases)
[![GitHub Release Date](https://img.shields.io/github/release-date/0xERR0R/blocky "Latest release date")](https://github.com/0xERR0R/blocky/releases)
[![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/0xERR0R/blocky "Go version")](#)
[![Docker pulls](https://img.shields.io/docker/pulls/spx01/blocky "Latest version")](https://hub.docker.com/r/spx01/blocky)
[![Docker Image Size (latest)](https://img.shields.io/docker/image-size/spx01/blocky/latest)](https://hub.docker.com/r/spx01/blocky)
[![Codecov](https://img.shields.io/codecov/c/gh/0xERR0R/blocky "Code coverage")](https://codecov.io/gh/0xERR0R/blocky)
[![Codacy grade](https://img.shields.io/codacy/grade/8fcd8f8420b8419c808c47af58ed9282 "Codacy grade")](#)
[![Go Report Card](https://goreportcard.com/badge/github.com/0xERR0R/blocky)](https://goreportcard.com/report/github.com/0xERR0R/blocky)
[![Dependabot Status](https://api.dependabot.com/badges/status?host=github&repo=0xERR0R/blocky)](https://dependabot.com)

<p align="center">
  <img height="200" src="https://github.com/0xERR0R/blocky/blob/master/docs/blocky.svg">
</p>

# Blocky

Blocky is a DNS proxy and ad-blocker for the local network written in Go with following features:

## Features

- **Blocking** - Blocking of DNS queries with external lists (Ad-block, malware) and whitelisting

  * Definition of black and white lists per client group (Kids, Smart home devices etc)
  * periodical reload of external black and white lists
  * blocking of request domain, response CNAME (deep CNAME inspection) and response IP addresses (against IP lists)

- **Advanced DNS configuration** - not just an ad-blocker

  * Custom DNS resolution for certain domain names
  * Conditional forwarding to external DNS server

- **Performance** - Improves speed and performance in your network

  * Customizable caching of DNS answers for queries -> improves DNS resolution speed and reduces amount of external DNS
    queries
  * Prefetching and caching of often used queries
  * Using multiple external resolver simultaneously
  * low memory footprint

- **Various Protocols** - Supports modern DNS protocols

  * DNS over UDP and TCP
  * DNS over HTTPS (aka DoH)
  * DNS over TLS (aka DoT)

- **Security and Privacy** - Secure communication

  * Supports modern DNS extensions: DNSSEC, eDNS, ...
  * Free configurable blocking lists - no hidden filtering etc.
  * Provides DoH Endpoint
  * Uses random upstream resolvers from the configuration - increases you privacy though the distribution of your DNS
    traffic over multiple provider
  * blocky does **NOT** collect any user data, telemetry, statistics etc.

- **Integration** - various integration

  * Prometheus metrics
  * Prepared Grafana dashboard
  * Logging of DNS queries per day / per client in CSV format - easy to analyze
  * Statistics report via CLI
  * Various REST API endpoints
  * CLI tool

- **Simple configuration** - single configuration file in YAML format

  * Simple to maintain
  * Simple to backup

- **Simple installation/configuration** - blocky was designed

  * Docker image with Multi-arch support
  * Single binary
  * Supports x86-64 and ARM architectures -> runs fine on Raspberry PI
  * Community supported Helm chart for k8s deployment

## Quick start

You can jump to [Installation](https://0xerr0r.github.io/blocky/installation/) chapter in the documentation.

## Full documentation

You can find full documentation and configuration examples
at: [https://0xERR0R.github.io/blocky/](https://0xERR0R.github.io/blocky/)

## CLI / REST API

If http listener is enabled, blocky provides REST API to control blocking status. Swagger documentation
under `http://host:port/swagger`

To run CLI, please ensure, that blocky DNS server is running, than execute `blocky help` for help or

- `./blocky blocking enable` to enable blocking
- `./blocky blocking disable` to disable blocking
- `./blocky blocking disable --duration [duration]` to disable blocking for a certain amount of time (30s, 5m, 10m30s,
  ...)
- `./blocky blocking status` to print current status of blocking
- `./blocky query <domain>` execute DNS query (A) (simple replacement for dig, useful for debug purposes)
- `./blocky query <domain> --type <queryType>` execute DNS query with passed query type (A, AAAA, MX, ...)

To run this inside docker run `docker exec blocky ./blocky blocking status`

## Additional information

### HTTPS configuration (for DoH)
See [Wiki - Configuration of HTTPS](https://github.com/0xERR0R/blocky/wiki/Configuration-of-HTTPS-for-DoH-and-Rest-API) for detailed information, how to configure HTTPS.

DoH url: https://host:port/dns-query

### Prometheus / Grafana

Blocky can export metrics for prometheus. Example grafana dashboard definition [as JSON](docs/blocky-grafana.json)
or [at grafana.com](https://grafana.com/grafana/dashboards/13768)
![grafana-dashboard](docs/grafana-dashboard.png).

See [Wiki - Prometheus / Grafana](https://github.com/0xERR0R/blocky/wiki/Prometheus---Grafana-integration) for more
information.


### Print current configuration
To print runtime configuration / statistics, you can send `SIGUSR1` signal to running process

### Statistics
blocky collects statistics and aggregates them hourly. If signal `SIGUSR2` is received, this will print statistics for last 24 hours:
* Top 20 queried domains
* Top 20 blocked domains
* Query count per client
...

Hint: To send a signal to a process you can use `kill -s USR1 <PID>` or `docker kill -s SIGUSR1 blocky` for docker setup

### Debug / Profiling
If http listener is enabled, pprof endpoint (`/debug/pprof`) is enabled automatically.
