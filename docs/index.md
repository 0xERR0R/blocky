# Blocky

<figure>
  <img src="https://raw.githubusercontent.com/0xERR0R/blocky/main/docs/blocky.svg" width="200" />
</figure>

Blocky is a DNS proxy and ad-blocker for the local network written in Go with following features:

## Features

- **Blocking** - :no_entry: Blocking of DNS queries with external lists (Ad-block, malware) and allowlisting

    * Definition of allow/denylists per client group (Kids, Smart home devices, etc.)
    * Periodical reload of external allow/denylists
    * Regex support
    * Blocking of request domain, response CNAME (deep CNAME inspection) and response IP addresses (against IP lists)

- **Advanced DNS configuration** - :nerd: not just an ad-blocker

    * Custom DNS resolution for certain domain names
    * Conditional forwarding to external DNS server
    * Upstream resolvers can be defined per client group

- **Performance** - :rocket: Improves speed and performance in your network

    * Customizable caching of DNS answers for queries -> improves DNS resolution speed and reduces amount of external DNS
      queries
    * Prefetching and caching of often used queries
    * Using multiple external resolver simultaneously
    * Low memory footprint

- **Various Protocols** - :computer: Supports modern DNS protocols

    * DNS over UDP and TCP
    * DNS over HTTPS (aka DoH)
    * DNS over TLS (aka DoT)

- **Security and Privacy** - :dark_sunglasses: Secure communication

    * Supports modern DNS extensions: DNSSEC, eDNS, ...
    * Free configurable blocking lists - no hidden filtering etc.
    * Provides DoH Endpoint
    * Uses random upstream resolvers from the configuration - increases your privacy through the distribution of your DNS
      traffic over multiple provider
    * Open source development
    * Blocky does **NOT** collect any user data, telemetry, statistics etc.

- **Integration** - :notebook_with_decorative_cover: various integration

    * [Prometheus](https://prometheus.io/) metrics
    * Prepared [Grafana](https://grafana.com/) dashboards (Prometheus and database)
    * Logging of DNS queries per day / per client in CSV format or MySQL/MariaDB/PostgreSQL database - easy to analyze
    * Various REST API endpoints
    * CLI tool

- **Simple configuration** - :baby: single configuration file in YAML format

    * Simple to maintain
    * Simple to backup

- **Simple installation/configuration** - :cloud: blocky was designed for simple installation

    * Stateless (no database, no temporary files)
    * Docker image with Multi-arch support
    * Single binary
    * Supports x86-64 and ARM architectures -> runs fine on Raspberry PI
    * Community supported Helm chart for k8s deployment


## Contribution

Issues, feature suggestions and pull requests are welcome! Blocky lives on :material-github:[GitHub](https://github.com/0xERR0R/blocky).

--8<-- "docs/includes/abbreviations.md"
