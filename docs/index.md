# Blocky

<figure>
  <img src="https://raw.githubusercontent.com/0xERR0R/blocky/master/docs/blocky.svg" width="200" />
</figure>

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

## Contribution

Issues, feature suggestions and pull requests are welcome! Blocky lives on :
material-github:[GitHub](https://github.com/0xERR0R/blocky).

--8<-- "docs/includes/abbreviations.md"
