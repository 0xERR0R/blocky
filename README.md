[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/0xERR0R/blocky/makefile.yml "Make")](https://github.com/0xERR0R/blocky/actions/workflows/makefile.yml)
[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/0xERR0R/blocky/release.yml "Release")](https://github.com/0xERR0R/blocky/actions/workflows/release.yml)
[![GitHub latest version](https://img.shields.io/github/v/release/0xERR0R/blocky "Latest version")](https://github.com/0xERR0R/blocky/releases)
[![GitHub Release Date](https://img.shields.io/github/release-date/0xERR0R/blocky "Latest release date")](https://github.com/0xERR0R/blocky/releases)
[![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/0xERR0R/blocky "Go version")](#)
[![Docker pulls](https://img.shields.io/docker/pulls/spx01/blocky "Latest version")](https://hub.docker.com/r/spx01/blocky)
[![Docker Image Size (latest)](https://img.shields.io/docker/image-size/spx01/blocky/latest)](https://hub.docker.com/r/spx01/blocky)
[![Codecov](https://img.shields.io/codecov/c/gh/0xERR0R/blocky "Code coverage")](https://codecov.io/gh/0xERR0R/blocky)
[![Codacy grade](https://img.shields.io/codacy/grade/8fcd8f8420b8419c808c47af58ed9282 "Codacy grade")](#)
[![Go Report Card](https://goreportcard.com/badge/github.com/0xERR0R/blocky)](https://goreportcard.com/report/github.com/0xERR0R/blocky)
[![Donation](https://img.shields.io/badge/buy%20me%20a%20coffee-donate-blueviolet.svg)](https://ko-fi.com/0xerr0r)
[![Liberapay receiving](https://img.shields.io/liberapay/receives/spx01.svg?logo=liberapay "Support via Liberapay")](https://liberapay.com/spx01)

<p align="center">
  <img height="200" src="https://github.com/0xERR0R/blocky/blob/main/docs/blocky.svg">
</p>

# Blocky

Blocky is a DNS proxy and ad-blocker for the local network written in Go with following features:

## Features

- **Blocking** - Blocking of DNS queries with external lists (Ad-block, malware) and allowlisting

  - Definition of allow/denylists per client group (Kids, Smart home devices, etc.)
  - Periodical reload of external allow/denylists
  - Regex support
  - Blocking of request domain, response CNAME (deep CNAME inspection) and response IP addresses (against IP lists)

- **Advanced DNS configuration** - not just an ad-blocker

  - Custom DNS resolution for certain domain names
  - Conditional forwarding to external DNS server
  - Upstream resolvers can be defined per client group

- **Performance** - Improves speed and performance in your network

  - Customizable caching of DNS answers for queries -> improves DNS resolution speed and reduces amount of external DNS
    queries
  - Prefetching and caching of often used queries
  - Using multiple external resolver simultaneously
  - Low memory footprint

- **Various Protocols** - Supports modern DNS protocols

  - DNS over UDP and TCP
  - DNS over HTTPS (aka DoH)
  - DNS over TLS (aka DoT)
  - DNS over QUIC (aka DoQ, RFC 9250)
  - DNS over HTTPS/3 (aka DoH3, RFC 9114)

- **Security and Privacy** - Secure communication

  - Supports modern DNS extensions: DNSSEC, eDNS, ...
  - DNSSEC validation of upstream resolvers
  - Free configurable blocking lists - no hidden filtering etc.
  - Provides DoH Endpoint
  - Uses random upstream resolvers from the configuration - increases your privacy through the distribution of your DNS
    traffic over multiple provider
  - Blocky does **NOT** collect any user data, telemetry, statistics etc.

- **Integration** - various integration

  - [Prometheus](https://prometheus.io/) metrics
  - Prepared [Grafana](https://grafana.com/) dashboards (Prometheus and database)
  - Logging of DNS queries per day / per client in CSV format or MySQL/MariaDB/PostgreSQL/Timescale database - easy to
    analyze
  - Various REST API endpoints
  - CLI tool

- **Simple configuration** - single or multiple configuration files in YAML format

  - Simple to maintain
  - Simple to backup

- **Simple installation/configuration** - blocky was designed for simple installation

  - Stateless (no database, no temporary files)
  - Docker image with Multi-arch support
  - Single binary
  - Supports x86-64, ARM, and MIPS architectures -> runs fine on Raspberry PI and OpenWrt routers
  - Community supported Helm chart for k8s deployment

## ❤️ Support Blocky

Blocky is **free, open source, and built entirely in my spare time** — with no telemetry, no data
collection, and no hidden filtering. It keeps the DNS for thousands of home networks, homelabs, and
businesses clean and private, and it always will.

Maintaining a project this size — fixing bugs, reviewing pull requests, shipping new features, and
keeping up with security — takes a lot of time. **Thousands of people run Blocky; only a handful
support it.** If Blocky is useful to you, please consider chipping in. Your support directly funds
ongoing development and helps keep Blocky independent and ad-free, forever.

Even a small recurring contribution makes a real difference and is hugely appreciated. 🙏

[![Sponsor on GitHub](https://img.shields.io/badge/Sponsor-GitHub-EA4AAA?logo=githubsponsors&logoColor=white)](https://github.com/sponsors/0xERR0R)
[![Support on thanks.dev](https://img.shields.io/badge/thanks.dev-support-00A98F)](https://thanks.dev/u/gh/0xERR0R)
[![Donate on Liberapay](https://img.shields.io/badge/Liberapay-donate-F6C915?logo=liberapay&logoColor=black)](https://liberapay.com/spx01)
[![Buy me a coffee on Ko-fi](https://img.shields.io/badge/Ko--fi-donate-FF5E5B?logo=kofi&logoColor=white)](https://ko-fi.com/0xerr0r)
[![Donate via PayPal](https://img.shields.io/badge/PayPal-donate-00457C?logo=paypal&logoColor=white)](https://paypal.me/spx01)

### 🥇 Gold sponsors

<!-- gold --><!-- gold -->

### Sponsors

<!-- sponsors --><!-- sponsors -->

Thank you to everyone who supports Blocky! ❤️

## Quick start

You can jump to [Installation](https://0xerr0r.github.io/blocky/latest/installation/) chapter in the documentation.

## Full documentation

You can find full documentation and configuration examples
at: [https://0xERR0R.github.io/blocky/](https://0xERR0R.github.io/blocky/)

## Contribution

Issues, feature suggestions and pull requests are welcome!

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/G2G25XZQG)
