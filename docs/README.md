[![GitHub Workflow Status](https://img.shields.io/github/workflow/status/0xERR0R/blocky/CI%20Build?label=CI%20Build "CI Build")](#)
[![GitHub Workflow Status](https://img.shields.io/github/workflow/status/0xERR0R/blocky/Release?label=Release "Release")](#)
[![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/0xERR0R/blocky "Go version")](#)
[![GitHub latest version](https://img.shields.io/github/v/release/0xERR0R/blocky "Latest version")](https://github.com/0xERR0R/blocky/releases)
[![Docker pulls](https://img.shields.io/docker/pulls/spx01/blocky "Latest version")](https://hub.docker.com/r/spx01/blocky)
[![GitHub Release Date](https://img.shields.io/github/release-date/0xERR0R/blocky "Latest release date")](https://github.com/0xERR0R/blocky/releases)
[![Codecov](https://img.shields.io/codecov/c/gh/0xERR0R/blocky "Code coverage")](https://codecov.io/gh/0xERR0R/blocky)
[![Codacy grade](https://img.shields.io/codacy/grade/8fcd8f8420b8419c808c47af58ed9282 "Codacy grade")](#)
[![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2F0xERR0R%2Fblocky.svg?type=shield)](https://app.fossa.io/projects/git%2Bgithub.com%2F0xERR0R%2Fblocky?ref=badge_shield)

<p align="center">
  <img height="200" src="https://github.com/0xERR0R/blocky/blob/master/docs/blocky.svg">
</p>

# Blocky
Blocky is a DNS proxy for the local network written in Go with following features:
- Blocking of DNS queries with external lists (Ad-block) with whitelisting
  - Definition of black and white lists per client group (Kids, Smart home devices etc) -> for example: you can block some domains for you Kids and allow your network camera only domains from a whitelist
  - periodical reload of external black and white lists
  - blocking of request domain, response CNAME (deep CNAME inspection) and response IP addresses (against IP lists)
- Caching of DNS answers for queries -> improves DNS resolution speed and reduces amount of external DNS queries
- Custom DNS resolution for certain domain names
- Serves DNS over UDP, TCP and HTTPS (DNS over HTTPS, aka DoH)
- Supports UDP, TCP and TCP over TLS DNS resolvers with DNSSEC support
- Supports DNS over HTTPS (DoH) resolvers
- Delegates DNS query to 2 external resolvers from a list of configured resolvers, uses the answer from the fastest one -> improves you privacy and resolution time
  - Blocky peeks 2 random resolvers with weighted random algorithm: resolvers with error will be used less frequently
- Logging of all DNS queries per day / per client in a text file
- Simple configuration in a single file
- Prometheus metrics
- Only one binary in docker container, low memory footprint
- Runs fine on raspberry pi

## Installation and configuration
Create `config.yml` file with your configuration [as yml](config.yml):
```yml
upstream:
    # these external DNS resolvers will be used. Blocky picks 2 random resolvers from the list for each query
    # format for resolver: [net:]host:[port][/path]. net could be empty (default, shortcut for tcp+udp), tcp+udp, tcp, udp, tcp-tls or https (DoH). If port is empty, default port will be used (53 for udp and tcp, 853 for tcp-tls, 443 for https (Doh))
    externalResolvers:
      - 46.182.19.48
      - 80.241.218.68
      - tcp-tls:fdns1.dismail.de:853
      - https://dns.digitale-gesellschaft.ch/dns-query
  
# optional: custom IP address for domain name (with all sub-domains)
# example: query "printer.lan" or "my.printer.lan" will return 192.168.178.3
customDNS:
    mapping:
      printer.lan: 192.168.178.3

# optional: definition, which DNS resolver should be used for queries to the domain (with all sub-domains).
# Example: Query client.fritz.box will ask DNS server 192.168.178.1. This is necessary for local network, to resolve clients by host name
conditional:
    mapping:
      fritz.box: udp:192.168.178.1
  
# optional: use black and white lists to block queries (for example ads, trackers, adult pages etc.)
blocking:
    # definition of blacklist groups. Can be external link (http/https) or local file
    blackLists:
      ads:
        - https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt
        - https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
        - https://mirror1.malwaredomains.com/files/justdomains
        - http://sysctl.org/cameleon/hosts
        - https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist
        - https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt
      special:
        - https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews/hosts
    # definition of whitelist groups. Attention: if the same group has black and whitelists, whitelists will be used to disable particular blacklist entries. If a group has only whitelist entries -> this means only domains from this list are allowed, all other domains will be blocked
    whiteLists:
      ads:
        - whitelist.txt
    # definition: which groups should be applied for which client
    clientGroupsBlock:
      # default will be used, if no special definition for a client name exists
      default:
        - ads
        - special
      # use client name (with wildcard support: * - sequence of any characters, [0-9] - range)
      # or single ip address / client subnet as CIDR notation
      laptop*:
        - ads
      192.168.178.1/24:
        - special
    # which response will be sent, if query is blocked:
    # zeroIp: 0.0.0.0 will be returned (default)
    # nxDomain: return NXDOMAIN as return code
    # comma separated list of destination IP adresses (for example: 192.100.100.15, 2001:0db8:85a3:08d3:1319:8a2e:0370:7344). Should contain ipv4 and ipv6 to cover all query types. Useful with running web server on this address to display the "blocked" page.
    blockType: zeroIp
    # optional: automatically list refresh period in minutes. Default: 4h.
    # Negative value -> deactivate automatically refresh.
    # 0 value -> use default
    refreshPeriod: 0

# optional: configuration for caching of DNS responses
caching:
  # amount in minutes, how long a response must be cached (min value). 
  # If <=0, use response's TTL, if >0 use this value, if TTL is smaller
  # Default: 0
  minTime: 40
  # amount in minutes, how long a response must be cached (max value). 
  # If <0, do not cache responses
  # If 0, use TTL
  # If > 0, use this value, if TTL is greater
  # Default: 0
  maxTime: -1
  
# optional: configuration of client name resolution
clientLookup:
  # optional: this DNS resolver will be used to perform reverse DNS lookup (typically local router)
  upstream: udp:192.168.178.1
  # optional: some routers return multiple names for client (host name and user defined name). Define which single name should be used.
  # Example: take second name if present, if not take first name
  singleNameOrder:
      - 2
      - 1
  # optional: custom mapping of client name to IP addresses. Useful if reverse DNS does not work properly or just to have custom client names.
  clients:
    laptop:
      - 192.168.178.29
# optional: configuration for prometheus metrics endpoint
prometheus:
  # enabled if true
  enable: true
  # url path, optional (default '/metrics')
  path: /metrics
  
# optional: write query information (question, answer, client, duration etc) to daily csv file
queryLog:
    # directory (should be mounted as volume in docker)
    dir: /logs
    # if true, write one file per client. Writes all queries to single file otherwise
    perClient: true
    # if > 0, deletes log files which are older than ... days
    logRetentionDays: 7
  
# optional: DNS listener port, default 53 (UDP and TCP)
port: 53
# optional: HTTP listener port, default 0 = no http listener. If > 0, will be used for prometheus metrics, pprof, REST API, DoH ...
httpPort: 4000
# optional: HTTPS listener port, default 0 = no http listener. If > 0, will be used for prometheus metrics, pprof, REST API, DoH...
httpsPort: 443
# mandatory, if https port > 0: path to cert and key file for SSL encryption
httpsCertFile: server.crt
httpsKeyFile: server.key
# optional: use this DNS server to resolve blacklist urls and upstream DNS servers (DOH). Useful if no DNS resolver is configured and blocky needs to resolve a host name. Format net:IP:port, net must be udp or tcp
bootstrapDns: tcp:1.1.1.1
# optional: Log level (one from debug, info, warn, error). Default: info
logLevel: info
# optional: Log format (text or json). Default: text
logFormat: text
```

### Run with docker
Start docker container with following `docker-compose.yml` file:
```yml
version: "2.1"
services:
  blocky:
    image: spx01/blocky
    container_name: blocky
    restart: unless-stopped
    ports:
      - "53:53/tcp"
      - "53:53/udp"
      - "4000:4000/tcp" # Prometheus stats (if enabled).
    environment:
      - TZ=Europe/Berlin
    volumes:
      # config file
      - ./config.yml:/app/config.yml
      # write query logs in this directory. You can also use a volume
      - ./logs:/logs
```

See [Wiki - Run with docker](https://github.com/0xERR0R/blocky/wiki/Run-with-docker) for more examples and additional information.

### Run standalone
Download the binary file for your architecture and run `./blocky --config config.yml`. Please be aware, you must run the binary with root privileges if you want to use port 53 or 953.

### Run with kubernetes (helm)
See [this repo](https://github.com/billimek/billimek-charts/tree/master/charts/blocky) or [the helm hub site](https://hub.helm.sh/charts/billimek/blocky) for details about running blocky via helm in kubernetes.

## CLI / REST API
If http listener is enabled, blocky provides REST API to control blocking status. Swagger documentation under `http://host:port/swagger`

To run CLI, please ensure, that blocky DNS server is running, than execute `blocky help` for help or
- `./blocky blocking enable` to enable blocking
- `./blocky blocking disable` to disable blocking
- `./blocky blocking disable --duration [duration]` to disable blocking for a certain amount of time (30s, 5m, 10m30s, ...)
- `./blocky blocking status` to print current status of blocking
- `./blocky query <domain>` execute DNS query (A) (simple replacement for dig, useful for debug purposes)
- `./blocky query <domain> --type <queryType>` execute DNS query with passed query type (A, AAAA, MX, ...)

To run this inside docker run `docker exec blocky ./blocky blocking status`

## Additional information

### HTTPS configuration (for DoH)
See [Wiki - Configuration of HTTPS](https://github.com/0xERR0R/blocky/wiki/Configuration-of-HTTPS-for-DoH-and-Rest-API) for detailed information, how to configure HTTPS.

DoH url: https://host:port/dns-query

### Prometheus / Grafana
Blocky can export metrics for prometheus. Example grafana dashboard definition [as JSON](blocky-grafana.json)
![grafana-dashboard](grafana-dashboard.png). 

See [Wiki - Prometheus / Grafana](https://github.com/0xERR0R/blocky/wiki/Prometheus---Grafana-integration) for more information.


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