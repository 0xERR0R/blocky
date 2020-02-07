[![GitHub Workflow Status](https://img.shields.io/github/workflow/status/0xERR0R/blocky/CI%20Build?label=CI%20Build "CI Build")](#)
[![GitHub Workflow Status](https://img.shields.io/github/workflow/status/0xERR0R/blocky/Release?label=Release "Release")](#)
[![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/0xERR0R/blocky "Go version")](#)
[![GitHub latest version](https://img.shields.io/github/v/release/0xERR0R/blocky "Latest version")](https://github.com/0xERR0R/blocky/releases)
[![Docker latest version](https://img.shields.io/badge/docker-latest-blue "Latest version")](https://hub.docker.com/r/spx01/blocky)
[![GitHub Release Date](https://img.shields.io/github/release-date/0xERR0R/blocky "Latest release date")](https://github.com/0xERR0R/blocky/releases)
[![Codecov](https://img.shields.io/codecov/c/gh/0xERR0R/blocky "Code coverage")](#)
[![Codacy grade](https://img.shields.io/codacy/grade/8fcd8f8420b8419c808c47af58ed9282 "Codacy grade")](#)



<p align="center">
  <img height="200" src="blocky.svg">
</p>

# Blocky
Blocky is a DNS proxy for local network written in Go with following features:
- Blocking of DNS queries with external lists (Ad-block) with whitelisting
  - Definition of black and white lists per client group (Kids, Smart home devices etc) -> for example: you can block some domains for you Kids and allow your network camera only domains from a whitelist
  - periodical reload of external black and white lists
- Caching of DNS answers for queries -> improves DNS resolution speed and reduces amount of external DNS queries
- Custom DNS resolution for certain domain names
- Supports UDP, TCP and TCP over TLS DNS resolvers
- Delegates DNS query to 2 external resolver from a list of configured resolvers, uses the answer from the fastest one -> improves you privacy and resolution time
- Logging of all DNS queries per day / per client in a text file
- Simple configuration in a single file
- Only one binary in docker container, low memory footprint
- Runs fine on raspbery pi

## Installation and configuration
Create `config.yml` file with your configuration:
```yml
upstream:
    # these external DNS resolvers will be used. Blocky picks 2 random resolvers from the list for each query
    # format for resolver: net:host:port. net could be tcp, udp or tcp-tls. If port is empty, default port will be used (53 for udp and tcp, 853 for tcp-tls)
    externalResolvers:
      - udp:8.8.8.8
      - udp:8.8.4.4
      - udp:1.1.1.1
      - tcp-tls:1.0.0.1:853
  
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
        - https://hosts-file.net/ad_servers.txt
    # definition of whitelist groups. Attention: if the same group has black and whitelists, whitelists will be used to disable particular blacklist entries. If a group has only whitelist entries -> this means only domains from this list are allowed, all other domains will be blocked
    whiteLists:
      ads:
        - whitelist.txt
    # definition: which groups should be appied for which client
    clientGroupsBlock:
      # default will be used, if no special definition for a client name exists
      default:
        - ads
        - special
      # use client name or ip address
      laptop.fritz.box:
        - ads
    # which response will be sent, if query is blocked:
    # zeroIp: 0.0.0.0 will be returned (default)
    # nxDomain: return NXDOMAIN as return code
    blockType: zeroIp
    # optional: automaticaly list refresh period in minutes. Default: 4h.
    # Negative value -> deactivate automaticaly refresh.
    # 0 value -> use default
    refreshPeriod: 1
  
#optional: configuration of client name resolution
clientLookup:
    # this DNS resolver will be used to perform reverse DNS lookup (typically local router)
    upstream: udp:192.168.178.1
    # optional: some routers return multiple names for client (host name and user defined name). Define which single name should be used.
    # Example: take second name if present, if not take first name
    singleNameOrder:
      - 2
      - 1
  
# optional: write query information (question, answer, client, duration etc) to daily csv file
queryLog:
    # directory (should be mounted as volume in docker)
    dir: /logs
    # if true, write one file per client. Writes all queries to single file otherwise
    perClient: true
    # if > 0, deletes log files which are older than ... days
    logRetentionDays: 7
  
# Port, should be 53 (UDP and TCP)
port: 53
# Log level (one from debug, info, warn, error)
logLevel: info
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
    environment:
      - TZ=Europe/Berlin
    volumes:
      # config file
      - ./config.yml:/app/config.yml
      # write query logs in this directory. You can also use a volume
      - ./logs:/logs
```

### Run standalone
Download binary file for your architecture, put it in one directory with config file. Please be aware, you must run the binary with root privileges if you want to use port 53 or 953.

### Additional information
To print runtime configuration / statistics, you can send signal to running process:
* `SIGUSR1` will print current configuration
* `SIGUSR2` prints 24h statistics

Hint: `kill -s USR1 <PID>` or `docker kill -s SIGUSR1 blocky` for docker setup
