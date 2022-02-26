# Configuration

This chapter describes all configuration options in `config.yaml`. You can download a reference file with all
configuration properties as [JSON](config.yml).

??? example "reference configuration file"

    ```yaml
    --8<-- "docs/config.yml"
    ```

## Basic configuration

| Parameter    | Type                            | Mandatory             | Default value | Description                                                                                                                                                                                                                                       |
|--------------|---------------------------------|-----------------------|---------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| port         | [IP]:port[,[IP]:port]*          | no                    | 53            | Port(s) and optional bind ip address(es) to serve DNS endpoint (TCP and UDP). If you wish to specify a specific IP, you can do so such as `192.168.0.1:53`. Example: `53`, `:53`, `127.0.0.1:53,[::1]:53`                                         |
| tlsPort      | [IP]:port[,[IP]:port]*          | no                    |               | Port(s) and optional bind ip address(es) to serve DoT DNS endpoint (DNS-over-TLS). If you wish to specify a specific IP, you can do so such as `192.168.0.1:853`. Example: `83`, `:853`, `127.0.0.1:853,[::1]:853`                                |
| httpPort     | [IP]:port[,[IP]:port]*          | no                    |               | Port(s) and optional bind ip address(es) to serve HTTP used for prometheus metrics, pprof, REST API, DoH... If you wish to specify a specific IP, you can do so such as `192.168.0.1:4000`. Example: `4000`, `:4000`, `127.0.0.1:4000,[::1]:4000` |
| httpsPort    | [IP]:port[,[IP]:port]*          | no                    |               | Port(s) and optional bind ip address(es) to serve HTTPS used for prometheus metrics, pprof, REST API, DoH... If you wish to specify a specific IP, you can do so such as `192.168.0.1:443`. Example: `443`, `:443`, `127.0.0.1:443,[::1]:443`     |
| certFile     | path                            | yes, if httpsPort > 0 |               | Path to cert and key file for SSL encryption (DoH and DoT)                                                                                                                                                                                        |
| keyFile      | path                            | yes, if httpsPort > 0 |               | Path to cert and key file for SSL encryption (DoH and DoT)
| bootstrapDns | IP:port                         | no                    |               | Use this DNS server to resolve blacklist urls and upstream DNS servers. Useful if no DNS resolver is configured and blocky needs to resolve a host name. NOTE: Works only on Linux/*Nix OS due to golang limitations under windows.               |
| disableIPv6  | bool                            | no                    | false         | Drop all AAAA query if set to true                                                                                                                                                                                                                |
| logLevel     | enum (debug, info, warn, error) | no                    | info          | Log level                                                                                                                                                                                                                                         |
| logFormat    | enum (text, json)               | no                    | text          | Log format (text or json).                                                                                                                                                                                                                        |
| logTimestamp | bool                            | no                    | true          | Log time stamps (true or false).                                                                                                                                                                                                                  |
| logPrivacy   | bool                            | no                    | false         | Obfuscate log output (replace all alphanumeric characters with *) for user sensitive data like request domains or responses to increase privacy.                                                                                                  |

!!! example

    ```yaml
    port: 53
    httpPort: 4000
    httpsPort: 443
    logLevel: info
    ```

## Upstream configuration

To resolve a DNS query, blocky needs external public or private DNS resolvers. Blocky supports DNS resolvers with
following network protocols (net part of the resolver URL):

- tcp+udp (UDP and TCP, dependent on query type)
- https (aka DoH)
- tcp-tls (aka DoT)

!!! hint

    You can (and should!) configure multiple DNS resolvers. Blocky picks 2 random resolvers from the list for each query and
    returns the answer from the fastest one. This improves your network speed and increases your privacy - your DNS traffic
    will be distributed over multiple providers.

Each resolver must be defined as a string in following format: `[net:]host:[port][/path]`.

| Parameter | Type                             | Mandatory | Default value                                     |
|-----------|----------------------------------|-----------|---------------------------------------------------|
| net       | enum (tcp+udp, tcp-tls or https) | no        | tcp+udp                                           |
| host      | IP or hostname                   | yes       |                                                   |
| port      | int (1 - 65535)                  | no        | 53 for udp/tcp, 853 for tcp-tls and 443 for https |

Blocky needs at least the configuration of the **default** group. This group will be used as a fallback, if no client
specific resolver configuration is available.

You can use the client name (see [Client name lookup](#client-name-lookup)), client's IP address or a client subnet as
CIDR notation.

!!! tip

    You can use `*` as wildcard for the sequence of any character or `[0-9]` as number range

!!! example

    ```yaml
    upstream:
      default:
      - 5.9.164.112
      - 1.1.1.1
      - tcp-tls:fdns1.dismail.de:853
      - https://dns.digitale-gesellschaft.ch/dns-query
      laptop*:
      - 123.123.123.123
      10.43.8.67/28:
      - 1.1.1.1
      - 9.9.9.9
    ```

Use `123.123.123.123` as single upstream DNS resolver for client laptop-home,
`1.1.1.1` and `9.9.9.9` for all clients in the sub-net `10.43.8.67/28` and 4 resolvers (default) for all others clients.

!!! note

    ** Blocky needs at least one upstream DNS server **

See [List of public DNS servers](additional_information.md#list-of-public-dns-servers) if you need some ideas, which
public free DNS server you could use.

### Upstream lookup timeout

Blocky will wait 2 seconds (default value) for the response from the external upstream DNS server. You can change this
value by setting the `upstreamTimeout` configuration parameter (in **duration format**).

!!! example

    ```yaml
    upstream:
        default:
        - 46.182.19.48
        - 80.241.218.68
    upstreamTimeout: 5s
    ```

## Custom DNS

You can define your own domain name to IP mappings. For example, you can use a user-friendly name for a network printer
or define a domain name for your local device on order to use the HTTPS certificate. Multiple IP addresses for one
domain must be separated by a comma.

| Parameter | Type                                    | Mandatory | Default value |
|-----------|-----------------------------------------|-----------|---------------|
| customTTL | duration (no unit is minutes)           | no        | 1h            |
| mapping   | string: string (hostname: address list) | no        |               |

!!! example

    ```yaml
    customDNS:
        customTTL: 1h
    mapping:
        printer.lan: 192.168.178.3
        otherdevice.lan: 192.168.178.15,2001:0db8:85a3:08d3:1319:8a2e:0370:7344
    ```

This configuration will also resolve any subdomain of the defined domain. For example a query "printer.lan" or "
my.printer.lan" will return 192.168.178.3 as IP address.

## Conditional DNS resolution

You can define, which DNS resolver(s) should be used for queries for the particular domain (with all subdomains). This
is for example useful, if you want to reach devices in your local network by the name. Since only your router know which
hostname belongs to which IP address, all DNS queries for the local network should be redirected to the router.

With the optional parameter `rewrite` you can replace domain part of the query with the defined part **before** the
resolver lookup is performed.

!!! example

    ```yaml
    conditional:
        rewrite:
            example.com: fritz.box
            replace-me.com: with-this.com
        mapping:
            fritz.box: 192.168.178.1
            lan.net: 192.170.1.2,192.170.1.3
            # for reverse DNS lookups of local devices
            178.168.192.in-addr.arpa: 192.168.178.1
            # for all unqualified hostnames
            .: 168.168.0.1
    ```

!!! tip

    You can use `.` as wildcard for all non full qualified domains (domains without dot)

In this example, a DNS query "client.fritz.box" will be redirected to the router's DNS server at 192.168.178.1 and client.lan.net to 192.170.1.2 and 192.170.1.3.
The query client.example.com will be rewritten to "client.fritz.box" and also redirected to the resolver at 192.168.178.1. All unqualified hostnames (e.g. 'test')
will be redirected to the DNS server at 168.168.0.1


## Client name lookup

Blocky can try to resolve a user-friendly client name from the IP address or server URL (DoT and DoH). This is useful
for defining of blocking groups, since IP address can change dynamically.

### Resolving client name from URL/Host

If DoT or DoH is enabled, you can use a subdomain prefixed with `id-` to provide a client name (wildcard ssl certificate
recommended).

Example: domain `example.com`

DoT Host: `id-bob.example.com` -> request's client name is `bob`
DoH URL: `https://id-bob.example.com/dns-query` -> request's client name is `bob`

For DoH you can also pass the client name as url parameter:

DoH URL: `https://blocky.example.com/dns-query/alice` -> request's client name is `alice`

### Resolving client name from IP address

Blocky uses rDNS to retrieve client's name. To use this feature, you can configure a DNS server for client lookup (
typically your router). You can also define client names manually per IP address.

#### Single name order

Some routers return multiple names for the client (host name and user defined name). With
parameter `clientLookup.singleNameOrder` you can specify, which of retrieved names should be used.

#### Custom client name mapping

You can also map a particular client name to one (or more) IP (ipv4/ipv6) addresses. Parameter `clientLookup.clients`
contains a map of client name and multiple IP addresses.

!!! example

    ```yaml
    clientLookup:
        upstream: 192.168.178.1
        singleNameOrder:
          - 2
          - 1
        clients:
          laptop:
            - 192.168.178.29
    ```

    Use `192.168.178.1` for rDNS lookup. Take second name if present, if not take first name. IP address `192.168.178.29` is mapped to `laptop` as client name.

## Blocking and whitelisting

Blocky can download and use external lists with domains or IP addresses to block DNS query (e.g. advertisement, malware,
trackers, adult sites). You can group several list sources together and define the blocking behavior per client.
External blacklists must be either in the well-known [Hosts format](https://en.wikipedia.org/wiki/Hosts_(file)) or just
a plain domain list (one domain per line). Blocky also supports regex as more powerful tool to define patterns to block.

Blocky uses [DNS sinkhole](https://en.wikipedia.org/wiki/DNS_sinkhole) approach to block a DNS query. Domain name from
the request, IP address from the response, and the CNAME record will be checked against configured blacklists.

To avoid over-blocking, you can define or use already existing whitelists.

### Definition black and whitelists

Each black or whitelist can be either a path to the local file, a URL to download or inline list definition of a domains
in hosts format (YAML literal block scalar style). All Urls must be grouped to a group name.

!!! example

    ```yaml
    blocking:
    blackLists:
    ads:
    - https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt
    - https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
    - |
    # inline definition with YAML literal block scalar style
    someadsdomain.com
    anotheradsdomain.com
    # this is a regex
    /^banners?[_.-]/
        special:
          - https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews/hosts
      whiteLists:
        ads:
          - whitelist.txt
          - |
            # inline definition with YAML literal block scalar style
            whitelistdomain.com
    ```

    In this example you can see 2 groups: **ads** with 2 lists and **special** with one list. One local whitelist was defined for the **ads** group.

!!! warning

    If the same group has black and whitelists, whitelists will be used to disable particular blacklist entries.
    If a group has **only** whitelist entries -> this means only domains from this list are allowed, all other domains will
    be blocked

!!! note
    Please define also client group mapping, otherwise you black and whitelist definition will have no effect

#### Regex support

You can use regex to define patterns to block. A regex entry must start and end with the slash character (/). Some
Examples:

- `/baddomain/` will block `www.baddomain.com`, `baddomain.com`, but also `mybaddomain-sometext.com`
- `/^baddomain/` will block `baddomain.com`, but not `www.baddomain.com`
- `/^apple\.(de|com)$/` will only block `apple.de` and `apple.com`

### Client groups

In this configuration section, you can define, which blocking group(s) should be used for which client in your network.
Example: All clients should use the **ads** group, which blocks advertisement and kids devices should use the **adult**
group, which blocky adult sites.

Clients without a group assignment will use automatically the **default** group.

You can use the client name (see [Client name lookup](#client-name-lookup)), client's IP address, client's full-qualified domain name
or a client subnet as CIDR notation.

If full-qualified domain name is used (for example "myclient.ddns.org"), blocky will try to resolve the IP address (A and AAAA records) of this domain.
If client's IP address matches with the result, the defined group will be used.

!!! example

    ```yaml
    blocking:
        clientGroupsBlock:
        # default will be used, if no special definition for a client name exists
          default:
            - ads
            - special
          laptop*:
            - ads
          192.168.178.1/24:
            - special
          kid-laptop:
            - ads
            - adult
    ```

    All queries from network clients, whose device name starts with `laptop`, will be filtered against the **ads** group's lists. All devices from the subnet `192.168.178.1/24` against the **special** group and `kid-laptop` against **ads** and **adult**. All other clients: **ads** and **special**.

!!! tip

    You can use `*` as wildcard for the sequence of any character or `[0-9]` as number range

### Block type

You can configure, which response should be sent to the client, if a requested query is blocked (only for A and AAAA
queries, NXDOMAIN for other types):

| blockType  | Example                                                 | Description                                                                                                                                                                            |
|------------|---------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| zeroIP     | zeroIP                                                  | This is the default block type. Server returns 0.0.0.0 (or :: for IPv6) as result for A and AAAA queries                                                                               |
| nxDomain   | nxDomain                                                | return NXDOMAIN as return code                                                                                                                                                         |
| custom IPs | 192.100.100.15, 2001:0db8:85a3:08d3:1319:8a2e:0370:7344 | comma separated list of destination IP addresses. Should contain ipv4 and ipv6 to cover all query types. Useful with running web server on this address to display the "blocked" page. |

!!! example

    ```yaml
    blocking:
    blockType: nxDomain
    ```

### Block TTL

TTL for answers to blocked domains can be set to customize the time (in **duration format**) clients ask for those
domains again. This setting only makes sense when `blockType` is set to `nxDomain` or `zeroIP`, and will affect how much
time it could take for a client to be able to see the real IP address for a domain after receiving the custom value.

!!! example

    ```yaml
    blocking:
      blockType: 192.100.100.15, 2001:0db8:85a3:08d3:1319:8a2e:0370:7344
      blockTTL: 10s
    ```

### List refresh period

To keep the list cache up-to-date, blocky will periodically download and reload all external lists. Default period is **
4 hours**. You can configure this by setting the `blocking.refreshPeriod` parameter to a value in **duration format**.
Negative value will deactivate automatically refresh.

!!! example

    ```yaml
    blocking:
    refreshPeriod: 60m
```

Refresh every hour.

### Download

You can configure the list download attempts according to your internet connection:

| Parameter        | Type            | Mandatory | Default value | Description                                     |
|------------------|-----------------|-----------|---------------|-------------------------------------------------|
| downloadTimeout  | duration format | no        | 60s           | Download attempt timeout                        |
| downloadAttempts | int             | no        | 3             | How many download attempts should be performed |
| downloadCooldown | duration format | no        | 1s            | Time between the download attempts              |

!!! example

    ```yaml
    blocking:
        downloadTimeout: 4m
        downloadAttempts: 5
        downloadCooldown: 10s
    ```

### Fail on start

You can ensure with parameter `failStartOnListError = true` that the application will fail if at least one list can't be
downloaded or opened. Default value is `false`.

!!! example

    ```yaml
    blocking:
     failStartOnListError: false
    ```

## Caching

Each DNS response has a TTL (Time-to-live) value. This value defines, how long is the record valid in seconds. The
values are maintained by domain owners, server administrators etc. Blocky caches the answers from all resolved queries
in own cache in order to avoid repeated requests. This reduces the DNS traffic and increases the network speed, since
blocky can serve the result immediately from the cache.

With following parameters you can tune the caching behavior:

!!! warning

    Wrong values can significantly increase external DNS traffic or memory consumption.

| Parameter                     | Type            | Mandatory | Default value | Description                                                                                                                                                                                                                                                                                                                                                                                                    |
|-------------------------------|-----------------|-----------|---------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| caching.minTime               | duration format | no        | 0 (use TTL)   | How long a response must be cached (min value). If <=0, use response's TTL, if >0 use this value, if TTL is smaller                                                                                                                                                                                                                                                                                            |
| caching.maxTime               | duration format | no        | 0 (use TTL)   | How long a response must be cached (max value). If <0, do not cache responses. If 0, use TTL. If > 0, use this value, if TTL is greater                                                                                                                                                                                                                                                                        |
| caching.maxItemsCount         | int             | no        | 0 (unlimited) | Max number of cache entries (responses) to be kept in cache (soft limit). Default (0): unlimited. Useful on systems with limited amount of RAM.                                                                                                                                                                                                                                                                |
| caching.prefetching           | bool            | no        | false         | if true, blocky will preload DNS results for often used queries (default: names queried more than 5 times in a 2 hour time window). Results in cache will be loaded again on their expire (TTL). This improves the response time for often used queries, but significantly increases external traffic. It is recommended to increase "minTime" to reduce the number of prefetch queries to external resolvers. |
| caching.prefetchExpires       | duration format | no        | 2h            | Prefetch track time window                                                                                                                                                                                                                                                                                                                                                                                     |
| caching.prefetchThreshold     | int             | no        | 5             | Name queries threshold for prefetch                                                                                                                                                                                                                                                                                                                                                                            |
| caching.prefetchMaxItemsCount | int             | no        | 0 (unlimited) | Max number of domains to be kept in cache for prefetching (soft limit). Default (0): unlimited. Useful on systems with limited amount of RAM.                                                                                                                                                                                                                                                                  |
| caching.cacheTimeNegative     | duration format | no        | 30m           | Time how long negative results are cached. A value of -1 will disable caching for negative results.                                                                                                                                                                                                                                                                                                            |

!!! example

    ```yaml
    caching:
        minTime: 5m
        maxTime: 30m
        prefetching: true
    ```

## Redis

Blocky can synchronize its cache and blocking state between multiple instances through redis.
Synchronization is disabled if no address is configured.

| Parameter                | Type            | Mandatory | Default value | Description                                |
|--------------------------|-----------------|-----------|---------------|--------------------------------------------|
| redis.address            | string          | no        |               | Server address and port                    |
| redis.password           | string          | no        |               | Password if necessary                      |
| redis.database           | int             | no        | 0             | Database                                   |
| redis.required           | bool            | no        | false         | Connection is required for blocky to start |
| redis.connectionAttempts | int             | no        | 3             | Max connection attempts                    |
| redis.connectionCooldown | duration format | no        | 1s            | Time between the connection attempts       |

!!! example

    ```yaml
    redis:
        address: redis:6379
        password: passwd
        database: 2
        required: true
        connectionAttempts: 10
        connectionCooldown: 3s
    ```

## Prometheus

Blocky can expose various metrics for prometheus. To use the prometheus feature, the HTTP listener must be enabled (
see [Basic Configuration](#basic-configuration)).

| Parameter         | Mandatory | Default value | Description                         |
|-------------------|-----------|---------------|-------------------------------------|
| prometheus.enable | no        | false         | If true, enables prometheus metrics |
| prometheus.path   | no        | /metrics      | URL path to the metrics endpoint    |

!!! example

    ```yaml
    prometheus:
        enable: true
        path: /metrics
    ```

## Query logging

You can enable the logging of DNS queries (question, answer, client, duration etc.) to a daily CSV file (can be opened
in Excel or OpenOffice Calc) or MySQL/MariaDB database.

!!! warning

    Query file/database contains sensitive information. Please ensure to inform users, if you log their queries.

### Query log types

You can select one of following query log types:

- `mysql` - log each query in the external MySQL/MariaDB database
- `postgresql` - log each query in the external PostgreSQL database
- `csv` - log into CSV file (one per day)
- `csv-client` - log into CSV file (one per day and per client)
- `console` - log into console output
- `none` - do not log any queries

Configuration parameters:

| Parameter                 | Type                                                                 | Mandatory | Default value | Description                                                                            |
|---------------------------|----------------------------------------------------------------------|-----------|---------------|----------------------------------------------------------------------------------------|
| queryLog.type             | enum (mysql, postgresql, csv, csv-client, console, none (see above)) | no        |               | Type of logging target. Console if empty                                               |
| queryLog.target           | string                                                               | no        |               | directory for writing the logs (for csv) or database url (for mysql or postgresql)     |
| queryLog.logRetentionDays | int                                                                  | no        | 0             | if > 0, deletes log files/database entries which are older than ... days               |
| queryLog.creationAttempts | int                                                                  | no        | 3             | Max attempts to create specific query log writer                                       |
| queryLog.CreationCooldown | duration format                                                      | no        | 2             | Time between the creation attempts                                                     |

!!! hint

    Please ensure, that the log directory is writable or database exists. If you use docker, please ensure, that the directory is properly
    mounted (e.g. volume)

example for CSV format
!!! example

    ```yaml
    queryLog:
        type: csv
        target: /logs
        logRetentionDays: 7
    ```

example for Database
!!! example

    ```yaml
    queryLog:
        type: mysql
        target: db_user:db_password@tcp(db_host_or_ip:3306)/db_user?charset=utf8mb4&parseTime=True&loc=Local
        logRetentionDays: 7
    ```

### Hosts file

You can enable resolving of entries, located in local hosts file.

Configuration parameters:

| Parameter                | Type                           | Mandatory | Default value | Description                                   |
|--------------------------|--------------------------------|-----------|---------------|-----------------------------------------------|
| hostsFile.filePath       | string                         | no        |               | Path to hosts file (e.g. /etc/hosts on Linux) |
| hostsFile.hostsTTL       | duration (no units is minutes) | no        | 1h            | TTL                                           |
| hostsFile.refreshPeriod  | duration format                | no        | 1h            | Time between hosts file refresh               |

!!! example

    ```yaml
    hostsFile:
        filePath: /etc/hosts
        hostsTTL: 60m
        refreshPeriod: 30m
    ```

## SSL certificate configuration (DoH / TLS listener)

See [Wiki - Configuration of HTTPS](https://github.com/0xERR0R/blocky/wiki/Configuration-of-HTTPS-for-DoH-and-Rest-API)
for detailed information, how to create and configure SSL certificates.

DoH url: `https://host:port/dns-query`

--8<-- "docs/includes/abbreviations.md"
