# Configuration

This chapter describes all configuration options in `config.yaml`. You can download a reference file with all
configuration properties as [JSON](config.yml).

??? example "reference configuration file"

    ```yaml
    --8<-- "docs/config.yml"
    ```

## Basic configuration

| Parameter           | Type                | Mandatory | Default value | Description                                                                                                |
| ------------------- | ------------------- | --------- | ------------- | ---------------------------------------------------------------------------------------------------------- |
| certFile            | path                | no        |               | Path to cert and key file for SSL encryption (DoH and DoT); if empty, self-signed certificate is generated |
| keyFile             | path                | no        |               | Path to cert and key file for SSL encryption (DoH and DoT); if empty, self-signed certificate is generated |
| minTlsServeVersion  | string              | no        | 1.2           | Minimum TLS version that the DoT and DoH server use to serve those encrypted DNS requests                  |
| connectIPVersion    | enum (dual, v4, v6) | no        | dual          | IP version to use for outgoing connections (dual, v4, v6)                                                  |

!!! example

    ```yaml
    minTlsServeVersion: 1.1
    connectIPVersion: v4
    ```

## Ports configuration

All logging port are optional.

| Parameter   | Type                   | Default value | Description                                                                                                                                                                                                                                       |
| ----------- | ---------------------- | ------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ports.dns   | [IP]:port[,[IP]:port]* | 53            | Port(s) and optional bind ip address(es) to serve DNS endpoint (TCP and UDP). If you wish to specify a specific IP, you can do so such as `192.168.0.1:53`. Example: `53`, `:53`, `127.0.0.1:53,[::1]:53`                                         |
| ports.tls   | [IP]:port[,[IP]:port]* |               | Port(s) and optional bind ip address(es) to serve DoT DNS endpoint (DNS-over-TLS). If you wish to specify a specific IP, you can do so such as `192.168.0.1:853`. Example: `83`, `:853`, `127.0.0.1:853,[::1]:853`                                |
| ports.http  | [IP]:port[,[IP]:port]* |               | Port(s) and optional bind ip address(es) to serve HTTP used for prometheus metrics, pprof, REST API, DoH... If you wish to specify a specific IP, you can do so such as `192.168.0.1:4000`. Example: `4000`, `:4000`, `127.0.0.1:4000,[::1]:4000` |
| ports.https | [IP]:port[,[IP]:port]* |               | Port(s) and optional bind ip address(es) to serve HTTPS used for prometheus metrics, pprof, REST API, DoH... If you wish to specify a specific IP, you can do so such as `192.168.0.1:443`. Example: `443`, `:443`, `127.0.0.1:443,[::1]:443`     |

!!! example

    ```yaml
    ports:
      dns: 53
      http: 4000
      https: 443
    ```

## Logging configuration

All logging options are optional.

| Parameter     | Type                            | Default value | Description                                                                                                                                      |
| ------------- | ------------------------------- | ------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| log.level     | enum (debug, info, warn, error) | info          | Log level                                                                                                                                        |
| log.format    | enum (text, json)               | text          | Log format (text or json).                                                                                                                       |
| log.timestamp | bool                            | true          | Log time stamps (true or false).                                                                                                                 |
| log.privacy   | bool                            | false         | Obfuscate log output (replace all alphanumeric characters with *) for user sensitive data like request domains or responses to increase privacy. |

!!! example

    ```yaml
    log:
      level: debug
      format: json
      timestamp: false
      privacy: true
    ```

## Upstreams configuration

| Parameter             | Type                                 | Mandatory | Default value | Description                                                                                     |
| --------------------- | ------------------------------------ | --------- | ------------- | ----------------------------------------------------------------------------------------------- |
| usptreams.groups      | map of name to upstream              | yes       |               | Upstream DNS servers to use, in groups.                                                         |
| usptreams.startVerify | bool                                 | no        | false         | If true, blocky will fail to start unless at least one upstream server per group is functional. |
| usptreams.strategy    | enum (parallel_best, random, strict) | no        | parallel_best | Upstream server usage strategy.                                                                 |
| usptreams.timeout     | duration                             | no        | 2s            | Upstream connection timeout.                                                                    |
| usptreams.userAgent   | string                               | no        |               | HTTP User Agent when connecting to upstreams.                                                   |


### Upstream Groups

To resolve a DNS query, blocky needs external public or private DNS resolvers. Blocky supports DNS resolvers with
following network protocols (net part of the resolver URL):

- tcp+udp (UDP and TCP, dependent on query type)
- https (aka DoH)
- tcp-tls (aka DoT)

!!! hint

    You can (and should!) configure multiple DNS resolvers.  
    Per default blocky uses the `parallel_best` upstream strategy where blocky picks 2 random resolvers from the list for each query and
    returns the answer from the fastest one.  

Each resolver must be defined as a string in following format: `[net:]host:[port][/path][#commonName]`.

| Parameter  | Type                             | Mandatory | Default value                                     |
| ---------- | -------------------------------- | --------- | ------------------------------------------------- |
| net        | enum (tcp+udp, tcp-tls or https) | no        | tcp+udp                                           |
| host       | IP or hostname                   | yes       |                                                   |
| port       | int (1 - 65535)                  | no        | 53 for udp/tcp, 853 for tcp-tls and 443 for https |
| commonName | string                           | no        | the host value                                    |

The `commonName` parameter overrides the expected certificate common name value used for verification.

!!! note
    Blocky needs at least the configuration of the **default** group with at least one upstream DNS server. This group will be used as a fallback, if no client
    specific resolver configuration is available.

    See [List of public DNS servers](additional_information.md#list-of-public-dns-servers) if you need some ideas, which public free DNS server you could use.

You can specify multiple upstream groups (additional to the `default` group) to use different upstream servers for different clients, based on client name (see [Client name lookup](#client-name-lookup)), client IP address or client subnet (as CIDR).

!!! tip

    You can use `*` as wildcard for the sequence of any character or `[0-9]` as number range

!!! example

    ```yaml
    upstreams:
      groups:
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

The above example results in:

- `123.123.123.123` as the only upstream DNS resolver for clients with a name starting with "laptop"
- `1.1.1.1` and `9.9.9.9` for all clients in the subnet `10.43.8.67/28`
- 4 resolvers (default) for all others clients.

The logic determining what group a client belongs to follows a strict order: IP, client name, CIDR

If a client matches multiple client name or CIDR groups, a warning is logged and the first found group is used.

### Upstream connection timeout

Blocky will wait 2 seconds (default value) for the response from the external upstream DNS server. You can change this
value by setting the `timeout` configuration parameter (in **duration format**).

!!! example

    ```yaml
    upstreams:
      timeout: 5s
      groups:
        default:
          - 46.182.19.48
          - 80.241.218.68
    ```

### Upstream strategy

Blocky supports different upstream strategies (default `parallel_best`) that determine how and to which upstream DNS servers requests are forwarded.

Currently available strategies:

- `parallel_best`: blocky picks 2 random (weighted) resolvers from the upstream group for each query and returns the answer from the fastest one.  
  If an upstream failed to answer within the last hour, it is less likely to be chosen for the race.  
  This improves your network speed and increases your privacy - your DNS traffic will be distributed over multiple providers.  
  (When using 10 upstream servers, each upstream will get on average 20% of the DNS requests)
- `random`: blocky picks one random (weighted) resolver from the upstream group for each query and if successful, returns its response.  
  If the selected resolver fails to respond, a second one is picked to which the query is sent.  
  The weighting is identical to the `parallel_best` strategy.  
  Although the `random` strategy might be slower than the `parallel_best` strategy, it offers more privacy since each request is sent to a single upstream.
- `strict`: blocky forwards the request in a strict order. If the first upstream does not respond, the second is asked, and so on.

!!! example

    ```yaml
    upstreams:
      strategy: strict
      groups:
        default:
          - 1.2.3.4
          - 9.8.7.6
    ```


## Bootstrap DNS configuration

These DNS servers are used to resolve upstream DoH and DoT servers that are specified as host names, and list domains.
It is useful if no system DNS resolver is configured, and/or to encrypt the bootstrap queries.

| Parameter | Type                 | Mandatory                   | Default value | Description                          |
| --------- | -------------------- | --------------------------- | ------------- | ------------------------------------ |
| upstream  | Upstream (see above) | no                          |               |                                      |
| ips       | List of IPs          | yes, if upstream is DoT/DoH |               | Only valid if upstream is DoH or DoT |

When using an upstream specified by IP, and not by hostname, you can write only the upstream and skip `ips`.

!!! note

    Works only on Linux/\*nix OS due to golang limitations under Windows.

!!! example

    ```yaml
        bootstrapDns:
          - upstream: tcp-tls:dns.example.com
            ips:
            - 123.123.123.123
          - upstream: https://234.234.234.234/dns-query
    ```

## Filtering

Under certain circumstances, it may be useful to filter some types of DNS queries. You can define one or more DNS query
types, all queries with these types will be dropped (empty answer will be returned).

!!! example

    ```yaml
    filtering:
      queryTypes:
        - AAAA
    ```

This configuration will drop all 'AAAA' (IPv6) queries.

## FQDN only

In domain environments, it may be useful to only response to FQDN requests. If this option is enabled blocky respond immediately
with NXDOMAIN if the request is not a valid FQDN. The request is therefore not further processed by other options like custom or conditional.
Please be aware that by enabling it your hostname resolution will break unless every hostname is part of a domain.

!!! example

    ```yaml
    fqdnOnly:
      enable: true
    ```

## Custom DNS

You can define your own domain name to IP mappings. For example, you can use a user-friendly name for a network printer
or define a domain name for your local device on order to use the HTTPS certificate. Multiple IP addresses for one
domain must be separated by a comma.

| Parameter           | Type                                    | Mandatory | Default value |
| ------------------- | --------------------------------------- | --------- | ------------- |
| customTTL           | duration (no unit is minutes)           | no        | 1h            |
| rewrite             | string: string (domain: domain)         | no        |               |
| mapping             | string: string (hostname: address list) | no        |               |
| filterUnmappedTypes | boolean                                 | no        | true          |

!!! example

    ```yaml
    customDNS:
      customTTL: 1h
      filterUnmappedTypes: true
      rewrite:
        home: lan
        replace-me.com: with-this.com
      mapping:
        printer.lan: 192.168.178.3
        otherdevice.lan: 192.168.178.15,2001:0db8:85a3:08d3:1319:8a2e:0370:7344
    ```

This configuration will also resolve any subdomain of the defined domain. For example a query "printer.lan" or "
my.printer.lan" will return 192.168.178.3 as IP address.

With the optional parameter `rewrite` you can replace domain part of the query with the defined part **before** the
resolver lookup is performed.
The query "printer.home" will be rewritten to "printer.lan" and return 192.168.178.3.

With parameter `filterUnmappedTypes = true` (default), blocky will filter all queries with unmapped types, for example:
AAAA for "printer.lan" or TXT for "otherdevice.lan".
With `filterUnmappedTypes = false` a query AAAA "printer.lan" will be forwarded to the upstream DNS server.

## Conditional DNS resolution

You can define, which DNS resolver(s) should be used for queries for the particular domain (with all subdomains). This
is for example useful, if you want to reach devices in your local network by the name. Since only your router know which
hostname belongs to which IP address, all DNS queries for the local network should be redirected to the router.

The optional parameter `rewrite` behaves the same as with custom DNS.

The optional parameter `fallbackUpstream`, if false (default), return empty result if after rewrite, the mapped resolver returned an empty answer. If true, the original query will be sent to the upstream resolver.

**Usage:** One usecase when having split DNS for internal and external (internet facing) users, but not all subdomains are listed in the internal domain

!!! example

    ```yaml
    conditional:
      fallbackUpstream: false
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
The query "client.example.com" will be rewritten to "client.fritz.box" and also redirected to the resolver at 192.168.178.1.

If not found and if `fallbackUpstream` was set to `true`, the original query "blog.example.com" will be sent upstream.

All unqualified host names (e.g. "test") will be redirected to the DNS server at 168.168.0.1.

One usecase for `fallbackUpstream` is when having split DNS for internal and external (internet facing) users, but not all subdomains are listed in the internal domain.

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

Blocky can use lists of domains and IPs to block (e.g. advertisement, malware,
trackers, adult sites). You can group several list sources together and define the blocking behavior per client.
Blocking uses the [DNS sinkhole](https://en.wikipedia.org/wiki/DNS_sinkhole) approach. For each DNS query, the domain name from
the request, IP address from the response, and any CNAME records will be checked to determine whether to block the query or not.

To avoid over-blocking, you can use whitelists.

### Definition black and whitelists

Lists are defined in groups. This allows using different sets of lists for different clients.

Each list in a group is a "source" and can be downloaded, read from a file, or inlined in the config. See [Sources](#sources) for details and configuring how those are loaded and reloaded/refreshed.

The supported list formats are:

1. the well-known [Hosts format](https://en.wikipedia.org/wiki/Hosts_(file))
2. one domain per line (plain domain list)
3. one wildcard per line
4. one regex per line

!!! example

    ```yaml
    blocking:
      blackLists:
        ads:
          - https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt
          - https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
          - |
            # inline definition using YAML literal block scalar style
            # content is in plain domain list format
            someadsdomain.com
            anotheradsdomain.com
            *.wildcard.example.com # blocks wildcard.example.com and all subdomains
          - |
            # inline definition with a regex
            /^banners?[_.-]/
        special:
          - https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews/hosts
      whiteLists:
        ads:
          - whitelist.txt
          - /path/to/file.txt
          - |
            # inline definition with YAML literal block scalar style
            whitelistdomain.com
    ```

    In this example you can see 2 groups: **ads** and **special** with one list. The **ads** group includes 2 inline lists.

!!! warning

    If the same group has black and whitelists, whitelists will be used to disable particular blacklist entries.
    If a group has **only** whitelist entries -> this means only domains from this list are allowed, all other domains will
    be blocked.

!!! warning
    You must also define client group mapping, otherwise you black and whitelist definition will have no effect.

#### Wildcard support

You can use wildcards to block a domain and all its subdomains.
Example: `*.example.com` will block `example.com` and `any.subdomains.example.com`.

#### Regex support

You can use regex to define patterns to block. A regex entry must start and end with the slash character (`/`). Some
Examples:

- `/baddomain/` will block `www.baddomain.com`, `baddomain.com`, but also `mybaddomain-sometext.com`
- `/^baddomain/` will block `baddomain.com`, but not `www.baddomain.com`
- `/^apple\.(de|com)$/` will only block `apple.de` and `apple.com`

!!! warning
    Regexes use more a lot more memory and are much slower than wildcards, you should use them as a last resort.

### Client groups

In this configuration section, you can define, which blocking group(s) should be used for which client in your network.
Example: All clients should use the **ads** group, which blocks advertisement and kids devices should use the **adult**
group, which blocky adult sites.

Clients without an explicit group assignment will use the **default** group.

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
| ---------- | ------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
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
domains again. Default Block TTL is **6hours**. This setting only makes sense when `blockType` is set to `nxDomain` or
`zeroIP`, and will affect how much time it could take for a client to be able to see the real IP address for a domain
after receiving the custom value.

!!! example

    ```yaml
    blocking:
      blockType: 192.100.100.15, 2001:0db8:85a3:08d3:1319:8a2e:0370:7344
      blockTTL: 10s
    ```

### Lists Loading

See [Sources Loading](#sources-loading).

## Caching

Each DNS response has a TTL (Time-to-live) value. This value defines, how long is the record valid in seconds. The
values are maintained by domain owners, server administrators etc. Blocky caches the answers from all resolved queries
in own cache in order to avoid repeated requests. This reduces the DNS traffic and increases the network speed, since
blocky can serve the result immediately from the cache.

With following parameters you can tune the caching behavior:

!!! warning

    Wrong values can significantly increase external DNS traffic or memory consumption.

| Parameter                     | Type            | Mandatory | Default value | Description                                                                                                                                                                                                                                                                                                                                                                                                    |
| ----------------------------- | --------------- | --------- | ------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| caching.minTime               | duration format | no        | 0 (use TTL)   | How long a response must be cached (min value). If <=0, use response's TTL, if >0 use this value, if TTL is smaller                                                                                                                                                                                                                                                                                            |
| caching.maxTime               | duration format | no        | 0 (use TTL)   | How long a response must be cached (max value). If <0, do not cache responses. If 0, use TTL. If > 0, use this value, if TTL is greater                                                                                                                                                                                                                                                                        |
| caching.maxItemsCount         | int             | no        | 0 (unlimited) | Max number of cache entries (responses) to be kept in cache (soft limit). Default (0): unlimited. Useful on systems with limited amount of RAM.                                                                                                                                                                                                                                                                |
| caching.prefetching           | bool            | no        | false         | if true, blocky will preload DNS results for often used queries (default: names queried more than 5 times in a 2 hour time window). Results in cache will be loaded again on their expire (TTL). This improves the response time for often used queries, but significantly increases external traffic. It is recommended to increase "minTime" to reduce the number of prefetch queries to external resolvers. |
| caching.prefetchExpires       | duration format | no        | 2h            | Prefetch track time window                                                                                                                                                                                                                                                                                                                                                                                     |
| caching.prefetchThreshold     | int             | no        | 5             | Name queries threshold for prefetch                                                                                                                                                                                                                                                                                                                                                                            |
| caching.prefetchMaxItemsCount | int             | no        | 0 (unlimited) | Max number of domains to be kept in cache for prefetching (soft limit). Default (0): unlimited. Useful on systems with limited amount of RAM.                                                                                                                                                                                                                                                                  |
| caching.cacheTimeNegative     | duration format | no        | 30m           | Time how long negative results (NXDOMAIN response or empty result) are cached. A value of -1 will disable caching for negative results.                                                                                                                                                                                                                                                                        |

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

| Parameter                | Type            | Mandatory | Default value | Description                                                         |
| ------------------------ | --------------- | --------- | ------------- | ------------------------------------------------------------------- |
| redis.address            | string          | no        |               | Server address and port or master name if sentinel is used          |
| redis.username           | string          | no        |               | Username if necessary                                               |
| redis.password           | string          | no        |               | Password if necessary                                               |
| redis.database           | int             | no        | 0             | Database                                                            |
| redis.required           | bool            | no        | false         | Connection is required for blocky to start                          |
| redis.connectionAttempts | int             | no        | 3             | Max connection attempts                                             |
| redis.connectionCooldown | duration format | no        | 1s            | Time between the connection attempts                                |
| redis.sentinelUsername   | string          | no        |               | Sentinel username if necessary                                      |
| redis.sentinelPassword   | string          | no        |               | Sentinel password if necessary                                      |
| redis.sentinelAddresses  | string[]        | no        |               | Sentinel host list (Sentinel is activated if addresses are defined) |

!!! example

    ```yaml
    redis:
      address: redismaster
      username: usrname
      password: passwd
      database: 2
      required: true
      connectionAttempts: 10
      connectionCooldown: 3s
      sentinelUsername: sentUsrname
      sentinelPassword: sentPasswd
      sentinelAddresses:
        - redis-sentinel1:26379
        - redis-sentinel2:26379
        - redis-sentinel3:26379
    ```

## Prometheus

Blocky can expose various metrics for prometheus. To use the prometheus feature, the HTTP listener must be enabled (
see [Basic Configuration](#basic-configuration)).

| Parameter         | Mandatory | Default value | Description                         |
| ----------------- | --------- | ------------- | ----------------------------------- |
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

### Query log fields

You can choose which information from processed DNS request and response should be logged in the target system. You can define one or more of following fields:

- `clientIP` - origin IP address from the request
- `clientName` - resolved client name(s) from the origins request
- `responseReason` - reason for the response (e.g. from which upstream resolver), response type and code
- `responseAnswer` - returned DNS answer
- `question` - DNS question from the request
- `duration` - request processing time in milliseconds

!!! hint
    If not defined, blocky will log all available information

Configuration parameters:

| Parameter                 | Type                                                                                 | Mandatory | Default value | Description                                                                        |
| ------------------------- | ------------------------------------------------------------------------------------ | --------- | ------------- | ---------------------------------------------------------------------------------- |
| queryLog.type             | enum (mysql, postgresql, csv, csv-client, console, none (see above))                 | no        |               | Type of logging target. Console if empty                                           |
| queryLog.target           | string                                                                               | no        |               | directory for writing the logs (for csv) or database url (for mysql or postgresql) |
| queryLog.logRetentionDays | int                                                                                  | no        | 0             | if > 0, deletes log files/database entries which are older than ... days           |
| queryLog.creationAttempts | int                                                                                  | no        | 3             | Max attempts to create specific query log writer                                   |
| queryLog.creationCooldown | duration format                                                                      | no        | 2s            | Time between the creation attempts                                                 |
| queryLog.fields           | list enum (clientIP, clientName, responseReason, responseAnswer, question, duration) | no        | all           | which information should be logged                                                 |
| queryLog.flushInterval    | duration format                                                                      | no        | 30s           | Interval to write data in bulk to the external database                            |

!!! hint

    Please ensure, that the log directory is writable or database exists. If you use docker, please ensure, that the directory is properly
    mounted (e.g. volume)

example for CSV format with limited logging information
!!! example

    ```yaml
    queryLog:
      type: csv
      target: /logs
      logRetentionDays: 7
      fields:
      - clientIP
      - duration
      flushInterval: 30s
    ```

example for Database
!!! example

    ```yaml
    queryLog:
      type: mysql
      target: db_user:db_password@tcp(db_host_or_ip:3306)/db_user?charset=utf8mb4&parseTime=True&loc=Local
      logRetentionDays: 7
    ```

## Hosts file

You can enable resolving of entries, located in local hosts file.

Configuration parameters:

| Parameter                | Type                           | Mandatory | Default value | Description                                     |
| ------------------------ | ------------------------------ | --------- | ------------- | ----------------------------------------------- |
| hostsFile.filePath       | string                         | no        |               | Path to hosts file (e.g. /etc/hosts on Linux)   |
| hostsFile.hostsTTL       | duration (no units is minutes) | no        | 1h            | TTL                                             |
| hostsFile.refreshPeriod  | duration format                | no        | 1h            | Time between hosts file refresh                 |
| hostsFile.filterLoopback | bool                           | no        | false         | Filter loopback addresses (127.0.0.0/8 and ::1) |

!!! example

    ```yaml
    hostsFile:
      filePath: /etc/hosts
      hostsTTL: 1h
      refreshPeriod: 30m
    ```

## Deliver EDE codes as EDNS0 option

DNS responses can be extended with EDE codes according to [RFC8914](https://datatracker.ietf.org/doc/rfc8914/).

Configuration parameters:

| Parameter  | Type | Mandatory | Default value | Description                                        |
| ---------- | ---- | --------- | ------------- | -------------------------------------------------- |
| ede.enable | bool | no        | false         | If true, DNS responses are deliverd with EDE codes |

!!! example

    ```yaml
    ede:
      enable: true
    ```

## EDNS Client Subnet options

EDNS Client Subnet (ECS) configuration parameters:

| Parameter       | Type | Mandatory | Default value | Description                                                                                   |
| --------------- | ---- | --------- | ------------- | --------------------------------------------------------------------------------------------- |
| ecs.useAsClient | bool | no        | false         | Use ECS information if it is present with a netmask is 32 for IPv4 or 128 for IPv6 as CientIP |
| ecs.forward     | bool | no        | false         | Forward ECS option to upstream                                                                |
| ecs.ipv4Mask    | int  | no        | 0             | Add ECS option for IPv4 requests if mask is greater than zero (max value 32)                  |
| ecs.ipv6Mask    | int  | no        | 0             | Add ECS option for IPv6 requests if mask is greater than zero (max value 128)                 |

!!! example

    ```yaml
    ecs:
      ipv4Mask: 32
      ipv6Mask: 128
    ```

## Special Use Domain Names

SUDN (Special Use Domain Names) are always enabled as they are required by various RFCs.  
Some RFCs have optional recommendations, which are configurable as described below.

Configuration parameters:

| Parameter                           | Type | Mandatory | Default value | Description                                                                                   |
| ----------------------------------- | ---- | --------- | ------------- | --------------------------------------------------------------------------------------------- |
| specialUseDomains.rfc6762-appendixG | bool | no        | true          | Block TLDs listed in [RFC 6762 Appendix G](https://www.rfc-editor.org/rfc/rfc6762#appendix-G) |

!!! example

    ```yaml
    specialUseDomains:
      rfc6762-appendixG: true
    ```

## SSL certificate configuration (DoH / TLS listener)

See [Wiki - Configuration of HTTPS](https://github.com/0xERR0R/blocky/wiki/Configuration-of-HTTPS-for-DoH-and-Rest-API)
for detailed information, how to create and configure SSL certificates.

DoH url: `https://host:port/dns-query`

--8<-- "docs/includes/abbreviations.md"

## Sources

Sources are a concept shared by the blocking and hosts file resolvers. They represent where to load the files for each resolver.

The supported source types are:

- HTTP(S) URL (any source starting with `http`)
- inline configuration (any source containing a newline)
- local file path (any source not matching the above rules)

!!! note

    The format/content of the sources depends on the context: lists and hosts files have different, but overlapping, supported formats.

!!! example

    ```yaml
    - https://example.com/a/source # blocky will download and parse the file
    - /a/file/path # blocky will read the local file
    - | # blocky will parse the content of this multi-line string
      # inline configuration
    ```

### Sources Loading

This sections covers `loading` configuration that applies to both the blocking and hosts file resolvers.
These settings apply only to the resolver under which they are nested.

!!! example

    ```yaml
    blocking:
      loading:
        # only applies to white/blacklists

    hostsFile:
      loading:
        # only applies to hostsFile sources
    ```

#### Refresh / Reload

To keep source contents up-to-date, blocky can periodically refresh and reparse them. Default period is **
4 hours**. You can configure this by setting the `refreshPeriod` parameter to a value in **duration format**.  
A value of zero or less will disable this feature.

!!! example

    ```yaml
    loading:
      refreshPeriod: 1h
    ```

    Refresh every hour.

### Downloads

Configures how HTTP(S) sources are downloaded:

| Parameter | Type     | Mandatory | Default value | Description                                    |
| --------- | -------- | --------- | ------------- | ---------------------------------------------- |
| timeout   | duration | no        | 5s            | Download attempt timeout                       |
| attempts  | int      | no        | 3             | How many download attempts should be performed |
| cooldown  | duration | no        | 500ms         | Time between the download attempts             |

!!! example

    ```yaml
    loading:
      downloads:
        timeout: 4m
        attempts: 5
        cooldown: 10s
    ```

### Strategy

This configures how Blocky startup works.  
The default strategy is blocking.

| strategy    | Description                                                                                                                              |
| ----------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| blocking    | all sources are loaded before DNS resolution starts                                                                                      |
| failOnError | like blocking but blocky will shut down if any source fails to load                                                                      |
| fast        | blocky starts serving DNS immediately and sources are loaded asynchronously. The features requiring the sources should enable soon after |

!!! example

    ```yaml
    loading:
      strategy: failOnError
    ```

### Max Errors per Source

Number of errors allowed when parsing a source before it is considered invalid and parsing stops.  
A value of -1 disables the limit.

!!! example

    ```yaml
    loading:
      maxErrorsPerSource: 10
    ```

### Concurrency

Blocky downloads and processes sources concurrently. This allows limiting how many can be processed in the same time.  
Larger values can reduce the overall list refresh time at the cost of using more RAM. Please consider reducing this value on systems with limited memory.  
Default value is 4.

!!! example

    ```yaml
    loading:
      concurrency: 10
    ```

!!! note

    As with other settings under `loading`, the limit applies to the blocking and hosts file resolvers separately.
    The total number of concurrent sources concurrently processed can reach the sum of both values.  
    For example if blocking has a limit set to 8 and hosts file's is 4, there could be up to 12 concurrent jobs.
