# Configuration

This chapter describes all configuration options in `config.yaml`. You can download a reference file with all
configuration properties as [JSON](config.yml).

## Basic configuration

| Parameter       | Mandatory | Default value      | Description                                       |
| --------------- | --------- | -------------------| ------------------------------------------------- |
| port            | no        | 53                 | Port to serve DNS endpoint (TCP and UDP)          |
| httpPort        | no        | 0                  | HTTP listener port. If > 0, will be used for prometheus metrics, pprof, REST API, DoH ... |
| httpsPort       | no        | 0                  | HTTPS listener port. If > 0, will be used for prometheus metrics, pprof, REST API, DoH... |
| httpsCertFile   | yes, if httpsPort > 0 |        | path to cert and key file for SSL encryption |
| httpsKeyFile    | yes, if httpsPort > 0 |        | path to cert and key file for SSL encryption |
| bootstrapDns    | no        |                    | use this DNS server to resolve blacklist urls and upstream DNS servers (DoH). Useful if no DNS resolver is configured and blocky needs to resolve a host name. Format net:IP:port, net must be udp or tcp|
| disableIPv6     | no        | false              | Drop all AAAA query if set to true
| logLevel        | no        | info               | Log level (one from debug, info, warn, error) |
| logFormat       | no        | text               | Log format (text or json). |
| logTimestamp    | no        | true               | Log time stamps (true or false). |

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

- udp (only UDP)
- tcp (only TCP)
- tcp+udp (UDP and TCP, dependent on query type)
- https (aka DoH)
- tcp-tls (aka DoT)

!!! hint

    You can (and should!) configure multiple DNS resolvers. Blocky picks 2 random resolvers from the list for each query and
    returns the answer from the fastest one. This improves your network speed and increases your privacy - your DNS traffic
    will be distributed over multiple providers.

Each resolver must be defined as a string in following format: `[net:]host:[port][/path]`.

| Parameter | Mandatory | Value                                        | Default value                                     |
| --------- | --------- | -------------------------------------------- | ------------------------------------------------- |
| net       | no        | one of (tcp+udp, tcp, udp, tcp-tls or https) | tcp+udp                                           |
| host      | yes       | full qualified domain name or ip address     |                                                   |
| port      | no        | number < 65535                               | 53 for udp/tcp, 853 for tcp-tls and 443 for https |

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
        - 46.182.19.48
        - 80.241.218.68
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

## Custom DNS

You can define your own domain name to IP mappings. For example, you can use a user-friendly name for a network printer
or define a domain name for your local device on order to use the HTTPS certificate. Multiple IP addresses for one
domain must be separated by a comma.

!!! example

    ```yaml
    customDNS:
      mapping:
        printer.lan: 192.168.178.3 
        otherdevice.lan: 192.168.178.15,2001:0db8:85a3:08d3:1319:8a2e:0370:7344
    ```

This configuration will also resolve any subdomain of the defined domain. For example a query "printer.lan" or "
my.printer.lan" will return 192.168.178.3 as IP address.

## Conditional DNS resolution

You can define, which DNS resolver(s) should be used for queries for the particular domain (with all sub-domains). This
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
        fritz.box: udp:192.168.178.1
        lan.net: udp:192.170.1.2,udp:192.170.1.3
        # for reverse DNS lookups of local devices
        178.168.192.in-addr.arpa: udp:192.168.178.1
    ```

    In this example, a DNS query "client.fritz.box" will be redirected to the router's DNS server at 192.168.178.1 and client.lan.net to 192.170.1.2 and 192.170.1.3. 
    The query client.example.com will be rewritten to "client.fritz.box" and also redirected to the resolver at 192.168.178.1

In this example, a DNS query "client.fritz.box" will be redirected to the router's DNS server at 192.168.178.1 and
client.lan.net to 192.170.1.2 and 192.170.1.3.

## Client name lookup

Blocky can try to resolve a user-friendly client name from the IP address. This is useful for defining of blocking
groups, since IP address can change dynamically. Blocky uses rDNS to retrieve client's name. To use this feature, you
can configure a DNS server for client lookup (typically your router). You can also define client names manually per IP
address.

### Single name order

Some routers return multiple names for the client (host name and user defined name). With
parameter `clientLookup.singleNameOrder` you can specify, which of retrieved names should be used.

### Custom client name mapping

You can also map a particular client name to one (or more) IP (ipv4/ipv6) addresses. Parameter `clientLookup.clients`
contains a map of client name and multiple IP addresses.

!!! example

    ```yaml
    clientLookup:
        upstream: udp:192.168.178.1
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
External blacklists must be in the well-known [Hosts format](https://en.wikipedia.org/wiki/Hosts_(file)).

Blocky uses [DNS sinkhole](https://en.wikipedia.org/wiki/DNS_sinkhole) approach to block a DNS query. Domain name from
the request, IP address from the response, and the CNAME record will be checked against configured blacklists.

To avoid overblocking, you can define or use already existing whitelists.

### Definition black and whitelists

Each black or whitelist can be either a path to the local file, or a URL to download. All Urls must be grouped to a
group name.

!!! example

    ```yaml
    blocking:
      blackLists:
        ads:
          - https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt
          - https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
        special:
          - https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews/hosts
      whiteLists:
        ads:
          - whitelist.txt
    ```

    In this example you can see 2 groups: **ads** with 2 lists and **special** with one list. One local whitelist was defined for the **ads** group.

!!! warning

    If the same group has black and whitelists, whitelists will be used to disable particular blacklist entries.
    If a group has **only** whitelist entries -> this means only domains from this list are allowed, all other domains will
    be blocked

### Client groups

In this configuration section, you can define, which blocking group(s) should be used for which client in your network.
Example: All clients should use the **ads** group, which blocks advertisement and kids devices should use the **adult**
group, which blocky adult sites.

Clients without a group assignment will use automatically the **default** group.

You can use the client name (see [Client name lookup](#client-name-lookup)), client's IP address or a client subnet as
CIDR notation.

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

| blockType  | Example | Description                                                      |
| ---------- | ------- | ---------------------------------------------------------------- |
| **zeroIP** | zeroIP  | This is the **
default** block type. Server returns 0.0.0.0 (or :: for IPv6) as result for A and AAAA queries |
| **nxDomain** | nxDomain | return NXDOMAIN as return code |
| custom IPs | 192.100.100.15, 2001:0db8:85a3:08d3:1319:8a2e:0370:7344 | comma separated list of destination IP addresses. Should contain ipv4 and ipv6 to cover all query types. Useful with running web server on this address to display the "blocked" page.|

!!! example

    ```yaml
    blocking:
      blockType: nxDomain
    ```

### List refresh period

To keep the list cache up-to-date, blocky will periodically download and reload all external lists. Default period is **
4 hours**. You can configure this by setting the `blocking.refreshPeriod` parameter to a value in **minutes**. Negative
value will deactivate automatically refresh.

!!! example

    ```yaml
    blocking:
      refreshPeriod: 60
    ```

    Refresh every hour.

## Caching

Each DNS response has a TTL (Time-to-live) value. This value defines, how long is the record valid in seconds. The
values are maintained by domain owners, server administrators etc. Blocky caches the answers from all resolved queries
in own cache in order to avoid repeated requests. This reduces the DNS traffic and increases the network speed, since
blocky can serve the result immediately from the cache.

With following parameters you can tune the caching behavior:

!!! warning

    Wrong values can significantly increase external DNS traffic or memory consumption.

| Parameter       | Mandatory | Default value      | Description                                       |
| --------------- | --------- | -------------------| ------------------------------------------------- |
| caching.minTime | no        | 0 (use TTL)        | Amount in minutes, how long a response must be cached (min value). If <=0, use response's TTL, if >0 use this value, if TTL is smaller |
| caching.maxTime | no        | 0 (use TTL)        | Amount in minutes, how long a response must be cached (max value). If <0, do not cache responses. If 0, use TTL. If > 0, use this value, if TTL is greater |
| caching.prefetching     | no        | false              | if true, blocky will preload DNS results for often used queries (names queried more than 5 times in a 2 hour time window). Results in cache will be loaded again on their expire (TTL). This improves the response time for often used queries, but significantly increases external traffic. It is recommended to increase "minTime" to reduce the number of prefetch queries to external resolvers. |

!!! example

    ```yaml
    blocking:
      minTime: 5
      maxTime: 30
      prefetching: true
    ```

## Prometheus

Blocky can expose various metrics for prometheus. To use the prometheus feature, the HTTP listener must be enabled (
see [Basic Configuration](#basic-configuration)).

| Parameter       | Mandatory | Default value      | Description                                       |
| --------------- | --------- | -------------------| ------------------------------------------------- |
| prometheus.enable | no      | false              |  If true, enables prometheus metrics              |
| prometheus.path |   no      | /metrics           |  URL path to the metrics endpoint                 |

!!! example

    ```yaml
    prometheus:
      enable: true
      path: /metrics
    ```

## Query logging

You can enable the logging of DNS queries (question, answer, client, duration etc) to a daily CSV file. This file can be
opened in Excel or OpenOffice writer for analyse purposes.

!!! warning

    Query file contain sensitive information. Please ensure to inform users, if you log their queries.

Configuration parameters:

| Parameter          | Mandatory | Default value      | Description                                       |
| ---------------    | --------- | -------------------| ------------------------------------------------- |
| queryLog.dir       | no        |                    |  If defined, directory for writing the logs       |
| queryLog.perClient |   no      | false              |  if true, write one file per client. Writes all queries to single file otherwise                |
| queryLog.logRetentionDays|   no      | 0            |  if > 0, deletes log files which are older than ... days             |

!!! hint

    Please ensure, that the log directory is writable. If you use docker, please ensure, that the directory is properly
    mounted (e.g. volume)

!!! example

    ```yaml
    queryLog:
        dir: /logs
        perClient: true
        logRetentionDays: 7
    ```

## HTTPS configuration (for DoH)

See [Wiki - Configuration of HTTPS](https://github.com/0xERR0R/blocky/wiki/Configuration-of-HTTPS-for-DoH-and-Rest-API)
for detailed information, how to configure HTTPS.

DoH url: `https://host:port/dns-query`

--8<-- "docs/includes/abbreviations.md"
