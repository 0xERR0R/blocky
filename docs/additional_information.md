# Additional information

## Print current configuration

To print runtime configuration / statistics, you can send `SIGUSR1` signal to running process.

!!! summary

    Example output:

    ```
    INFO server: current configuration:
    INFO server: -> resolver: 'ClientNamesResolver'
    INFO server:      singleNameOrder = "[2 1]"
    INFO server:      externalResolver = "upstream 'tcp+udp:192.168.178.1:53'"
    INFO server:      cache item count = 7
    INFO server: -> resolver: 'QueryLoggingResolver'
    INFO server:      logDir= "/logs"
    INFO server:      perClient = false
    INFO server:      logRetentionDays= 7
    INFO server: -> resolver: 'MetricsResolver'
    INFO server:      metrics:
    INFO server:        Enable = true
    INFO server:        Path   = /metrics
    INFO server: -> resolver: 'ConditionalUpstreamResolver'
    INFO server:      fritz.box = "parallel upstreams 'upstream 'tcp+udp:192.168.178.1:53''"
    INFO server: -> resolver: 'CustomDNSResolver'
    INFO server: runtime information:
    ...
    INFO server: MEM Alloc =                 9 MB
    INFO server: MEM HeapAlloc =             9 MB
    INFO server: MEM Sys =                  88 MB
    INFO server: MEM NumGC =              1533
    INFO server: RUN NumCPU =                4
    INFO server: RUN NumGoroutine =         18
    
    ```

!!! hint

    To send a signal to a process you can use `kill -s USR1 <PID>` or `docker kill -s SIGUSR1 blocky` for docker setup

## Debug / Profiling

If http listener is enabled, [pprof](https://golang.org/pkg/net/http/pprof/) endpoint (`/debug/pprof`) is enabled
automatically.

## List sources

Some links/ideas for lists:

### Blacklists

* [https://github.com/StevenBlack/hosts](https://github.com/StevenBlack/hosts)
* [https://github.com/nickspaargaren/no-google](https://github.com/nickspaargaren/no-google)
* [https://energized.pro/](https://energized.pro/)
* [https://github.com/Perflyst/PiHoleBlocklist](https://github.com/Perflyst/PiHoleBlocklist)
* [https://github.com/kboghdady/youTube_ads_4_pi-hole](https://github.com/kboghdady/youTube_ads_4_pi-hole)
* [https://github.com/chadmayfield/my-pihole-blocklists](https://github.com/chadmayfield/my-pihole-blocklists)

!!! warning

    Use only blacklists from the sources you trust!

### Whitelists

* [https://github.com/anudeepND/whitelist](https://github.com/anudeepND/whitelist)

## List of public DNS servers

!!! warning

    DNS server provider has access to all your DNS queries (all visited domain names). Some DNS providers can use (tracking, analyzing, profiling etc.). It is recommended to use different DNS upstream servers in blocky to distribute your DNS queries over multiple providers.

    Please read the description before using the DNS server as upstream. Some of them provide already an ad-blocker, some
    filters other content. If you use external DNS server with included ad-blocker, you can't choose which domains should be
    blocked, and you can't use whitelisting.

This is only a small excerpt of all free available DNS servers and should only be understood as an idee.

!!! info

    I will **NOT** rate the DNS providers in the list. This list is sorted alphabetically.

* [AdGuard](https://adguard.com/en/adguard-dns/setup.html)
* [CloudFlare](https://1.1.1.1/)
* [Comodo](https://www.comodo.com/secure-dns/)
* [DigitalCourage](https://digitalcourage.de/support/zensurfreier-dns-server)
* [DigitaleGesellschaft](https://www.digitale-gesellschaft.ch/dns/)
* [Dismail](https://dismail.de/info.html#dns)
* [dnsforge](https://dnsforge.de/)
* [Google](https://developers.google.com/speed/public-dns)
* [OpenDNS](https://www.opendns.com/setupguide/#familyshield)
* [Quad9](https://www.quad9.net/)
* [UncensoredDNS](https://blog.uncensoreddns.org/dns-servers/)

## Project links

### Code repository

Main: [:material-github:GitHub](https://github.com/0xERR0R/blocky)

Mirror: [:simple-codeberg:Codeberg](https://codeberg.org/0xERR0R/blocky)

### Container Registry

Main: [:material-docker:Docker Hub](https://hub.docker.com/r/spx01/blocky)

Mirror: [:material-github:GitHub Container Registry](https://ghcr.io/0xerr0r/blocky)

--8<-- "docs/includes/abbreviations.md"
