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
    INFO server: -> resolver: 'StatsResolver'
    INFO server:      stats:
    INFO server:       - Top 20 queries
    INFO server:       - Top 20 blocked queries
    INFO server:       - Query count per client
    INFO server:       - Reason
    INFO server:       - Query type
    INFO server:       - Response type
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

## Statistics

blocky collects statistics and aggregates them hourly. If signal `SIGUSR2` is received, this will print statistics for
last 24 hours:

* Top 20 queried domains
* Top 20 blocked domains
* Query count per client ...

!!! summary

    Example output:

    ```
    INFO stats_resolver: ******* STATS 24h *******
    INFO stats_resolver: ┌───────────────────────────────────────────────────────────┐
    INFO stats_resolver: │ Top 20 queries                                            │
    INFO stats_resolver: ├────────────────────────────────────────────────────┬──────┤
    INFO stats_resolver: │                                      123.fritz.box │ 5760 │
    INFO stats_resolver: │                               checkip.12344567.com │ 1431 │
    INFO stats_resolver: │                                     wpad.fritz.box │  379 │
    INFO stats_resolver: │                          raw.githubusercontent.com │  299 │
    INFO stats_resolver: │                                        grafana.com │  288 │
    INFO stats_resolver: │                                     www.google.com │  224 │
    INFO stats_resolver: │                                    www.youtube.com │  193 │
    INFO stats_resolver: │                                 www.googleapis.com │  169 │
    INFO stats_resolver: │                                          fritz.box │  156 │
    INFO stats_resolver: │                     incoming.telemetry.mozilla.org │  148 │
    INFO stats_resolver: │                             android.googleapis.com │  114 │
    INFO stats_resolver: │                        userlocation.googleapis.com │  101 │
    INFO stats_resolver: │                                play.googleapis.com │  100 │
    INFO stats_resolver: │                        safebrowsing.googleapis.com │   97 │
    INFO stats_resolver: │                            api-mifitsdfsdfsdfi.com │   84 │
    INFO stats_resolver: │                      connectivitycheck.gstatic.com │   75 │
    INFO stats_resolver: │                                  fonts.gstatic.com │   66 │
    INFO stats_resolver: │                                        i.ytimg.com │   62 │
    INFO stats_resolver: │                         android.clients.google.com │   55 │
    INFO stats_resolver: │                                    play.google.com │   50 │
    INFO stats_resolver: └────────────────────────────────────────────────────┴──────┘
    INFO stats_resolver: ┌──────────────────────────────────────────────────────────┐
    INFO stats_resolver: │ Top 20 blocked queries                                   │
    INFO stats_resolver: ├────────────────────────────────────────────────────┬─────┤
    INFO stats_resolver: │                     incoming.telemetry.mozilla.org │ 148 │
    INFO stats_resolver: │                        googleads.g.doubleclick.net │  47 │
    INFO stats_resolver: │                        data.mistat.intl.xiaomi.com │  29 │
    INFO stats_resolver: │                           ssl.google-analytics.com │  25 │
    INFO stats_resolver: │                                app-measurement.com │  25 │
    INFO stats_resolver: │                           www.googletagmanager.com │  24 │
    INFO stats_resolver: │                           www.googleadservices.com │  23 │
    INFO stats_resolver: │                          privatestats.whatsapp.net │  22 │
    INFO stats_resolver: │                        find.api.micloud.xiaomi.net │  21 │
    INFO stats_resolver: │                       sdkconfig.ad.intl.xiaomi.com │  18 │
    INFO stats_resolver: │                               sessionssdfsdfasdfam │  16 │
    INFO stats_resolver: │                      pagead2.googlesyndication.com │  16 │
    INFO stats_resolver: │                  firebase-settings.crashlytics.com │  16 │
    INFO stats_resolver: │                          abroad.apilocate.amap.com │  16 │
    INFO stats_resolver: │                           www.google-analytics.com │  15 │
    INFO stats_resolver: │                             tracking.intl.miui.com │  15 │
    INFO stats_resolver: │                     resolver.asdfsadfsdfsdfsdfsdfd │  14 │
    INFO stats_resolver: │                                       adfgdfgsfgdg │  14 │
    INFO stats_resolver: │                               adservice.google.com │  14 │
    INFO stats_resolver: │                                 www.tns-cdfgffgdfg │  12 │
    INFO stats_resolver: └────────────────────────────────────────────────────┴─────┘
    INFO stats_resolver: ┌───────────────────────────────────────────────────────────┐
    INFO stats_resolver: │ Query count per client                                    │
    INFO stats_resolver: ├────────────────────────────────────────────────────┬──────┤
    INFO stats_resolver: │                                      sdf.fritz.box │ 6338 │
    INFO stats_resolver: │                               dfdgsfgsfg.fritz.box │ 2075 │
    INFO stats_resolver: │                                       df.fritz.box │ 1484 │
    INFO stats_resolver: │                                 sdfgsdfg.fritz.box │ 1129 │
    INFO stats_resolver: │                                Android-3.fritz.box │ 1007 │
    INFO stats_resolver: │                           dfgsdfgsdfgsdf.fritz.box │  956 │
    INFO stats_resolver: │                                         172.20.0.2 │  833 │
    INFO stats_resolver: │                     345345354353453iNote.fritz.box │  393 │
    INFO stats_resolver: │                             R334534545-D.fritz.box │  359 │
    INFO stats_resolver: │                                Android-2.fritz.box │  347 │
    INFO stats_resolver: │                                  Android.fritz.box │  317 │
    INFO stats_resolver: │                               wererrw-TV.fritz.box │  244 │
    INFO stats_resolver: │                        dfsdf-dfsddsdfsdf.fritz.box │   77 │
    INFO stats_resolver: │                                    sdfdf.fritz.box │   18 │
    INFO stats_resolver: │                                sdfsdffsd.fritz.box │   10 │
    INFO stats_resolver: │                 android-936072d2983c456a.fritz.box │    8 │
    INFO stats_resolver: └────────────────────────────────────────────────────┴──────┘
    INFO stats_resolver: ┌───────────────────────────────────────────────────────────┐
    INFO stats_resolver: │ Reason                                                    │
    INFO stats_resolver: ├────────────────────────────────────────────────────┬──────┤
    INFO stats_resolver: │                                        CONDITIONAL │ 6518 │
    INFO stats_resolver: │                                             CACHED │ 5431 │
    INFO stats_resolver: │                                      BLOCKED (ads) │ 1104 │
    INFO stats_resolver: │                              RESOLVED (1.1.1.1:53) │  928 │
    INFO stats_resolver: │                              RESOLVED (9.9.9.9:53) │  630 │
    INFO stats_resolver: │                        RESOLVED (80.241.218.68:53) │  374 │
    INFO stats_resolver: │                         RESOLVED (89.233.43.71:53) │  277 │
    INFO stats_resolver: │                         RESOLVED (46.182.19.48:53) │  177 │
    INFO stats_resolver: │                       RESOLVED (91.239.100.100:53) │   77 │
    INFO stats_resolver: │                                         CUSTOM DNS │   39 │
    INFO stats_resolver: │                                     BLOCKED (kids) │   14 │
    INFO stats_resolver: │                                   BLOCKED IP (ads) │    9 │
    INFO stats_resolver: │                                    CACHED NEGATIVE │    8 │
    INFO stats_resolver: │                                BLOCKED CNAME (ads) │    7 │
    INFO stats_resolver: └────────────────────────────────────────────────────┴──────┘
    INFO stats_resolver: ┌───────────────────────────────────────────────────────────┐
    INFO stats_resolver: │ Query type                                                │
    INFO stats_resolver: ├────────────────────────────────────────────────────┬──────┤
    INFO stats_resolver: │                                                  A │ 8206 │
    INFO stats_resolver: │                                               AAAA │ 7330 │
    INFO stats_resolver: │                                                SRV │   44 │
    INFO stats_resolver: │                                              NAPTR │   15 │
    INFO stats_resolver: └────────────────────────────────────────────────────┴──────┘
    INFO stats_resolver: ┌────────────────────────────────────────────────────────────┐
    INFO stats_resolver: │ Response type                                              │
    INFO stats_resolver: ├────────────────────────────────────────────────────┬───────┤
    INFO stats_resolver: │                                            NOERROR │ 15368 │
    INFO stats_resolver: │                                           NXDOMAIN │   222 │
    INFO stats_resolver: │                                           SERVFAIL │     5 │
    INFO stats_resolver: └────────────────────────────────────────────────────┴───────┘
    
    ```

!!! hint

    To send a signal to a process you can use `kill -s USR2 <PID>` or `docker kill -s SIGUSR2 blocky` for docker setup

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

--8<-- "docs/includes/abbreviations.md"
