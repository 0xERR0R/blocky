# Client Group Endpoints

Blockasaurus can identify which client group a DNS query belongs to using
hostnames, URL paths, or EDNS options — similar to how NextDNS assigns
per-profile hostnames. This lets you give each client group its own DNS
endpoint without relying solely on source IP matching.

## How It Works

Each client group gets a **slug** — a DNS-safe identifier derived from the
group name. For example, a group named "Kids Devices" gets the slug
`kids-devices`. This slug is used across all identification methods:

| Protocol | Identification method | Example |
|----------|----------------------|---------|
| Plain DNS (UDP/TCP) | EDNS CPE-ID (dnsmasq `add-cpe-id=`) | `add-cpe-id=kids-devices` |
| Plain DNS (UDP/TCP) | Source IP / CIDR | Existing behavior |
| DoH (HTTPS) | URL path | `https://dns.example.com/dns-query/kids-devices` |
| DoH (HTTPS) | Subdomain | `https://kids-devices.dns.example.com/dns-query` |
| DoT (TLS, port 853) | TLS SNI | `kids-devices.dns.example.com` |
| DoQ (QUIC, port 853) | TLS SNI | `kids-devices.dns.example.com` |

**Resolution priority** (first match wins):

1. DoH URL path parameter (`/dns-query/{slug}`)
2. Subdomain from HTTP Host header or TLS SNI
3. EDNS CPE-ID option
4. Source IP / reverse DNS name (existing behavior)

## Configuration

```yaml
clientGroupEndpoints:
  # Base domains for subdomain-based identification.
  # {slug}.{domain} in TLS SNI or HTTP Host extracts the slug.
  domains:
    - dns.example.com
    - blockasaurus.local

  # Enable EDNS CPE-ID extraction (option code 65074) for plain DNS.
  # Used by dnsmasq's add-cpe-id= directive.
  cpeId: true     # default: true

  # Auto-create DNS records so clients can resolve *.{domain} to this server.
  # "auto" detects the IP (k8s LB service or outbound interface), or set an
  # explicit IP. Omit or leave empty to disable.
  advertiseAddress: auto
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `clientGroupEndpoints.domains` | list of strings | `[]` | Base domains for subdomain extraction |
| `clientGroupEndpoints.cpeId` | bool | `true` | Enable EDNS CPE-ID (option 65074) extraction |
| `clientGroupEndpoints.advertiseAddress` | string | `""` | Auto-create DNS records for configured domains. `auto`, explicit IP, or empty to disable |
| `ports.adminPort` | string/int | `""` | Admin port (HTTP). When set, `http`/`https` serve DoH only; UI/API/metrics move here |
| `ports.adminPortTLS` | string/int | `""` | Admin port (HTTPS). Same as `adminPort` but with TLS |

### Auto-Advertise DNS Records

When `advertiseAddress` is set, blockasaurus automatically creates `A` (or `AAAA`)
records for each configured domain and its wildcard (`*.domain`), pointing to the
detected or specified IP. This eliminates the need to manually add `customDNS.mapping`
entries or external DNS records for subdomain-based client group identification.

**Detection order for `auto`:**

1. **Kubernetes**: Queries the k8s API for a LoadBalancer Service with port 53 in the
   pod's namespace. Requires the service account to have `get`/`list` on Services
   (the Helm chart creates this RBAC automatically).
2. **Bare metal**: Opens a UDP socket to detect the primary outbound interface IP.
3. **Failure**: Logs a warning and skips record injection.

User-defined `customDNS.mapping` entries for the same domain always take precedence —
auto-advertised records are skipped for domains that already have explicit entries.

!!! note
    The IP is detected once at startup. If the IP changes (e.g., DHCP renewal),
    a restart is required. In Kubernetes, LoadBalancer IPs are typically stable.

## Setup Scenarios

### Scenario 1: Homelab — No TLS

The simplest setup. Clients are identified by source IP, EDNS CPE-ID, or
DoH URL path. No TLS certificates or custom domain required.

```yaml
clientGroupEndpoints:
  cpeId: true

ports:
  dns: 53
  http: 80
```

**Client examples:**

- **Any device (DHCP):** Set DNS server to blockasaurus IP (e.g., 192.168.1.5).
  The device's source IP is matched against client groups.
- **Subnet of IoT devices:** Add CIDR `192.168.1.0/28` to a client group.
- **dnsmasq forwarder:** Forward to blockasaurus and identify with CPE-ID:
  ```
  server=192.168.1.5
  add-cpe-id=kids-devices
  ```
- **Browser/OS DoH:** Configure DoH URL:
  `http://192.168.1.5/dns-query/kids-devices`

!!! note
    Android Private DNS and other DoT-only clients are not available without
    TLS. Use Scenario 2 or 3 for those.

---

### Scenario 2: Homelab with Self-Signed Wildcard Cert (.local)

Adds subdomain-based DoH and DoT. With `advertiseAddress`, blockasaurus
automatically creates DNS records for `*.blockasaurus.local` — no manual
`customDNS.mapping` needed.

```yaml
clientGroupEndpoints:
  domains:
    - blockasaurus.local
  advertiseAddress: auto   # or explicit IP like 192.168.1.5
  cpeId: true

ports:
  dns: 53
  http: 80
  https: 443
  tls: 853

certFile: /certs/tls.crt
keyFile: /certs/tls.key
```

**Helm service values** — expose all ports on the LoadBalancer:

```yaml
service:
  dns:
    enabled: true
    type: LoadBalancer
    port: 53
    dot: true
    http: true
    https: true
```

**Generate the self-signed wildcard cert:**

```bash
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -days 3650 -nodes \
  -keyout tls.key -out tls.crt \
  -subj '/CN=blockasaurus.local' \
  -addext 'subjectAltName=DNS:blockasaurus.local,DNS:*.blockasaurus.local'
```

**Client examples** (in addition to Scenario 1):

- **Browser DoH (subdomain):**
  `https://kids-devices.blockasaurus.local/dns-query`
- **DoT per-group:**
  `kids-devices.blockasaurus.local` port 853
- **Android Private DNS:**
  `kids-devices.blockasaurus.local` (device must trust the self-signed cert)

!!! important "How .local subdomain resolution works"
    mDNS (multicast DNS) does **not** support wildcard names. The subdomain
    `kids-devices.blockasaurus.local` is resolved by blockasaurus's own DNS
    via the `customDNS` wildcard entry — not by mDNS. This means clients
    must already be using blockasaurus as their DNS server (port 53) before
    subdomain-based DoH/DoT will work. This is a natural bootstrap
    dependency — your DHCP server hands out blockasaurus's IP as the DNS
    server first.

!!! tip "Distributing the self-signed cert"
    Each client must trust the self-signed certificate:

    - **Android:** Install as user CA in Settings → Security → Encryption
    - **iOS/macOS:** Install and trust via a configuration profile
    - **Linux:** Copy to `/usr/local/share/ca-certificates/` and run `update-ca-certificates`
    - **Windows:** Import into the Trusted Root Certification Authorities store

---

### Scenario 3: Custom Domain with Wildcard Cert

Full production setup with a real domain and automated wildcard cert from
Let's Encrypt. All identification methods are available. A single
LoadBalancer IP serves DNS, DoT, DoH, and the web UI.

```yaml
clientGroupEndpoints:
  domains:
    - dns.example.com
  advertiseAddress: auto
  cpeId: true

ports:
  dns: 53
  http: 80
  https: 443
  tls: 853

certFile: /certs/tls.crt
keyFile: /certs/tls.key
```

**Helm service values** — expose all protocols on one LoadBalancer:

```yaml
service:
  dns:
    enabled: true
    type: LoadBalancer
    externalTrafficPolicy: Local   # preserves client source IPs
    port: 53
    dot: true      # DoT on 853/TCP
    http: true     # Web UI + DoH on 80/TCP
    https: true    # Web UI + DoH on 443/TCP
```

With `advertiseAddress: auto`, blockasaurus detects the LoadBalancer's
external IP and creates DNS records for `dns.example.com` and
`*.dns.example.com` automatically. No external DNS records or ingress
needed — clients resolve the domain through blockasaurus itself.

**TLS cert** — the certificate must include **both** the base domain and
the wildcard as SANs:

=== "cert-manager (Helm chart)"

    The Helm chart can create a cert-manager `Certificate` resource for you.
    In your `values.yaml`:

    ```yaml
    certificate:
      enabled: true
      issuerRef:
        name: letsencrypt-dns01-cloudflare
        kind: ClusterIssuer
      dnsNames:
        - dns.example.com          # base domain — required for https://dns.example.com
        - "*.dns.example.com"      # wildcard — covers per-group subdomains

    tls:
      enabled: true
      secretName: my-release-blockasaurus-tls  # matches certificate.secretName default
    ```

    This requires [cert-manager](https://cert-manager.io/) and a `ClusterIssuer`
    (or `Issuer`) already configured in your cluster. The certificate is created
    and renewed automatically alongside the blockasaurus release.

    !!! warning "Include the base domain in dnsNames"
        A wildcard cert (`*.dns.example.com`) does **not** cover the bare
        domain (`dns.example.com`). You must list both in `dnsNames` or
        HTTPS connections to the base domain will fail with a certificate
        error.

    See the full set of `certificate.*` options in the chart's
    [`values.yaml`](https://github.com/chrissnell/blockasaurus/blob/main/packaging/helm/blockasaurus/values.yaml).

=== "certbot (manual)"

    ```bash
    certbot certonly --dns-cloudflare \
      -d 'dns.example.com' \
      -d '*.dns.example.com'
    ```

    Then create the Kubernetes secret and reference it in `tls.secretName`:

    ```bash
    kubectl create secret tls blockasaurus-tls \
      --cert=/etc/letsencrypt/live/dns.example.com/fullchain.pem \
      --key=/etc/letsencrypt/live/dns.example.com/privkey.pem
    ```

**Client examples** (all methods):

| Device / Software | Configuration | Method |
|---|---|---|
| Any device (DHCP) | DNS server: `<LB IP>` | Source IP |
| dnsmasq forwarder | `server=<LB IP>` / `add-cpe-id=kids-devices` | EDNS CPE-ID |
| Browser DoH (path) | `https://dns.example.com/dns-query/kids-devices` | URL path |
| Browser DoH (subdomain) | `https://kids-devices.dns.example.com/dns-query` | Subdomain |
| Web UI | `https://dns.example.com` | HTTPS |
| Android Private DNS | `kids-devices.dns.example.com` | DoT via SNI |
| iOS/macOS profile | `https://kids-devices.dns.example.com/dns-query` | DoH via subdomain |
| DoQ client | `quic://kids-devices.dns.example.com:853` | DoQ via SNI |
| Stubby (DoT) | Server: `kids-devices.dns.example.com`, port 853 | DoT via SNI |

This is the recommended setup for homelabs with a domain name. Let's Encrypt
wildcard certs are free and auto-renewable, and all clients work without
manual certificate trust.

---

### Scenario 4: External DoH with Admin Port

For deployments where DoH is exposed to the internet but the admin UI
should remain internal, use the **admin port** feature to separate them
onto different ports.

When `adminPort` (or `adminPortTLS`) is set in the `ports` config, the main
`http`/`https` ports serve **only** the `/dns-query` endpoint. Everything
else — the web UI, REST API, Prometheus metrics, debug profiler, and
websocket log stream — moves to the admin port. When omitted (the
default), all endpoints share the same port as in Scenarios 1-3.

**Blockasaurus config** (under `config:` in Helm values, or standalone):

```yaml
ports:
  dns: 53
  http: 80          # DoH queries only (internet-facing)
  https: 443        # DoH queries only (internet-facing, TLS)
  tls: 853
  adminPort: 8080       # Web UI, API, metrics (internal only)

certFile: /certs/tls.crt
keyFile: /certs/tls.key
```

**Helm service values** — DoH on the LoadBalancer, UI on a ClusterIP:

```yaml
service:
  dns:
    enabled: true
    type: LoadBalancer
    externalTrafficPolicy: Local
    port: 53
    dot: true       # DoT on 853/TCP
    http: true      # DoH on 80/TCP (no UI — on admin port)
    https: true     # DoH on 443/TCP (no UI — on admin port)
  adminPort:
    enabled: true   # Web UI on a separate internal service
    type: ClusterIP
    port: 8080
```

The admin service is only reachable within the cluster (or via
`kubectl port-forward`). The DoH endpoint remains on the LoadBalancer,
exposed to DNS clients.

**What moves to the admin port:**

| Endpoint | Admin port | Main http/https port |
|----------|:---:|:---:|
| `/dns-query` (DoH) | — | ✓ |
| Web UI (`/`, `/ui/`) | ✓ | — |
| REST API (`/api/*`) | ✓ | — |
| Prometheus metrics (`/metrics`) | ✓ | — |
| WebSocket log stream (`/api/ws/logs`) | ✓ | — |
| OpenAPI docs (`/docs/`) | ✓ | — |

!!! note "Prometheus scraping"
    When the admin port is active, the `/metrics` endpoint moves to the admin
    port. Update `prometheus.io/port` in your pod annotations to match
    (e.g., `"8080"` instead of `"80"`).

!!! tip "Accessing the UI"
    With the admin port on a ClusterIP, access the web UI via:

    - `kubectl port-forward svc/blockasaurus-admin 8080:8080`
    - Or configure an internal ingress / VPN route to the ClusterIP

**Admin port with TLS on both sides:**

If you want TLS on the admin port as well (e.g., for internal compliance),
use `adminPortTLS` instead of `adminPort`:

```yaml
ports:
  https: 443           # DoH over TLS
  adminPortTLS: 8443       # UI over TLS
```

Both listeners share the same TLS certificate from `certFile`/`keyFile`.

## Slug Generation

Client group names are automatically converted to DNS-safe slugs:

| Group Name | Slug |
|------------|------|
| Kids Devices | `kids-devices` |
| IoT_Network | `iot-network` |
| Guest WiFi 2.4 | `guest-wifi-2-4` |

Rules: lowercase, spaces/underscores/dots become hyphens, non-alphanumeric
characters are stripped, max 63 characters (DNS label limit). Each slug must
be unique across all client groups.

The slug is shown alongside the group name in the web UI and is the value
used for DoH paths, subdomain hostnames, and CPE-ID strings.

## Apple Configuration Profiles (.mobileconfig)

Blockasaurus can generate Apple `.mobileconfig` profiles for iOS and macOS
devices directly from the web UI. Each profile is preconfigured for the
selected client group and the server's endpoint configuration.

### How It Works

Navigate to a client group in the web UI, open the **iOS** or **macOS** tab
in the Setup Guide, and click **Download Configuration Profile**. The
downloaded `.mobileconfig` file configures the device's system-wide DNS
settings so all apps use blockasaurus.

The profile's DNS protocol is chosen automatically based on your server
configuration:

| Server Configuration | Profile Protocol | DNS Identifier |
|---|---|---|
| HTTPS ports + domains configured | DoH | `https://{slug}.{domain}{dohPath}` |
| TLS ports + domains (no HTTPS) | DoT | `{slug}.{domain}` |
| No encrypted DNS | Cleartext | Server IP from `advertiseAddress` |

### Deterministic UUIDs

Profiles use UUID v5 (SHA-1 based, deterministic) so that reinstalling a
profile for the same client group **replaces** the existing profile rather
than creating a duplicate. The UUIDs are derived from the client group slug.

### Reviewing Profiles Before Installing

We highly recommend reviewing any configuration profile before installing it
on your device. The free
[iMazing Profile Editor](https://imazing.com/profile-editor) can open
`.mobileconfig` files and show you exactly what the profile changes on your
system. This is good security practice for any profile, whether generated by
blockasaurus or downloaded from elsewhere.

### Optional CA Certificate Embedding

If your server uses a self-signed certificate (common in homelab setups),
the web UI shows an **Include CA certificate in profile** checkbox. When
checked, the profile includes a `com.apple.security.root` payload containing
the trust anchor certificate extracted from the configured `certFile`.

This checkbox only appears when blockasaurus detects a self-signed root in
the certificate chain. Users with publicly-trusted certificates (e.g.,
Let's Encrypt) will not see it.

!!! important "Manual trust step required"
    Even with the certificate embedded in the profile, Apple requires the
    user to manually enable trust after installing:

    - **iOS**: Settings → General → About → Certificate Trust Settings →
      enable the Blockasaurus CA
    - **macOS**: Open Keychain Access, find the Blockasaurus CA cert, and
      set it to Always Trust

    Only MDM-deployed profiles receive automatic trust.

### API Endpoint

The profile is served at:

```
GET /api/mobileconfig/{slug}
GET /api/mobileconfig/{slug}?includeCert=1
```

| Parameter | Description |
|---|---|
| `{slug}` | Client group slug (from the URL path) |
| `includeCert=1` | Optional query parameter to embed the CA certificate |

Response headers:

- `Content-Type: application/x-apple-aspen-config`
- `Content-Disposition: attachment; filename="blockasaurus-{slug}.mobileconfig"`
