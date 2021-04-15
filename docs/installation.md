# Installation

You can choose one of the following installation options:

* Run as standalone binary
* Run as docker container
* Kubernetes with helm chart

## Prepare your configuration

Blocky uses one YAML file as configuration. Create new `config.yaml` with your configuration (
see [Configuration](configuration.md) for more details and all configuration options).

Simple configuration file, which enables only basic features:

```yaml
upstream:
  externalResolvers:
    - 46.182.19.48
    - 80.241.218.68
    - tcp-tls:fdns1.dismail.de:853
    - https://dns.digitale-gesellschaft.ch/dns-query
blocking:
  blackLists:
    ads:
      - https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
  clientGroupsBlock:
    default:
      - ads
port: 53
httpPort: 4000
```

## Run as standalone binary

Download the binary file from [GitHub](https://github.com/0xERR0R/blocky/releases) for your architecture and
run `./blocky --config config.yml`.

!!! warning

    Please be aware, if you want to use port 53 or 953 on Linux you should add CAP_NET_BIND_SERVICE capability
    to the binary or run with root privileges (running as root is not recommended).

## Run with docker

### Alternative registry

Blocky docker images are deployed to DockerHub (`spx01/blocky`) and GitHub Container Registry (`ghcr.io/0xerr0r/blocky`)
.

### Docker from command line

Execute following command from the command line:

```    
docker run --name blocky -v /path/to/config.yml:/app/config.yml -p 4000:4000 -p 53:53/udp spx01/blocky
```

### Run with docker-compose

Create following `docker-compose.yml` file

```yaml
version: "2.1"
services:
  blocky:
    image: spx01/blocky
    container_name: blocky
    restart: unless-stopped
    ports:
      - "53:53/tcp"
      - "53:53/udp"
      - "4000:4000/tcp"
    environment:
      - TZ=Europe/Berlin # Optional to synchronize the log timestamp with host
    volumes:
      # config file
      - ./config.yml:/app/config.yml
```

and start docker container with

```
docker-compose up -d
```

### Advanced setup

Following example shows, how to run blocky in a docker container and store query logs on a SAMBA share. Local black and
whitelists directories are mounted as volume. You can create own black or whitelists in these directories and define the
path like '/app/whitelists/whitelist.txt' in the config file.

!!! example

```yaml
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
      # write query logs in this volume
      - queryLogs:/logs
      # put your custom white and blacklists in these directories
      - ./blacklists:/app/blacklists/
      - ./whitelists:/app/whitelists/

volumes:
  queryLogs:
    driver: local
    driver_opts:
      type: cifs
      o: username=USER,password=PASSWORD,rw
      device: //NAS_HOSTNAME/blocky  
```

## Run with helm chart on Kubernetes

See [this repo](https://github.com/k8s-at-home/charts/tree/master/charts/stable/blocky)
or [artifacthub](https://hub.helm.sh/charts/k8s-at-home/blocky) for details about running blocky via helm in kubernetes.

--8<-- "docs/includes/abbreviations.md"
