#!/bin/bash
# Install blocky to CentOS (x86_64)

# Envs
# ---------------------------------------------------\
PATH=$PATH:/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin
SCRIPT_PATH=$(cd `dirname "${BASH_SOURCE[0]}"` && pwd)

# Vars
# ---------------------------------------------------\
_APP_FOLDER_NAME="blocky2"
_APP_USER_NAME="user2"
_DESTINATION=/opt/${_APP_FOLDER_NAME}
_BINARY=`curl -s https://api.github.com/repos/0xERR0R/blocky/releases/latest | grep browser_download_url | grep "Linux_x86_64" | awk '{print $2}' | tr -d '\"'`

# Functions
# ---------------------------------------------------\

# Check destination folder
if [[ ! -d $_DESTINATION ]]; then
	mkdir -p $_DESTINATION/logs
else
  echo "Folder exist! Exit.."
  exit 1
fi

# Download latest blocky release from official repo
download_blocky() {
	cd $_DESTINATION
	wget "$_BINARY"
	tar xvf `ls ls *.tar.gz`
}

# Create simple user for blocky
create_APP_USER_NAME() {
	useradd $_APP_USER_NAME
	chown -R $_APP_USER_NAME:$_APP_USER_NAME $_DESTINATION
	setcap cap_net_bind_service=ep $_DESTINATION/blocky
}

# Create basic blocky config
create_blocky_config() {
# Config
# https://github.com/0xERR0R/blocky/blob/development/docs/installation.md
cat > $_DESTINATION/config.yml <<_EOF_
upstream:
  default:
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
_EOF_
}

# Create systemd unit
create_systemd_config() {
# Systemd unit
cat > /etc/systemd/system/$_APP_FOLDER_NAME.service <<_EOF_
[Unit]
Description=Blocky is a DNS proxy and ad-blocker
ConditionPathExists=${_DESTINATION}
After=local-fs.target

[Service]
user=${_APP_USER_NAME}
group=${_APP_USER_NAME}
Type=simple
WorkingDirectory=${_DESTINATION}
ExecStart=${_DESTINATION}/blocky --config ${_DESTINATION}/config.yml
Restart=on-failure
RestartSec=10

StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=blocky

[Install]
WantedBy=multi-user.target
_EOF_

systemctl daemon-reload
systemctl enable --now $_APP_FOLDER_NAME
}

# Install blocky
# ---------------------------------------------------\
download_blocky
create_blocky_config
create_APP_USER_NAME
create_systemd_config

