#!/bin/bash
# Install blocky to CentOS (x86_64)

set -e

# Envs
# ---------------------------------------------------\
PATH=$PATH:/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin
SCRIPT_PATH=$(cd `dirname "${BASH_SOURCE[0]}"` && pwd)

# Vars
# ---------------------------------------------------\
_APP_NAME="blocky"
_APP_USER_NAME="blockyusr"
_DESTINATION=/opt/${_APP_NAME}
_BINARY=`curl -s https://api.github.com/repos/0xERR0R/blocky/releases/latest | grep browser_download_url | grep "Linux_x86_64" | awk '{print $2}' | tr -d '\"'`

SERVER_IP=$(hostname -I | cut -d' ' -f1)
SERVER_NAME=$(hostname)
# Output messages
# ---------------------------------------------------\

# And colors
RED='\033[0;91m'
GREEN='\033[0;92m'
CYAN='\033[0;96m'
YELLOW='\033[0;93m'
PURPLE='\033[0;95m'
BLUE='\033[0;94m'
BOLD='\033[1m'
WHiTE="\e[1;37m"
NC='\033[0m'

ON_SUCCESS="DONE"
ON_FAIL="FAIL"
ON_ERROR="Oops"
ON_CHECK="✓"

Info() {
  echo -en "${1} ${GREEN}${2}${NC}\n"
}

Warn() {
  echo -en "${1} ${PURPLE}${2}${NC}\n"
}

Success() {
  echo -en "${1} ${GREEN}${2}${NC}\n"
}

Error () {
  echo -en "${1} ${RED}${2}${NC}\n"
}

Splash() {
  echo -en "${WHiTE} ${1}${NC}\n"
}

space() { 
  echo -e ""
}


# Functions
# ---------------------------------------------------\

# Yes / No confirmation
confirm() {
    # call with a prompt string or use a default
    read -r -p "${1:-Are you sure? [y/N]} " response
    case "$response" in
        [yY][eE][sS]|[yY]) 
            true
            ;;
        *)
            false
            ;;
    esac
}

# Check is current user is root
isRoot() {
  if [ $(id -u) -ne 0 ]; then
    Error $ON_ERROR "You must be root user to continue"
    exit 1
  fi
  RID=$(id -u root 2>/dev/null)
  if [ $? -ne 0 ]; then
    Error "User root no found. You should create it to continue"
    exit 1
  fi
  if [ $RID -ne 0 ]; then
    Error "User root UID not equals 0. User root must have UID 0"
    exit 1
  fi
}

# Checks supporting distros
checkDistro() {
  # Checking distro
  if [ -e /etc/centos-release ]; then
      DISTRO=`cat /etc/redhat-release | awk '{print $1,$4}'`
      RPM=1
  elif [ -e /etc/fedora-release ]; then
      DISTRO=`cat /etc/fedora-release | awk '{print ($1,$3~/^[0-9]/?$3:$4)}'`
      RPM=1
  elif [ -e /etc/os-release ]; then
    DISTRO=`lsb_release -d | awk -F"\t" '{print $2}'`
    RPM=0
  else
      Error "Your distribution is not supported (yet)"
      exit 1
  fi
}

# get Actual date
getDate() {
  date '+%d-%m-%Y_%H-%M-%S'
}

# SELinux status
isSELinux() {

  if [[ "$RPM" -eq "1" ]]; then
    selinuxenabled
    if [ $? -ne 0 ]
    then
        Error "SELinux:\t\t" "DISABLED"
    else
        Info "SELinux:\t\t" "ENABLED"
    fi
  fi

}

centos_installs() {
  yum install wget net-tools git -y
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
cat > /etc/systemd/system/$_APP_NAME.service <<_EOF_
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
systemctl enable --now $_APP_NAME

sleep 2

if (systemctl is-active --quiet $_APP_NAME); then
    echo -e "[${GREEN}✓${NC}] Blocky is running"
else
  echo -e "[${RED}✓${NC}] Blocky does not started, please check service status with command: journalctl -xe"
fi

}

install_additional_software() {

  echo -e "[${GREEN}✓${NC}] - Install Cloudflared"
  if confirm "Install Cloudflared? (y/n or enter)"; then

    git clone https://github.com/m0zgen/install-cloudflared.git $_DESTINATION/install-cloudflared
    $_DESTINATION/install-cloudflared/install.sh

  fi

  echo -e "[${GREEN}✓${NC}] - Install Certbot"
  if confirm "Install Certbot? (y/n or enter)"; then

    git clone https://github.com/m0zgen/install-certbot.git $_DESTINATION/install-certbot
    $_DESTINATION/install-certbot/install.sh

  fi

  echo -e "[${GREEN}✓${NC}] - Install Nginx"
  if confirm "Install Nginx? (y/n or enter)"; then

    git clone https://github.com/m0zgen/install-nginx.git $_DESTINATION/install-nginx
    $_DESTINATION/install-nginx/install.sh

  fi

}

# Download latest blocky release from official repo
download_blocky() {

  # Check destination folder
  if [[ ! -f $_DESTINATION/blocky ]]; then
    mkdir -p $_DESTINATION/logs
    cd $_DESTINATION
    
    wget "$_BINARY"
    tar xvf `ls *.tar.gz`
    
  else
    Warn $ON_ERROR "Folder $_DESTINATION exist! Blocky already installed?"

    if confirm "$ON_CHECK Reinstall Blocky? (y/n or enter)"; then

      if (systemctl is-active --quiet $_APP_NAME); then
        systemctl stop $_APP_NAME
        sleep 2
      fi

      local backup_folder=/opt/blocky_backup_$(getDate)
      mkdir -p $backup_folder
      mv $_DESTINATION $backup_folder
      
      mkdir -p $_DESTINATION/logs
      cd $_DESTINATION

      Info "[${GREEN}✓${NC}] - Download blocky.."
      wget "$_BINARY"

      Info "[${GREEN}✓${NC}] - Unpacking blocky.."
      tar xvf `ls *.tar.gz` 
      
      Info "[${GREEN}✓${NC}] - Restore blocky config.."
      cp $backup_folder/blocky/config.yml $_DESTINATION/
      # TODO - Checks user already exists

      Info "[${GREEN}✓${NC}] - Restart blocky.."
      systemctl restart blocky

      if confirm "$ON_CHECK Install additional software? (y/n or enter)"; then
          install_additional_software
      else
        Info "[${GREEN}Exit${NC}] - Bye.."
        exit 1
      fi

      Info "[${GREEN}✓${NC}] - Done!"

      exit 1
    else
      Info "[${GREEN}Exit${NC}] - Bye.."
      exit 1
    fi
  fi
}

set_hostname() {
  read -p "Setup new host name: " answer
  hostnamectl set-hostname $answer
}

# Install blocky
# ---------------------------------------------------\

isRoot
checkDistro

space
Info $ON_CHECK "Blocky installer is starting..."
if confirm "$ON_CHECK Install blocky? (y/n or enter)"; then

    if ss -tulpn | grep ':53' >/dev/null; then
      Error $ON_CHECK "Another DNS is running on 53 port!"

      if (systemctl is-active --quiet systemd-resolved); then
            Warn $ON_CHECK "Systemd-resolve possible using port"
      fi

      if confirm "$ON_CHECK Continue (systemd-resolved will be disabled)? (y/n or enter)"; then
        echo -e "[${GREEN}✓${NC}] Run blocky installer"

        if (systemctl is-active --quiet systemd-resolved); then
            systemctl disable --now systemd-resolved
        fi
      else
        echo -e "[${RED}✓${NC}] Blocky installer exit. Bye."
        exit 1
      fi

    fi

    if confirm "$ON_CHECK Set hostname? (y/n or enter)"; then
      set_hostname
    fi

    Info $ON_CHECK "Run CentOS installer..."
    if [[ "$RPM" -eq "1" ]]; then
      echo -e "[${GREEN}✓${NC}] Install CentOS packages"
      centos_installs
    fi

    download_blocky
    create_blocky_config
    create_APP_USER_NAME
    create_systemd_config

    if confirm "$ON_CHECK Install additional software? (y/n or enter)"; then
        install_additional_software
    else
      Info "[${GREEN}Exit${NC}] - Bye.."
      exit 1
    fi

else
  Info "[${GREEN}Exit${NC}] - Bye.."
  exit 1
fi

