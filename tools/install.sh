#!/bin/bash
# Install blocky to CentOS (x86_64)

# Envs
# ---------------------------------------------------\
PATH=$PATH:/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin
SCRIPT_PATH=$(cd `dirname "${BASH_SOURCE[0]}"` && pwd)

# Vars
# ---------------------------------------------------\
_APP_FOLDER_NAME="blocky"
_APP_USER_NAME="blockyusr"
_DESTINATION=/opt/${_APP_FOLDER_NAME}
_BINARY=`curl -s https://api.github.com/repos/0xERR0R/blocky/releases/latest | grep browser_download_url | grep "Linux_x86_64" | awk '{print $2}' | tr -d '\"'`

# Functions
# ---------------------------------------------------\

if [[ -f /usr/bin/lsof ]]; then

  if lsof -Pi :53 -sTCP:LISTEN -t >/dev/null ; then
      echo "Another DNS is running on 53 port! Exit.."
      exit 1
  fi

else
  echo "Please install lsof for checking local exist DNS server.."
  exit 1
fi

# Check destination folder
if [[ ! -d $_DESTINATION ]]; then
  mkdir -p $_DESTINATION/logs
else
  echo -e "Folder $_DESTINATION exist! Blocky already installed? Exit.."
  exit 1
fi

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
    Error "You must be root user to continue"
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
