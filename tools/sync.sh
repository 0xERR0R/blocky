#!/bin/bash
# Sync blocky to CentOS (x86_64)

set -e

# Envs
# ---------------------------------------------------\
PATH=$PATH:/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin
SCRIPT_PATH=$(cd `dirname "${BASH_SOURCE[0]}"` && pwd)
cd ~/

# Vars
# ---------------------------------------------------\
answer="y"
sync_config='sync_config'
destination='/opt/blocky'

test_ssh_connection() {
  status=$(ssh -p $1 -o BatchMode=yes -o ConnectTimeout=5  $2@$3 echo ok 2>&1)

  if [[ $status == ok ]] ; then
    echo status: auth ok
    ret_val=1
  elif [[ $status == "Permission denied"* ]] ; then
    echo status: no_auth
    ret_val=2
  else
    echo status: other_error
    ret_val=3
  fi
}

if [ ! -f $sync_config ]; then
  while [[ $answer = "y"* ]]; do
    echo "Enter remote server:"
    read -p "IP: " -r  answer_ip
    echo "ip_address=$answer_ip" > $sync_config

    echo "Enter remote server:"
    read -p "Port: " -r  answer_port
    echo "remote_port=$answer_port" >> $sync_config

    echo "Enter remote server:"
    read -p "User name: " -r  answer
    echo "user_name=$answer" >> $sync_config
  done

  echo "Trying copy ssh key to remote server"

  ssh-copy-id -o PubkeyAuthentication=no -i ~/.ssh/id_rsa.pub -p $answer_port $answer@$answer_ip

  echo -e "\nSync config created run script again. Exit."
  exit 1
fi

_ip=`grep 'ip_address' $sync_config | cut -d "=" -f2`
_port=`grep 'remote_port' sync_config | cut -d "=" -f2`
_user=`grep 'user_name' sync_config | cut -d "=" -f2`

echo "Test ssh connection with user: $_user to: $_ip port: $_port "
test_ssh_connection $_port $_user $_ip

if [ "$ret_val" -eq "1" ]; then
    scp -P $_port $_user@$_ip:$destination/config.yml $destination/
    sudo systemctl restart blocky
    echo "Config copied from server: $_ip to $destination. Done."
fi