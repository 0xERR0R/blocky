# Blocky installer

`installer.sh` it is a bash script for install Blocky to:

* CentOS/Fedora Linux
* Blocky is installed as systemctl unit service to `/opt/blocky` catalog as default. 
* After install Blocky works from regular user.

_Note: All features tested. deployed and using on CentOS 8_

## Features

* Install from scratch to rpm based distros
  * Steb-by-step installer
  * Automate installer
* Detect and download latest `blocky` release from official repo
* Install under simple user
  * New user creation
  * Allow to user using privileged ports (aka 53) without sudo
  * Allow to user start, stop, enable, disable `blocky` service
  * Create `systemctl` unit service
  * Generate simple `config.yml`
* Reinstall `blocky`
* Backup `blocky`
* Install additional software (optionally):
  * Cloudflared
  * Cerbot
  * Nginx

## Sync configs

After install Blocky you can use sync feature to download or upload config to remote server over ssh connection with `sync.sh`.

In first run `sync.sh` will ask:
* Remote server IP
* Remote server port
* Remote server ssh user name

Them will try copy ssh key to remote server with `ssh-copy-id`, after that you can run script again and `sync.sh` will copy `cinfig.yml` from remote server to local `/opt/blocky` folder.

