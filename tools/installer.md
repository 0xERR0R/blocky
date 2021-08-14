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

After unstall Blocky you can use sync feature to download or upload config to remote server over ssh connection.

