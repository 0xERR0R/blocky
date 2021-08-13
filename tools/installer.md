# Blocky installer

`installer.sh` it is a simple script for install Blocky to:

* CentOS 7/8
* Ubuntu/Debian (in future)

Note: All features tested and deployed on CentOS 8

## Features

* Install from scratch to rpm/beb based distros
* Steb-by-step installer
* Automatically detect and download latest `blocky` release from official repo
* Install under simple user
  * New user creation
  * Allow for new user using privileged ports (aka 53) without sudo
  * Create `systemctl` unit service
  * Generate simple `config.yml`
* Reinstall `blocky`
* Backup `blocky`
* Install additional software (optionally):
  * Cloudflared
  * Cerbot
  * Nginx