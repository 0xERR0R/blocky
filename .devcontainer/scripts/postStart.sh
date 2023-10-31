#!/bin/bash

set -e

# Use the host's timezone and time
sudo ln -sf /usr/share/host/localtime /etc/localtime
sudo ln -sf /usr/share/host/timezone /etc/timezone

bash -c "\"${WORKSPACE_FOLDER}/.devcontainer/scripts/ginkgo-watch.sh\""