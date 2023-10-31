#!/bin/bash -e

# Use the host's timezone and time
sudo ln -sf /usr/share/host/localtime /etc/localtime
sudo ln -sf /usr/share/host/timezone /etc/timezone

echo "Downloading Go modules..."
sudo chown -R vscode:golang /go/pkg/mod
go mod download