#!/bin/bash -e

# Use the host's timezone and time
sudo ln -sf /usr/share/host/localtime /etc/localtime
sudo ln -sf /usr/share/host/timezone /etc/timezone

echo "Downloading Go modules..."
sudo chown -R vscode:golang /go/pkg
go mod download -x

echo "Installing Go tools..."
go install github.com/onsi/ginkgo/v2/ginkgo@latest
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
go install mvdan.cc/gofumpt@latest