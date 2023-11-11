#!/bin/bash -e

echo "Setting up go environment..."
# Use the host's timezone and time
sudo ln -sf /usr/share/host/localtime /etc/localtime
sudo ln -sf /usr/share/host/timezone /etc/timezone
# Change permission on pkg volume
sudo chown -R vscode:golang /go/pkg
echo ""

echo "Downloading Go modules..."
go mod download -x
echo ""

echo "Tidying Go modules..."
go mod tidy -x
echo ""

echo "Installing Go tools..."
echo "  - ginkgo"
go install github.com/onsi/ginkgo/v2/ginkgo@latest
echo "  - golangci-lint"
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
echo "  - gofumpt"
go install mvdan.cc/gofumpt@latest
echo "  - gcov2lcov"
go install github.com/jandelgado/gcov2lcov@latest