#!/bin/bash -e

cd "${WORKSPACE_FOLDER}"
go run github.com/onsi/ginkgo/v2/ginkgo "$@"