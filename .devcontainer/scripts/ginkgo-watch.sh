#!/bin/bash

set -e

# Install required tools
go install github.com/onsi/ginkgo/v2/ginkgo@latest
go install github.com/jandelgado/gcov2lcov@latest

COVERAGE_DIR="${WORKSPACE_FOLDER}/.coverage"
GCOV_FILE="${COVERAGE_DIR}/coverage.gcov"
LCOV_FILE="${COVERAGE_DIR}/coverage.lcov"

mkdir -p "${COVERAGE_DIR}"

function getFileName(){
  echo "${COVERAGE_DIR}/coverage_${1}.${2}"
}

function watch(){
  local gcovFilename="coverage.gcov"
  local lcovFile="${COVERAGE_DIR}/${1}_coverage.lcov"
  local gcovFile="${COVERAGE_DIR}/${1}_${gcovFilename}"
  ginkgo watch --output-dir="${COVERAGE_DIR}" --coverprofile="${gcovFilename}" --cover --after-run-hook="gcov2lcov -infile=${gcovFile} -outfile=${lcovFile}" "${WORKSPACE_FOLDER}/${1}" &
}

watch api
watch cmd
watch config
watch lists
watch querylog
watch redis
watch resolver
watch server
watch util