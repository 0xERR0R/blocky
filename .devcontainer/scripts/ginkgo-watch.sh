#!/bin/bash -e
FOLDERS=("api" "cmd" "config" "lists" "querylog" "redis" "resolver" "server" "util")

echo "Starting ginkgo watchers" > /tmp/ginkgo-watch.log

# Watch function for seperate folders to run ginkgo and convert gcov to lcov
function watch(){
  local gcovFilename=".coverage.gcov"
  local watchDir="${WORKSPACE_FOLDER}/${1}"
  local lcovFile="${watchDir}/.coverage.lcov"
  local gcovFile="${watchDir}/${gcovFilename}"
  go run github.com/onsi/ginkgo/v2/ginkgo watch --no-color --coverprofile="${gcovFilename}" --keep-separate-coverprofiles --cover --after-run-hook="go run github.com/jandelgado/gcov2lcov -infile=${gcovFile} -outfile=${lcovFile}" "${watchDir}" >>/tmp/ginkgo-watch.log &
}

# Watch for changes in the following folders
for folder in "${FOLDERS[@]}"; do
  watch "${folder}"
done

tail -f /tmp/ginkgo-watch.log
