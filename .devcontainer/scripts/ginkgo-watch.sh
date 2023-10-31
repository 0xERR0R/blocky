#!/bin/bash -e

# Watch function for seperate folders to run ginkgo and convert gcov to lcov
function watch(){
  local gcovFilename=".coverage.gcov"
  local watchDir="${WORKSPACE_FOLDER}/${1}"
  local lcovFile="${watchDir}/.coverage.lcov"
  local gcovFile="${watchDir}/${gcovFilename}"
  go run github.com/onsi/ginkgo/v2/ginkgo watch --no-color --coverprofile="${gcovFilename}" --keep-separate-coverprofiles --cover --after-run-hook="go run github.com/jandelgado/gcov2lcov -infile=${gcovFile} -outfile=${lcovFile}" "${watchDir}" &
}

# Watch for changes in the following folders
watch api
watch cmd
watch config
watch lists
watch querylog
watch redis
watch resolver
watch server
watch util

echo "Setup complete."