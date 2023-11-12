#!/bin/bash -e

cd "${WORKSPACE_FOLDER}"

nohup bash -c 'echo "-- Start tests --" && (ginkgo --label-filter="!e2e" --no-color --keep-going --timeout=5m --coverprofile=lcov.work --covermode=atomic --cover -r -p || true) && echo "-- Start lcov convert --" && gcov2lcov -infile=lcov.work -outfile=lcov.info && echo "-- Finished --"' > lcov.log 2>&1
