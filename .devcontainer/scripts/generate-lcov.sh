#!/bin/bash -e

cd "${WORKSPACE_FOLDER}"

nohup bash -c 'ginkgo --label-filter="!e2e" --no-color --keep-going --timeout=5m --coverprofile=lcov.work --covermode=set --cover -r -p && gcov2lcov -infile=coverage.txt -outfile=lcov.info' > lcov.log 2>&1