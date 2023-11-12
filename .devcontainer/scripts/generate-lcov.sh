#!/bin/bash -e

cd "${WORKSPACE_FOLDER}"

nohup bash -c '(ginkgo --label-filter="!e2e" --no-color --keep-going --timeout=5m --coverprofile=lcov.work --covermode=set --cover -r -p || true) && gcov2lcov -infile=lcov.work -outfile=lcov.info' > lcov.log 2>&1