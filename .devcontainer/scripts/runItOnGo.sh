#!/bin/bash -e

FOLDER_PATH=$1
if [ -z "${FOLDER_PATH}" ]; then
    FOLDER_PATH=$PWD
fi

BASE_PATH=$2
if [ -z "${BASE_PATH}" ]; then
    BASE_PATH=$WORKSPACE_FOLDER
fi

if [ "$FOLDER_PATH" = "$BASE_PATH" ]; then
    echo "Skipping lcov creation for base path"
    exit 1
fi

FOLDER_NAME=${FOLDER_PATH#"$BASE_PATH/"}
FILE_NAME="$(echo "$FOLDER_NAME" | sed 's/\//-/g').ginkgo"
FILE_PATH="/tmp/$FILE_NAME"


echo "-- Start $FOLDER_NAME ($(date '+%T')) --"

TIMEFORMAT=' - Ginkgo tests finished in: %R seconds'
time ginkgo --label-filter="!e2e" --keep-going --timeout=5m --output-dir=/tmp --coverprofile="$FILE_NAME" --covermode=atomic --cover -r -p "$FOLDER_PATH" || true

TIMEFORMAT=' - lcov convert finished in: %R seconds'
time gcov2lcov -infile="$FILE_PATH" -outfile="$FOLDER_PATH/lcov.info"

TIMEFORMAT=' - cleanup finished in: %R seconds'
time rm "$FILE_PATH"

echo "-- Finished $FOLDER_NAME ($(date '+%T')) --"