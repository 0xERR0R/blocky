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
WORK_NAME="$(echo "$FOLDER_NAME" | sed 's/\//-/g')"
WORK_FILE_NAME="$WORK_NAME.ginkgo"
WORK_FILE_PATH="/tmp/$WORK_FILE_NAME"
OUTPUT_FOLDER="$BASE_PATH/coverage"
OUTPUT_FILE_PATH="$OUTPUT_FOLDER/$WORK_NAME.lcov"


mkdir -p "$OUTPUT_FOLDER"

echo "-- Start $FOLDER_NAME ($(date '+%T')) --"

TIMEFORMAT=' - Ginkgo tests finished in: %R seconds'
time ginkgo --label-filter="!e2e" --keep-going --timeout=5m --output-dir=/tmp --coverprofile="$WORK_FILE_NAME" --covermode=atomic --cover -r -p "$FOLDER_PATH" || true

TIMEFORMAT=' - lcov convert finished in: %R seconds'
time gcov2lcov -infile="$WORK_FILE_PATH" -outfile="$OUTPUT_FILE_PATH" || true

TIMEFORMAT=' - cleanup finished in: %R seconds'
time rm "$WORK_FILE_PATH" || true

echo "-- Finished $FOLDER_NAME ($(date '+%T')) --"