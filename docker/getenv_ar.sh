#!/bin/bash

if [[ "$GOARCH" = "arm64" ]]
then 
    AR_BIN="aarch64-linux-gnu-ar"
elif  [[ "$GOARCH" = "arm" ]]
then
    if [[ "$GOARM" = "7" ]]
    then
        AR_BIN="arm-linux-gnueabihf-ar"
    else
        AR_BIN="arm-linux-gnueabi-ar"
    fi
else
    AR_BIN=""
fi

echo $AR_BIN