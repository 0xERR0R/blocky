#!/bin/bash

if [[ "$GOARCH" = "arm64" ]]
then 
    LD_BIN="aarch64-linux-gnu-ld"
elif  [[ "$GOARCH" = "arm" ]]
then
    if [[ "$GOARM" = "7" ]]
    then
        LD_BIN="arm-linux-gnueabihf-ld"
    else
        LL_BIN="arm-linux-gnueabi-ld"
    fi
else
    LD_BIN=""
fi

echo $LD_BIN