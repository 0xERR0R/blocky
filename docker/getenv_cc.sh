#!/bin/bash

if [[ "$GOARCH" = "arm64" ]]
then 
    CC_BIN="aarch64-linux-gnu-gcc"
elif  [[ "$GOARCH" = "arm" ]]
then
    if [[ "$GOARM" = "7" ]]
    then
        CC_BIN="arm-linux-gnueabihf-gcc"
    else
        CC_BIN="arm-linux-gnueabi-gcc"
    fi
else
    CC_BIN=""
fi

echo $CC_BIN