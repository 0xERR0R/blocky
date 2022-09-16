#!/bin/bash

if [[ "$GOARCH" = "arm64" ]]
then 
    GCC_BIN="aarch64-linux-gnu-gcc"
elif  [[ "$GOARCH" = "arm" ]]
then
    if [[ "$GOARM" = "7" ]]
    then
        GCC_BIN="arm-linux-gnueabihf-gcc"
    else
        GCC_BIN="arm-linux-gnueabi-gcc"
    fi
else
    GCC_BIN="x86_64-linux-gnu-gcc"
fi

echo "/usr/bin$GCC_BIN"