#!/bin/bash -e

if [[ "$TARGETARCH" == "arm64" ]]
then 
    GCC_BIN="aarch64-linux-gnu-gcc"
elif  [[ "$TARGETARCH" == "arm" ]]
then
    if [[ "$TARGETVARIANT" == "v7" ]]
    then
        GCC_BIN="arm-linux-gnueabihf-gcc"
    else
        GCC_BIN="arm-linux-gnueabi-gcc"
    fi
else
    GCC_BIN="x86_64-linux-gnu-gcc"
fi

export CC="/usr/bin$GCC_BIN"