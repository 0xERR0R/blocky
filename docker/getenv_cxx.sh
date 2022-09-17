#!/bin/bash

if [[ "$GOARCH" = "arm64" ]]
then 
    CXX_BIN="aarch64-linux-gnu-g++"
elif  [[ "$GOARCH" = "arm" ]]
then
    if [[ "$GOARM" = "7" ]]
    then
        CXX_BIN="arm-linux-gnueabihf-g++"
    else
        CXX_BIN="arm-linux-gnueabi-g++"
    fi
else
    CXX_BIN=""
fi

echo $CXX_BIN