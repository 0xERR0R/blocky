#!/bin/bash

export CGO_ENABLED=0
export GOOS=$TARGETOS
export GOARCH=$TARGETARCH
export GOARM=${TARGETVARIANT##*v}