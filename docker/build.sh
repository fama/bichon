#!/bin/bash
set -e

VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' ../Cargo.toml | head -1)
echo "Building bichon $VERSION"

docker build \
    --build-arg CRATE_VERSION="$VERSION" \
    -t bichon:"$VERSION" \
    -f ./Dockerfile \
    ..

docker tag bichon:"$VERSION" billydong/bichon:"$VERSION"
echo "Tagged billydong/bichon:$VERSION"
