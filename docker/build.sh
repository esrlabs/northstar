#!/usr/bin/env bash

docker build -t north/x86_64-unknown-linux-gnu:0.2.0 -f Dockerfile.x64_64-unknown-linux-gnu .
docker build -t north/aarch64-linux-android:0.2.0 -f Dockerfile.aarch64-linux-android .