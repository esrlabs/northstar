#!/bin/bash

curl --retry 3 -sSfL "https://dl.google.com/android/repository/android-ndk-r19c-linux-x86_64.zip" -O
unzip -q android-ndk-*.zip
rm android-ndk-*.zip
mv android-ndk-r19c/toolchains/llvm/prebuilt/linux-x86_64 /android-ndk
rm -r android-ndk-r19c
