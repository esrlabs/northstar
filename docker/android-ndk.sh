#!/usr/bin/env bash

set -x
set -euo pipefail

NDK_URL=https://dl.google.com/android/repository/android-ndk-r19c-linux-x86_64.zip

main() {

    local dependencies=(
        curl
        unzip
    )

    apt-get update
    apt-get install --assume-yes --no-install-recommends --fix-missing squashfs-tools

    local purge_list=()
    for dep in "${dependencies[@]}"; do
        if ! dpkg -L "${dep}"; then
            apt-get install --assume-yes --no-install-recommends --fix-missing "${dep}"
            purge_list+=( "${dep}" )
        fi
    done
    local td
    td="$(mktemp -d)"

    pushd "${td}"

    curl --retry 3 -sSfL "${NDK_URL}" -O
    unzip -q android-ndk-*.zip

    mv android-ndk-r19c/toolchains/llvm/prebuilt/linux-x86_64 /android-ndk

    popd

    if (( ${#purge_list[@]} )); then
      apt-get purge --assume-yes --auto-remove "${purge_list[@]}"
    fi

    rm -rf "${td}"
    rm "${0}"
}

main "${@}"
