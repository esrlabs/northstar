#!/bin/bash
# Build example containers. Expected to be called from the northstar root directory e.g ./examples/build_examples.sh <target>

set -o errexit
set -o pipefail
set -o nounset

exe() { echo " + $@" ; "$@" ; }
bold=$(tput bold)
normal=$(tput sgr0)

if [ "$#" -eq  "0" ]
then
  PLATFORMS=(
    "aarch64-linux-android"
    "aarch64-unknown-linux-gnu"
    "aarch64-unknown-linux-musl"
    "x86_64-unknown-linux-gnu"
  )
else
  PLATFORMS=$1
fi

OUTPUT_DIR="./target/north/registry"
EXAMPLES=(
  "./examples/container/cpueater"
  "./examples/container/crashing"
  "./examples/container/datarw"
  "./examples/container/hello"
  "./examples/container/memeater"
  "./examples/container/resource/ferris"
  "./examples/container/resource/ferris_says_hello"
  "./examples/container/resource/hello_message"
)

echo "${bold}Creating ${OUTPUT_DIR}${normal}"
exe mkdir -p "${OUTPUT_DIR}"

for EXAMPLE in ${EXAMPLES[*]}; do
  # Create tmp directory and ensure its removal
  TMP_DIR=$(mktemp -d)
  if [ ! -e "${TMP_DIR}" ]; then
    echo >&2 "Failed to create tmp directory"
    exit 1
  fi
  trap "exit 1" HUP INT PIPE QUIT TERM
  trap 'rm -rf "${TMP_DIR}"' EXIT

  for PLATFORM in ${PLATFORMS[*]}; do
    NAME="$(basename "${EXAMPLE}")"
    echo "${bold}Building ${NAME}${normal} (target: ${PLATFORM})"
    ROOT_DIR="${TMP_DIR}/root"
    exe mkdir -p "${ROOT_DIR}"

    # Copy manifest and root to tmp
    cp "${EXAMPLE}/manifest.yaml" "${TMP_DIR}"
    if [ -d "${EXAMPLE}/root/" ]; then
      cp -r "${EXAMPLE}/root/." "${ROOT_DIR}/"
    fi

    # Cross compile and store artifacts
    if [ -f "${EXAMPLE}/Cargo.toml" ]; then
      exe cross build --release --bin "${NAME}" --target "${PLATFORM}"
      exe cp "./target/$PLATFORM/release/$NAME" "${ROOT_DIR}"
    fi

    exe cargo run --bin sextant -- pack --dir "${TMP_DIR}" --out "${OUTPUT_DIR}" --key "./examples/keys/north.key" --platform "${PLATFORM}"
  done
done
