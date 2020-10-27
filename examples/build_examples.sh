#!/bin/bash
# Build example containers. Expected to be called from the northstar root directory e.g ./examples/build_examples.sh <platform>

set -o errexit
set -o pipefail
set -o nounset

exe() { echo " + $@" ; "$@" ; }
bold=$(tput bold)
normal=$(tput sgr0)

if [ -z ${1+x} ]
then
  PLATFORM="host"
else
  PLATFORM=${1}
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

  NAME="$(basename "${EXAMPLE}")"
  echo "${bold}Building ${NAME}${normal} (target: ${PLATFORM})"
  ROOT_DIR="${TMP_DIR}/root"
  exe mkdir -p "${ROOT_DIR}"

  # Copy manifest and root to tmp
  cp "${EXAMPLE}/manifest.yaml" "${TMP_DIR}"
  if [ -d "${EXAMPLE}/root/" ]; then
    cp -r "${EXAMPLE}/root/." "${ROOT_DIR}/"
  fi

  # Cross compile and store artifacts for Rust containers
  if [ -f "${EXAMPLE}/Cargo.toml" ]; then
    if [ "${PLATFORM}" = "host" ]; then
      exe cargo build --release --bin "${NAME}"
      exe cp "./target/release/$NAME" "${ROOT_DIR}"
    else
      exe cross build --release --bin "${NAME}" --target "${PLATFORM}"
      exe cp "./target/$PLATFORM/release/$NAME" "${ROOT_DIR}"
    fi
  fi

  exe cargo run --bin sextant -- pack --dir "${TMP_DIR}" --out "${OUTPUT_DIR}" --key "./examples/keys/north.key"
done
