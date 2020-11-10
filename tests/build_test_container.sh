#!/bin/bash
set -o errexit
set -o pipefail
set -o nounset

TEST_CONTAINER_DIR="./tests/test_container"
PLATFORM="x86_64-unknown-linux-gnu"
REGISTRY_DIR="./target/north/registry"
EXAMPLE_PRV_KEY="./examples/keys/north.key"

# create registry and key directories
if [ ! -d "${REGISTRY_DIR}" ]; then
  echo "Creating registry in ${REGISTRY_DIR}"
  mkdir -p "${REGISTRY_DIR}"
fi

# create tmp directory and ensure its removal
TMP_DIR=$(mktemp -d)
if [ ! -e "${TMP_DIR}" ]; then
echo >&2 "Failed to create tmp directory"
exit 1
fi
trap "exit 1" HUP INT PIPE QUIT TERM
trap 'rm -rf "${TMP_DIR}"' EXIT

name="$(basename "${TEST_CONTAINER_DIR}")"
echo "Building (${name}, ${PLATFORM})"
ROOT_DIR="${TMP_DIR}/root"
mkdir -p "${ROOT_DIR}"

# copy manifest
cp "${TEST_CONTAINER_DIR}/manifest.yaml" "${TMP_DIR}"

# cross compile and store artifacts
cross build --release --bin "${name}" --target "${PLATFORM}"
cp "./target/$PLATFORM/release/$name" "${ROOT_DIR}"

cargo run --bin sextant -- \
  pack \
  --dir "${TMP_DIR}" \
  --out "${REGISTRY_DIR}" \
  --key "${EXAMPLE_PRV_KEY}"
