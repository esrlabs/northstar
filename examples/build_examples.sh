#!/bin/bash
set -o errexit
set -o pipefail
set -o nounset

# Build all example containers for all supported platforms. Expected to be called from the northstar
# root directory:
#     ./examples/build_examples.sh
# from the directory 'northstar'.

EXAMPLES_DIR="./examples/container"
EXAMPLES=(
  "${EXAMPLES_DIR}/cpueater"
  "${EXAMPLES_DIR}/crashing"
  "${EXAMPLES_DIR}/datarw"
  "${EXAMPLES_DIR}/hello"
  "${EXAMPLES_DIR}/memeater"
  "${EXAMPLES_DIR}/resource/ferris"
  "${EXAMPLES_DIR}/resource/ferris_says_hello"
  "${EXAMPLES_DIR}/resource/hello_message"
)
ALL_PLATFORMS=(
  "aarch64-linux-android"
  "aarch64-unknown-linux-gnu"
  "aarch64-unknown-linux-musl"
  "x86_64-unknown-linux-gnu"
)
PLATFORMS=(
  "x86_64-unknown-linux-gnu"
)
REGISTRY_DIR="./target/north/registry"
KEY_DIR="./target/north/keys"
EXAMPLE_PUB_KEY="./examples/keys/north.pub"
EXAMPLE_PRV_KEY="./examples/keys/north.key"

# create registry and key directories
if [ ! -d "${REGISTRY_DIR}" ]; then
  echo "Creating registry in ${REGISTRY_DIR}"
  mkdir -p "${REGISTRY_DIR}"
fi
if [ ! -d "${KEY_DIR}" ]; then
  echo "Creating key directory in ${KEY_DIR}"
  mkdir -p "${KEY_DIR}"
fi
if [ ! -f "${KEY_DIR}" ]; then
  echo "Populating key directory"
  cp -n "${EXAMPLE_PUB_KEY}" "${KEY_DIR}"
fi

# build and pack all examples for all platforms
for example_dir in "${EXAMPLES[@]}"; do
  # create tmp directory and ensure its removal
  TMP_DIR=$(mktemp -d)
  if [ ! -e "${TMP_DIR}" ]; then
    echo >&2 "Failed to create tmp directory"
    exit 1
  fi
  trap "exit 1" HUP INT PIPE QUIT TERM
  trap 'rm -rf "${TMP_DIR}"' EXIT

  for platform in "${PLATFORMS[@]}"; do
    name="$(basename "${example_dir}")"
    echo "Building (${name}, ${platform})"
    ROOT_DIR="${TMP_DIR}/root"
    mkdir -p "${ROOT_DIR}"

    # copy manifest and root to tmp
    cp "${example_dir}/manifest.yaml" "${TMP_DIR}"
    if [ -d "${example_dir}/root/" ]; then
      cp -r "${example_dir}/root/." "${ROOT_DIR}/"
    fi

    # cross compile and store artifacts
    if [ -f "${example_dir}/Cargo.toml" ]; then
      cd ${example_dir}
        echo "cross build --release --bin ${name} --target ${platform}"
        cross build --release --bin "${name}" --target "${platform}"
        cp "target/$platform/release/$name" "${ROOT_DIR}"
      cd -
    fi

    echo "Creating NPK (${name})"
    ./target/release/sextant \
      pack \
      --dir "${TMP_DIR}" \
      --out "${REGISTRY_DIR}" \
      --key "${EXAMPLE_PRV_KEY}" \
      --platform "${platform}"
  done
done
