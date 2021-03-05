#!/bin/bash
# Build example containers. Expected to be called from the northstar root directory e.g ./examples/build_examples.sh <platform>

set -eu
set -o errexit
set -o pipefail
set -o nounset

this_script=$(basename $0)
bold=$(tput bold)
normal=$(tput sgr0)

usage() {
    echo "USAGE:"
    echo "    build_examples.sh [OPTIONS]"
    echo ""
    echo "OPTIONS:"
    echo "    -t, --target <platform>   Target platform"
    echo "    -c, --comp   <algorithm>  Compression algorithm used by squashfs"
    echo "                              (gzip, lzma, lzo, xz, zstd)"
    echo "    -h, --help                Prints help information"

}

while [[ $# -gt 0 ]]
do
key=$1

case $key in
    -t|--target)
    PLATFORM="$2"
    shift # past argument
    shift # past value
    ;;
    -c|--comp)
    COMPRESSION_ALGORITHM="$2"
    shift # past argument
    shift # past value
    ;;
    -h|--help)
    usage
    exit 0
    ;;
    *) # unknown
    shift
    ;;
esac
done

PLATFORM=${PLATFORM-"host"}
COMPRESSION_ALGORITHM=${COMPRESSION_ALGORITHM-"gzip"}

echo "PLATFORM              = ${PLATFORM}"
echo "COMPRESSION_ALGORITHM = ${COMPRESSION_ALGORITHM}"

exe() { echo " + $*" ; $* ; }

log_err() {
  echo >&2 "$@"
}

assert_is_toplevel_dir() {
  local top_level_dir=$(git rev-parse --show-toplevel)

  if [[ ${top_level_dir} != $(pwd) ]]; then
    log_err "${this_script} must be invoked from the top-level directory"
    exit 64
  fi
}

# In bash/sh, any global variable that is modified by a sub-shell will
# lose it's binding when the subshell exits. For a cleanup 'trap' to
# work correct, the scope must be global
TMP_DIR=""
cleanup_tmpdir() {
  if [[ ! -z ${TMP_DIR} ]] ; then
    rm -rf $TMP_DIR
  fi
}

create_temp_dir() {
  # Create tmp directory and ensure its removal
  local tmpdir=$(mktemp -d)

  if [ ! -e "${tmpdir}" ]; then
    log_err "Failed to create tmp directory"
    exit 1
  fi
  trap "exit 1" HUP INT PIPE QUIT TERM
  echo -n "${tmpdir}"
}

provision_artifact() {
  local NAME="$1"
  local ROOT_DIR="$2"

  if [ "${PLATFORM}" = "host" ]; then
    exe cargo build --release --bin "${NAME}"
    exe cp "./target/release/$NAME" "${ROOT_DIR}"
  else
    exe cross build --release --bin "${NAME}" --target "${PLATFORM}"
    exe cp "./target/$PLATFORM/release/$NAME" "${ROOT_DIR}"
  fi
}

provision_root_folder() {
  local EXAMPLE="$1"
  local ROOT_DIR="$2"

  if [ -d "${EXAMPLE}/root/" ]; then
    cp -r "${EXAMPLE}/root/." "${ROOT_DIR}/"
  fi
}

build_example() {
  local EXAMPLE="$1"
  local OUTPUT_DIR="$2"

  local NAME="$(basename "${EXAMPLE}")"
  echo "${bold}Building ${NAME}${normal} (target: ${PLATFORM})"

  local MANIFEST="${EXAMPLE}/manifest.yaml"
  local ROOT_DIR="${TMP_DIR}/root"
  exe rm -rf "${ROOT_DIR}"
  exe mkdir -p "${ROOT_DIR}"

  # Copy root folder to tmp
  provision_root_folder "${EXAMPLE}" "${ROOT_DIR}"

  # Cross compile and store artifacts for Rust containers
  if [ -f "${EXAMPLE}/Cargo.toml" ]; then
    provision_artifact "${NAME}" "${ROOT_DIR}"
  fi

  exe cargo run --bin sextant -- pack --manifest "${MANIFEST}" --root "${ROOT_DIR}" --out "${OUTPUT_DIR}" --key "./examples/keys/northstar.key" --comp "${COMPRESSION_ALGORITHM}"
}

main() {
  assert_is_toplevel_dir

  local EXAMPLES=(
    "./examples/container/capabilities"
    "./examples/container/cpueater"
    "./examples/container/crashing"
    "./examples/container/datarw"
    "./examples/container/hello-world"
    "./examples/container/memeater"
    "./examples/container/resource/ferris"
    "./examples/container/resource/hello-ferris"
    "./examples/container/resource/hello-resource"
    "./examples/container/resource/message-0.0.1"
    "./examples/container/resource/message-0.0.2"
    "./examples/container/seccomp"
  )

  local OUTPUT_DIR="./target/northstar/repository"

  echo "${bold}Creating ${OUTPUT_DIR}${normal}"
  exe mkdir -p "${OUTPUT_DIR}"

  for EXAMPLE in ${EXAMPLES[*]}; do
    build_example "${EXAMPLE}" "${OUTPUT_DIR}"
  done
}


# Create tmp directory and ensure its removal
TMP_DIR=$(create_temp_dir)
trap "cleanup_tmpdir" EXIT

main "$@"
