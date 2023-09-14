#!/bin/bash
# Build example containers. Expected to be called from the northstar root directory.

set -x
set -e

PROFILE="debug"
KEY_ARG="--key examples/northstar.key"
REPOSITORY="target/northstar/repository"
TMPDIR=`mktemp -d`
trap 'rm -rf "$TMPDIR"' EXIT

while true; do
  case "$1" in
    --key) KEY_ARG="--key $2"; shift 2 ;;
    --target) TARGET_ARG="--target $2"; TARGET="$2"; shift 2 ;;
    --release) PROFILE_ARG="--release"; PROFILE="release"; shift ;;
    --compression) COMPRESSION_ARG="--compression $2"; shift 2;;
    -- ) shift; break ;;
    * ) break ;;
  esac
done

# Build carg-npk and northstar-sextant.
cargo build --bin cargo-npk ${PROFILE_ARG}
cargo build --bin northstar-sextant ${PROFILE_ARG}

if [ "${TARGET}" = "" ]; then
  CARGO="cargo"
  TARGET_DIR=target/${PROFILE}
else
  CARGO="cross"
  TARGET_DIR=target/${TARGET}/${PROFILE}
fi
CARGO_BUILD="${CARGO} build ${PROFILE_ARG} ${TARGET_ARG}"
CARGO_NPK_PACK="target/${PROFILE}/cargo-npk npk pack ${PROFILE_ARG} ${TARGET_ARG} ${KEY_ARG} ${COMPRESSION_ARG}"
SEXTANT_PACK="target/${PROFILE}/northstar-sextant pack --out ${TARGET_DIR} ${KEY_ARG} ${COMPRESSION_ARG}"

# Clear repository and target dir.
rm -rf ${REPOSITORY}
mkdir -p ${REPOSITORY}
rm -f ${TARGET_DIR}/*.npk

# Containers from cargo crates.
${CARGO_NPK_PACK} -p console
${CARGO_NPK_PACK} -p cpueater
${CARGO_NPK_PACK} -p crashing
${CARGO_NPK_PACK} -p custom
${CARGO_NPK_PACK} -p hello-resource
${CARGO_NPK_PACK} -p hello-world
${CARGO_NPK_PACK} -p inspect
${CARGO_NPK_PACK} -p memeater
${CARGO_NPK_PACK} -p persistence
${CARGO_NPK_PACK} -p redis-client
${CARGO_NPK_PACK} -p redis-server
${CARGO_NPK_PACK} -p seccomp
${CARGO_NPK_PACK} -p sockets
${CARGO_NPK_PACK} -p test-container
${CARGO_NPK_PACK} -p token-client
${CARGO_NPK_PACK} -p token-server

# Resources with root filesystem.
${SEXTANT_PACK} --manifest-path examples/message-0.0.1/manifest.yaml --root examples/message-0.0.1/root
${SEXTANT_PACK} --manifest-path examples/message-0.0.2/manifest.yaml --root examples/message-0.0.2/root
${SEXTANT_PACK} --manifest-path examples/test-resource/manifest.yaml --root examples/test-resource/root

# Containers without root filesystem.
${SEXTANT_PACK} --manifest-path examples/hello-ferris/manifest.yaml
${SEXTANT_PACK} --manifest-path examples/netns/manifest.yaml

# Resource from a cargo crate (very special case and you will probably never need this).
${CARGO_BUILD} --manifest-path examples/ferris/Cargo.toml
mkdir -p $TMPDIR/ferris
cp ${TARGET_DIR}/ferris $TMPDIR/ferris
${SEXTANT_PACK} --manifest-path examples/ferris/manifest.yaml --root $TMPDIR/ferris

# Copy npks to repository.
cp ${TARGET_DIR}/*.npk ${REPOSITORY}
ls -c1 ${REPOSITORY}
