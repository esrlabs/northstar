aarch64-linux-android

The `cross` tool uses a outdated NDK (version r15) which is not abled to build libminijail.
The Dockerfile.aarch64-linux-android replaces the r15 NDK with r19c. The docker images is
referenced in Cross.toml.

x86_64-unknown-linux-gnu

The `cross` docker image for x86_64-unknown-linux-gnu lacks libcap. The Dockerfile adds this.
The Docker tag is referenced in Cross.toml.