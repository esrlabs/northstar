docker build -t esrlabs/aarch64-linux-android:latest -f Dockerfile.aarch64-unknown-linux-gnu .
docker build -t esrlabs/aarch64-unknown-linux-gnu:latest -f Dockerfile.aarch64-unknown-linux-gnu .
docker build -t esrlabs/aarch64-unknown-linux-musl:latest -f Dockerfile.aarch64-unknown-linux-musl .
docker build -t esrlabs/x86_64-unknown-linux-gnu:latest -f Dockerfile.x86_64-unknown-linux-gnu .
