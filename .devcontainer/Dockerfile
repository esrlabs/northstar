FROM mcr.microsoft.com/vscode/devcontainers/base:debian

RUN apt-get update && export DEBIAN_FRONTEND=noninteractive && apt-get -y install clang libclang-dev help2man libz-dev liblzo2-dev liblz4-dev libzstd-dev

ENV HOME /home/vscode

RUN git clone https://github.com/plougher/squashfs-tools.git &&\
    cd squashfs-tools/squashfs-tools &&\
    git checkout 4.6.1 &&\
    CONFIG=1 LZO_SUPPORT=1 LZ4_SUPPORT=1 ZSTD_SUPPORT=1 make -j $(nproc) install &&\
    cd ../../ &&\
    rm -r squashfs-tools

RUN git clone https://github.com/rui314/mold.git &&\
    mkdir mold/build &&\
    cd mold/build &&\
    git checkout v1.7.0 &&\
    ../install-build-deps.sh &&\
    cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_COMPILER=c++ ..  &&\
    cmake --build . -j $(nproc) &&\
    cmake --install . &&\
    cd ../../ &&\
    rm -r mold

ENV CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER clang
ENV CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS "-C link-arg=-fuse-ld=/usr/local/bin/mold"