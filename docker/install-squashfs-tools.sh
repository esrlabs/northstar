#!/bin/bash

git clone https://github.com/plougher/squashfs-tools.git
cd squashfs-tools/squashfs-tools
git checkout 4.5.1
make install
cd ../../
rm -r squashfs-tools