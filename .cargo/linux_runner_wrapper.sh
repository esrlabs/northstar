#!/usr/bin/env bash

binary_name=`basename $1`

if [[ $binary_name =~ ^(north|tests-[a-z0-9]{16})$ ]]; then
    sudo -E $@
else
    eval $@
fi
