#!/usr/bin/env bash

binary_name=`basename $1`

if [[ $binary_name =~ ^(north|integration_tests-[a-z0-9]{16})$ ]]; then
    sudo -E --preserve-env=PATH $@
else
    eval $@
fi
