#!/bin/bash

rm -rf $(find vendor/* -maxdepth 0 ! -name 'vendor.json')

go get -u github.com/kardianos/govendor
govendor sync

CHANGES=`git diff`
if [ -n "$CHANGES" ] ; then
    echo "vendor does not match the lock:"
    echo $CHANGES
    exit 1
fi
