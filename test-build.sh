#!/bin/bash

DPDK="/root/dpdk"
DPDK_PING="/root/dpdk-ping"

#set -e
set -x

cd $DPDK

if [ $# -eq 0 ]
then
	TAG="v18.05"
else
	TAG="$1"
fi

git tag | grep -A 5000 -m1 "^$TAG" | grep '^v[0-9][0-9]\.' | grep -v '\-rc' | while read tag
do
	cd $DPDK

	git stash save --keep-index --include-untracked
	git stash drop
	rm -rf build

	git checkout $tag &&
	meson build &&
	cd build &&
	ninja &&
	meson install
	if [ $? -ne 0 ]; then
		echo "? $tag"
		exit 1
	fi

	cd $DPDK_PING

	make clean && make
	if [ $? -ne 0 ]; then
		echo "- $tag"
		exit 1
	else
		echo "+ $tag"
	fi
done
