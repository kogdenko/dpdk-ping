#!/bin/bash

DPDK="/root/dpdk"
DPDK_PING="/root/dpdk-ping"
LOG="./build.log"

#set -x

cd $DPDK

if [ $# -eq 0 ]
then
	TAG="v18.05"
else
	TAG="$1"
fi

echo "" > $LOG

git tag | grep -A 5000 -m1 "^$TAG" | grep '^v[0-9][0-9]\.' | grep -v '\-rc' | while read tag
do
	cd $DPDK

	git stash save --keep-index --include-untracked >> $LOG 2>&1
	git stash drop >> $LOG 2>&1
	rm -rf build >> $LOG 2>&1

	echo "$tag: Compiling DPDK"
	git checkout $tag >> $LOG 2>&1 &&
	meson build >> $LOG 2>&1 &&
	cd build >> $LOG 2>&1 &&
	ninja >> $LOG 2>&1 &&
	meson install  >> $LOG 2>&1
	if [ $? -ne 0 ]; then
		echo "$tag: DPDK compilation failed"
	else
		echo "$tag: DPDK compiled successfully"
		cd $DPDK_PING

		make clean >> $LOG 2>&1 &&
		make >> $LOG 2>&1
		if [ $? -ne 0 ]; then
			echo "$tag: dpdk-ping compilation failed"
		else
			echo "$tag: dpdk-ping compiled successfully"
		fi
	fi
done
