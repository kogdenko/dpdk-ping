#!/bin/bash

SCRIPT=$(basename $0)
SCRIPTPATH=$(realpath "$0")
SCRIPTDIR=$(dirname "$SCRIPTPATH")

DPDK="/root/dpdk"
LOG_DIR=""
TAG="v18.05"

usage()
{
	echo "$SCRIPT --dpdk {path} [-h] [--log {dir}] [--tag {tag}]"
}

while [ $# -ge 1 ]; do
	case "$1" in
	-h)
		usage
		shift
		exit 0
		;;
	--dpdk)
		DPDK=$(realpath $2)
		shift 2
		;;
	--log)
		LOG_DIR=$(realpath $2)
		shift 2
		;;
	--tag)
		TAG=$2
		shift 2
		;;
	* )
		echo "$SCRIPT: unrecognized option '$1'"
		exit 1
	esac
done

if [ -z "$DPDK" ]; then
	usage
	exit 2
fi

cd $DPDK

git tag | grep -A 5000 -m1 "^$TAG" | grep '^v[0-9][0-9]\.' | grep -v '\-rc' | while read tag
do
	cd $DPDK
	
	if [ -z "$LOG_DIR" ]; then
		LOG="/dev/null"
	else
		mkdir -p $LOG_DIR
		LOG=$LOG_DIR/$tag
	fi

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
		cd $SCRIPTDIR

		make clean >> /dev/null 2>&1
		make build >> $LOG 2>&1
		if [ $? -ne 0 ]; then
			echo "$tag: dpdk-ping compilation failed"
		else
			echo "$tag: dpdk-ping compiled successfully"
		fi
	fi
done
