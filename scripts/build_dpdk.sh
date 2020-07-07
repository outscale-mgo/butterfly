#!/bin/bash

set -e

# -DHAVE_TC_FLOWER -DHAVE_TC_VLAN_ID
DPDK_CFLAGS="-fPIC -Wno-address-of-packed-member -Wno-format-overflow -Wno-maybe-uninitialized -Wno-stringop-overflow -Wno-zero-length-bounds -fcommon"

echo dpdk source dir: $1
cd $1

EXTRA_CFLAGS=$DPDK_CFLAGS

make EXTRA_CFLAGS="$DPDK_CFLAGS"

