#!/bin/bash

#check that dperf work

BUTTERFLY_BUILD_ROOT=$1
BUTTERFLY_SRC_ROOT=$(cd "$(dirname $0)/../.." && pwd)
source $BUTTERFLY_SRC_ROOT/tests/functions.sh

network_connect 0 1
server_start 0
nic_add 0 1 42 sg-1
nic_add 0 2 42 sg-1
sg_rule_add_all_open 0 sg-1
qemus_start 1 2
scp_to 1 $BUTTERFLY_SRC_ROOT/3rdparty/dpdk/usertools/
# modprobe uio_pci_generic
# ip link set ens4 down
#./usertools/dpdk-devbind.py  -u 0000:00:04.0
#./usertools/dpdk-devbind.py  --bind=uio_pci_generic 0000:00:04.0
#./dperf --no-huge -- --ether 800 --smac "52:54:00:12:34:01" --dmac "52:54:00:12:34:02" --sip "42.0.0.1" --dip "42.0.0.2" --verbose

read
qemus_stop 1 2
server_stop 0
network_disconnect 0 1
return_result
