#!/bin/bash

BUTTERFLY_SRC_ROOT=$1
BUTTERFLY_BUILD_ROOT=$2

source $BUTTERFLY_SRC_ROOT/tests/functions.sh

network_connect 0 1
server_start 0
nic_add 0 1 42 sg-1
nic_add 0 2 42 sg-2
qemu_start 1
qemu_start 2

sg_member_add 0 sg-1 42.0.0.1
sg_rule_add_with_sg_member udp sg-2 0 8000 sg-1
ssh_connection_test udp 1 2 8000
ssh_no_connection_test udp 2 1 8000

sg_member_del 0 sg-1 42.0.0.1
ssh_no_connection_test udp 1 2 8000
ssh_no_connection_test udp 2 1 8000

sg_member_add 0 sg-1 42.0.0.1
ssh_connection_test udp 1 2 8000
ssh_no_connection_test udp 2 1 8000

qemu_stop 1
qemu_stop 2
server_stop 0
network_disconnect 0 1
return_result
