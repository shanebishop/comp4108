#!/usr/bin/env bash
set -eo pipefail

# Ensure this script is run as root
if [ "$EUID" -ne 0 ]; then
    echo "This script must run as root"
    exit 1
fi

set -x

# Zero the iptables counters
iptables -Z
iptables -F

######## Set INPUT chain iptables rules ########

# Drop invalid packets
iptables -A INPUT -m state --state INVALID -j DROP

# Accept packets with states ESTABLISHED or RELATED
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Accept TCP packets with syn flag set, destined for port 22, in NEW state
# For the --tcp-flags option, the first arg is the flag(s) to examine, and
# the second arg is the flags(s) which must be set 
iptables -A INPUT \
    -m state --state NEW \
    -p tcp \
    --destination-port 22 \
    --tcp-flags SYN SYN \
    -j ACCEPT

# Accept ICMP packets with type echo-request
iptables -A INPUT -p icmp --icmp-type 'echo-request' -j ACCEPT

# iptables -A INPUT -j REJECT # Part B, Q1 code - *reject* all other packets

# Part B, Q4 code - *drop* all other packets
iptables -A INPUT -j DROP

######## Done setting INPUT chain iptables rules ########

# Part B, Q5 code - accept packets with syn flag set, destined for port 6010,
# in NEW state, with 127.0.0.1 as source address
iptables -A INPUT \
    -m state --state NEW \
    -p tcp \
    --destination-port 6010 \
    --tcp-flags SYN SYN \
    -s 127.0.0.1 \
    -j ACCEPT

# Part B, Q6 code - drop outbound TCP connections to port 587
iptables -A OUTPUT -p tcp --destination-port 587 -j DROP

# Print final iptables rules
set +x
echo
echo 'Final iptables rules:'
iptables -L -v

exit 0
