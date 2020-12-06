#!/usr/bin/env bash
set -eo pipefail

echo "All ports we are interested in:"
sudo nmap -p1024- -sS 127.0.0.1 | tail -n+7 | head -n-2 | awk '{split($1,x,"/"); print x[1]}'

for port in $(sudo nmap -p1024- -sS 127.0.0.1 | tail -n+7 | head -n-2 | awk '{split($1,x,"/"); print x[1]}')
do
    echo "Copying input.txt to port $port."
    netcat -vl "$port" < /dev/null &
    sleep 1
    netcat -n 127.0.0.1 "$port" < input.txt
done

echo 'Done.'
exit 0
