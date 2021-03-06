#!/bin/bash

BRUTE_PATH="./brute"

echo "Write password:"
read VAL
HASH=$(htpasswd -nbd A $VAL)
for MODE in "-i -s" "-r -s" "-i -m" "-r -m"
do
	echo -e '\n\n'"KEYS = " $MODE
	time "${BRUTE_PATH}" ${MODE} "${HASH/A:/}"
done
