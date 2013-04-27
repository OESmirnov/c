#!/bin/bash

check() {
	echo " ${1} :"
	if [[ $4 = "" ]]; then
		RES="${2} ${3}"
	else
		RES="${2} ${3} ${4}"
	fi
	HASH=$(htpasswd -nbd $1 $1)
	PASS=$("${BRUTE_PATH}" -i -m "${HASH:5}")
	echo "  ""${PASS}"
	if [[ $RES = "${PASS}" ]]; then
		return 0;
	else
		echo "$RES"
		return 1;
	fi
}

BRUTE_PATH="./brute"

VAL1="csit"
VAL2="aaaa"
VAL3="zzzz"
VAL4="*__*"

RES1="Password: \"$VAL1\""
RES2="Password: \"$VAL2\""
RES3="Password: \"$VAL3\""
RES4="Pass not found"


echo "MULTITHREAD ITERATION :"
BOOL=0
for arg in "$VAL1 ${RES1}" "$VAL2 $RES2" "$VAL3 $RES3" "$VAL4 $RES4"
do
	check $arg
	let "BOOL += $?"
done
if [[ $BOOL = 0 ]]; then
	echo " -OK   The program works correctly"
	exit 0
else
	echo " -ERROR   The program works uncorrectly"
	exit 1
fi
