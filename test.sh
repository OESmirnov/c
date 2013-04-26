#!/bin/bash

BRUTE_PATH="./brute"

VAL1="csit"
VAL2="aaaa"
VAL3="zzzz"
VAL4="*__*"

PNF="Pass not found"
HNF="Hash not found"


HASH1=$(htpasswd -nbd $VAL1 $VAL1)
HASH2=$(htpasswd -nbd $VAL2 $VAL2)
HASH3=$(htpasswd -nbd $VAL3 $VAL3)
HASH4=$(htpasswd -nbd $VAL4 $VAL4)


echo "SINGLETHREAD ITERATION :"
echo " $VAL1 :"
VAR1=$("${BRUTE_PATH}" -i -s "${HASH1:5}")
PASS1="${VAR1:11:4}"
echo "  "$VAR1
echo " $VAL2 :"
VAR2=$("${BRUTE_PATH}" -i -s "${HASH2:5}")
PASS2="${VAR2:11:4}"
echo "  "$VAR2
echo " $VAL3 :"
VAR3=$("${BRUTE_PATH}" -i -s "${HASH3:5}")
PASS3="${VAR3:11:4}"
echo "  "$VAR3
echo " $VAL4 :"
VAR4=$("${BRUTE_PATH}" -i -s "${HASH4:5}")
echo "  "$VAR4
echo " Empty hash :"
VAR5=$("${BRUTE_PATH}" -i -s)
echo "  "$VAR5

if [[ $VAL1 = $PASS1 && $VAL2 = $PASS2 && $VAL3 = $PASS3 && $VAR4 = $PNF && $VAR5 = $HNF ]]; then
	echo " -OK   The program works correctly"
	SI=0
else
	echo " -ERROR   The program works uncorrectly"
	SI=1
fi



echo ""
echo "SINGLETHREAD RECURSION :"
echo " $VAL1 :"
VAR1=$("${BRUTE_PATH}" -r -s "${HASH1:5}")
PASS1="${VAR1:11:4}"
echo "  "$VAR1
echo " $VAL2 :"
VAR2=$("${BRUTE_PATH}" -r -s "${HASH2:5}")
PASS2="${VAR2:11:4}"
echo "  "$VAR2
echo " $VAL3 :"
VAR3=$("${BRUTE_PATH}" -r -s "${HASH3:5}")
PASS3="${VAR3:11:4}"
echo "  "$VAR3
echo " $VAL4 :"
VAR4=$("${BRUTE_PATH}" -r -s "${HASH4:5}")
echo "  "$VAR4
echo " Empty hash :"
VAR5=$("${BRUTE_PATH}" -r -s)
echo "  "$VAR5

if [[ $VAL1 = $PASS1 && $VAL2 = $PASS2 && $VAL3 = $PASS3 && $VAR4 = $PNF && $VAR5 = $HNF ]]; then
	echo " -OK   The program works correctly"
	SR=0
else
	echo " -ERROR   The program works uncorrectly"
	SR=1
fi



echo ""
echo "MULTITHREAD ITERATION :"
echo " $VAL1 :"
VAR1=$("${BRUTE_PATH}" -i -m "${HASH1:5}")
PASS1="${VAR1:11:4}"
echo "  "$VAR1
echo " $VAL2 :"
VAR2=$("${BRUTE_PATH}" -i -m "${HASH2:5}")
PASS2="${VAR2:11:4}"
echo "  "$VAR2
echo " $VAL3 :"
VAR3=$("${BRUTE_PATH}" -i -m "${HASH3:5}")
PASS3="${VAR3:11:4}"
echo "  "$VAR3
echo " $VAL4 :"
VAR4=$("${BRUTE_PATH}" -i -m "${HASH4:5}")
echo "  "$VAR4
echo " Empty hash :"
VAR5=$("${BRUTE_PATH}" -i -m)
echo "  "$VAR5

if [[ $VAL1 = $PASS1 && $VAL2 = $PASS2 && $VAL3 = $PASS3 && $VAR4 = $PNF && $VAR5 = $HNF ]]; then
	echo " -OK   The program works correctly"
	MI=0
else
	echo " -ERROR   The program works uncorrectly"
	MI=1
fi



echo ""
echo "MULTITHREAD RECURSION :"
echo " $VAL1 :"
VAR1=$("${BRUTE_PATH}" -r -m "${HASH1:5}")
PASS1="${VAR1:11:4}"
echo "  "$VAR1
echo " $VAL2 :"
VAR2=$("${BRUTE_PATH}" -r -m "${HASH2:5}")
PASS2="${VAR2:11:4}"
echo "  "$VAR2
echo " $VAL3 :"
VAR3=$("${BRUTE_PATH}" -r -m "${HASH3:5}")
PASS3="${VAR3:11:4}"
echo "  "$VAR3
echo " $VAL4 :"
VAR4=$("${BRUTE_PATH}" -r -m "${HASH4:5}")
echo "  "$VAR4
echo " Empty hash :"
VAR5=$("${BRUTE_PATH}" -r -m)
echo "  "$VAR5

if [[ $VAL1 = $PASS1 && $VAL2 = $PASS2 && $VAL3 = $PASS3 && $VAR4 = $PNF && $VAR5 = $HNF ]]; then
	echo " -OK   The program works correctly"
	MR=0
else
	echo " -ERROR   The program works uncorrectly"
	MR=1
fi



if [[ $SI -eq 0 && $SR -eq 0 && $MI -eq 0 && $MR -eq 0 ]]; then
	echo "STATUS   :  THE PROGRAMM WORKS CORRECTLY"
else
	echo "STATUS   :  THE PROGRAMM WORKS UNCORRECTLY"
fi

