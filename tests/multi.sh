#!/bin/bash

BOOL=0;
tests/multi_iter_test.sh
let "BOOL += $?"
tests/multi_rec_test.sh
let "BOOL += $?"
if [[ $BOOL = 0 ]]; then
	echo "STATUS   :  THE PROGRAMM WORKS CORRECTLY"
	exit 0
else
	echo "STATUS   :  THE PROGRAMM WORKS UNCORRECTLY"
	exit 1
fi
