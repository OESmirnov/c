#!/bin/bash

BOOL=0;
tests/single_iter_test.sh
let "BOOL += $?"
tests/single_rec_test.sh
let "BOOL += $?"
if [[ $BOOL = 0 ]]; then
	echo "STATUS   :  THE PROGRAM WORKS CORRECTLY"
	exit 0
else
	echo "STATUS   :  THE PROGRAM WORKS UNCORRECTLY"
	exit 1
fi
