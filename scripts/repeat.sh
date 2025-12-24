#!/bin/sh

while :; do
	build test --valgrind;
	RES=$?;
	echo "result=$RES"
	if [ "$RES" != "0" ]; then
		echo "fail!";
		exit 1;
	fi
done
