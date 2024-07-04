#!/bin/bash

# This script sends every possible signals
# to a specific PID with pause between them.
# SIGKILL & SIGSTOP are not send.
# Signals 32 & 33 are not send too.

# Check if PID is provided as an argument
if [ -z "$1" ]; then
	echo "Usage: $0 <pid>"
	exit 1
fi

PID=$1

# Loop through signal numbers from 1 to 64
for SIG in {1..64}; do
	# Skip signal number 9 (SIGKILL)
	if [ "$SIG" -eq 9 ]; then
		echo "Skipping SIGKILL (signal 9)"
		continue
	fi

	if [ "$SIG" -eq 19 ]; then
		echo "Skipping SIGSTOP (signal 19)"
		continue
	fi

	if [ "$SIG" -eq 32 ]; then
		echo "Skipping signal 32"
		continue
	fi

	if [ "$SIG" -eq 33 ]; then
		echo "Skipping signal 33"
		continue
	fi

	SIGNAL_NAME=$(kill -l $SIG 2>/dev/null)
	if [ $? -eq 0 ]; then
		echo "Sending signal $SIG ($SIGNAL_NAME) to process $PID"
		kill -$SIG $PID

		if [ $? -eq 1 ]; then
			echo "Terminating."
			exit 0
		fi

		sleep 0.5
	else
		echo "Skipping invalid signal number: $SIG"
	fi
done
