#!/bin/bash

echo $@

PCMD=$(cat /proc/$PPID/cmdline | strings -1)
PCMD=$(echo -n ${PCMD##*/})
RNAME=$(echo -n ${@##*/})

if [[ "$PCMD" =~ "cargo test" ]]; then
	exec $@
elif [[ "$PCMD" =~ "cargo bench" ]]; then
	exec $@
else
	if [[ $RNAME =~ "reflow-cli" ]]; then
		exec sudo PATH=$PATH RUST_BACKTRACE=$RUST_BACKTRACE $@
	else
		exec $@
	fi
fi
