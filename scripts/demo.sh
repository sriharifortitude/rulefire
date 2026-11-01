#!/usr/bin/env bash
# Prints the README's example: each command, then what it prints. Run from anywhere.
set -u
cd "$(dirname "$0")/.."
bin=${RULEFIRE:-rulefire}
echo "\$ rulefire test examples/tests"
"$bin" test examples/tests | tr -d '\r'
echo
echo "\$ rulefire test -q examples/regression"
"$bin" test -q examples/regression | tr -d '\r'
