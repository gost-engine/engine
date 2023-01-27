#!/bin/bash -efux

PREFIX=$HOME/opt
PATH=$PREFIX/bin:$PATH

list=$(git ls-tree --name-only -r HEAD | grep -v ecp_id_.* | grep -v gost_grasshopper_precompiled.c | grep '[.][ch]$')
clang-format -i $list
diffLen=$(git diff | wc -l)
test 0 -eq $diffLen || exit 1
