#!/bin/bash
find test/ -name "*.c" | xargs -n1 rpl $1 $2
find src/ -name "*.c" | xargs -n1 rpl $1 $2
find include/ -name "*.h" | xargs -n1 rpl $1 $2

