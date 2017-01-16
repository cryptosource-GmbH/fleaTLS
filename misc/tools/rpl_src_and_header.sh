#!/bin/bash
find test/ -name "*.c" | xargs -n1 rpl $1 $2
find test/ -name "*.cpp" | xargs -n1 rpl $1 $2
find test/ -name "*.h" | xargs -n1 rpl $1 $2
find src/ -name "*.c" | xargs -n1 rpl $1 $2
find include/ -name "*.h" | xargs -n1 rpl $1 $2

