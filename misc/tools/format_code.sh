#!/bin/bash
find include/ -name "*.h" | xargs -n1 uncrustify -c misc/tools/uncrustify.cfg \
--no-backup --replace
find src/ -name "*.c" | xargs -n1 uncrustify -c misc/tools/uncrustify.cfg \
--no-backup --replace
find test/ -name "*.c" | xargs -n1 uncrustify -c misc/tools/uncrustify.cfg \
--no-backup --replace
