#!/bin/bash
find include -name "*.h" | xargs -n1 sed -i -e '1h;2,$H;$!d;g' -re 's/(THR_[^)]+\)) *;/\1 FLEA_ATTRIB_UNUSED_RESULT;/g'
