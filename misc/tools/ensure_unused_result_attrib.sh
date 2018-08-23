#!/bin/bash
#find include -name "*.h" | xargs -n1 sed -i -e '1h;2,$H;$!d;g' -re 's/(THR_[^)]+\)) *;/\1 FLEA_ATTRIB_UNUSED_RESULT;/g'
shopt -s globstar
for i in include/**/*.h; do # Whitespace-safe and recursive
    mod_file=${i}_eura
    sed -e '1h;2,$H;$!d;g' -re 's/(THR_[^)]+\)) *;/\1 FLEA_ATTRIB_UNUSED_RESULT;/g' $i > $mod_file
    #echo diff $i $mod_file
    diff $i $mod_file > /dev/null 2>&1
    do_differ=$?
    #echo differ = $do_differ
    if [ $do_differ != 0 ]; then 
      cp $mod_file $i
    fi
    rm $mod_file
done
