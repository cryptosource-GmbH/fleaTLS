#!/bin/bash
#find test/ -name "*.c" | xargs -n1 rpl $1 $2
#find test/ -name "*.cpp" | xargs -n1 rpl $1 $2
#find test/ -name "*.h" | xargs -n1 rpl $1 $2
#find src/ -name "*.c" | xargs -n1 rpl $1 $2
#find include/ -name "*.h" | xargs -n1 rpl $1 $2
#find build_cfg/ -name "*.h" | xargs -n1 rpl $1 $2
#find examples/ -name "*.c" | xargs -n1 rpl $1 $2
#find examples/ -name "*.h" | xargs -n1 rpl $1 $2
find misc/doc/api_doc/pages/ -name "*.h" | xargs -n1 rpl $1 $2
#find misc/doc/api_doc/pages/ -name "*.dox" | xargs -n1 rpl $1 $2

