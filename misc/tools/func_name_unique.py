# -*- coding: iso-8859-1 -*-

import re
import os
import os.path
import glob
import sys
import shutil
import subprocess
import random

gl_compare_len = 31 # C99 for external symbols 

#ctags -R -x --c-types=f src/

def get_ctags_output():
  p = subprocess.Popen('ctags -R -x --c-types=f src/', shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
  #print("MAKE OUTPUT:")
  ctags_output = []
  for line in p.stdout.readlines():
    ctags_output.append(line)
    #print line,
  #for line in p.stderr.readlines():
    #print line,
  retval = p.wait()
  if(retval != 0):
    print "ctags error, exiting"
    exit(1)
  return ctags_output

def crop_ctags_output(ctags_output):
    result = []
    for i in range(len(ctags_output)):
        line = ctags_output[i]
        m = re.search ('^([A-Za-z0-9_]+)', line)
        if(not m):
            print("error with ctags file line = '" + line);
        func_name = m.group(1)
        result.append(func_name)
    return result
           
# [0:31]
# => pos 0 ... 30 => 31 positions
def get_function_collisions(func_name, func_names, index_of_func):
    result = []
    if(len(func_name) <= gl_compare_len):
        return [] 
    for i in range(len(func_names)):
        if(i == index_of_func):
            continue
        if(func_name[:gl_compare_len] == func_names[i][:gl_compare_len]):
            result.append(func_names[i])
    return result

def check_all_collisions(func_names):
    spaces = ""
    for i in range(gl_compare_len-1):
        spaces += " "
    for i in range(len(func_names)):
        colls = get_function_collisions(func_names[i], func_names, i)
        if(len(colls)):
            print("collisions for " + func_names[i] + ":")
            print("               " + spaces + "^")
            for i in range(len(colls)):
                print("  " + colls[i])

                




ctags_output = get_ctags_output()
func_names = crop_ctags_output(ctags_output)
check_all_collisions(func_names)


