# -*- coding: iso-8859-1 -*-

import re
import os
import os.path
import glob
import sys
import shutil
import subprocess
import random


# open: make a first run w/o valgrind, then a run with valgrind
# open: support for a value range for normal flags
# open: keep FBFLAGS comments in produced header file so that it can be reused
# by the script

#build_config_file_str = "../../../include/internal/common/build_config.h"
build_config_file_str = "../../../build_cfg/general/default/build_config_gen.h"
#build_config_file_save_str = "../../../include/internal/common/build_config.h__orig"
build_config_file_save_str = "../../../build_cfg/general/default/build_config_gen.h__orig"
make_cwd_str = "../../../"
#build_config_file_str = "include/internal/common/build_config.h"
#build_config_file_save_str = "include/internal/common/build_config.h__orig"
#make_cwd_str = "."

#normal_var_concrete_lists = []
#normal_var_index = 0
#normal_var_max = 0

flag_combinations_groups = []
flag_combinations = []
range_lists = []
range_defs = []
range_comment = []
concrete_flag_combinations = []

def clearGlobals():
  global flag_combinations_groups 
  global flag_combinations 
  global range_lists
  global range_defs
  global concrete_flag_combinations 
  global range_comment
  flag_combinations_groups = []
  flag_combinations = []
  range_lists = []
  range_defs = []
  range_comment = []
  concrete_flag_combinations = []

do_exec_valgrind = True 

def print_combinations():
  counter = 0
  for item in flag_combinations_groups:
    print "group " + item
    for item2 in flag_combinations[counter]:
      #print ', '.join(item2)
      print "  " + item2
    counter += 1
  

def add_flag_to_combinations(flag_with_define, group_name):
  global flag_combinations_groups
  global flag_combinations
  #print "adding to combinations: text = " + flag_with_define + ", group = " + group_name 
  counter = 0
  did_find = False
  for item in flag_combinations_groups:
    if item == group_name:
      flag_combinations[counter].append(flag_with_define)
      did_find = True
    counter += 1
  if(did_find == False):
    new_list = [flag_with_define] 
    flag_combinations.append(new_list)
    flag_combinations_groups.append(group_name)
  #print "combinations after adding:"
  ##print_combinations()
 

def determine_max_comb_len(list):
  max = 0
  for item in list:
    if (len(item) > max):
      max = len(item)
  for rlist in range_lists:
    if(len(rlist) > max):
      max = len(rlist)
  return max

def make_core_flag_list():
 #global normal_var_concrete_lists
 #global normal_var_index
 #global normal_var_max
 global range_lists
 global range_defs
 global range_comment
 result_list = []
 result_file = []
 with open(build_config_file_str) as f:
   lines = f.readlines()
 for line in lines:
   #print line
   m = re.search('FBFLAGS_([A-Za-z0-9]+)_ON_OFF', line)
   m_val_list = re.search('FBFLAGS__INT_LIST', line)
   #m_norm = re.search('NORMAL_ON_OFF', line)
   #m = re.search("abc", "abcde")
   if(m):
     #print "found line with flag:" + m.group(0)
     #print "belongs to group " + m.group(1)
     #print "in line: " + line
     m2 = re.search('#\s*define\s+([A-Za-z0-9_]+)', line)
     if(m2):
      name = m2.group(1)
      #print("found name = " + name)
      #add_flag_to_combinations(m2.group(0), m.group(1))
      # remove potentially leading "//" from line
      cm = re.search('\s*//\s*(#.*)', line);
      if(cm):
        add_flag_to_combinations(cm.group(1) + "\n", m.group(1))
      else:
        add_flag_to_combinations(line, m.group(1))
     else:
      print "error, could not find flag name"
      exit(1)
   elif(m_val_list):
     #m2 = re.search('(#define\s+([A-Za-z0-9_]+))\s+(([0-9]+)\s+)(//[.*]+)', line)
     m2 = re.search('(#\s*define\s+([A-Za-z0-9_]+))\s+[0-9]+\s+(//\s*([A-Za-z0-9_]+)\s+([0-9 ]+))', line)
     if(m2):
      vals = m2.group(5)
      #print "vals = " + vals
      vlist = vals.split() 
      #print "appending to range_lists: " + str(vlist)
      range_lists.append(vlist) 
      name = m2.group(1)
      #print("found int list name = " + name)
      #add_flag_to_combinations(m2.group(0), m.group(1))
      # remove potentially leading "//" from line
      #cm = re.search('\s*//\s*(#.*)', line);
      #if(cm):
      #print "appending to range_defs: " + m2.group(1)
      range_defs.append(m2.group(1))
      #print "appending to range_comment: " + m2.group(3)
      range_comment.append(m2.group(3))
      #else:
      #  range_defs.append(line)
     else:
      print "error, could not find int list name"
      exit(1)
   else:
      #print "appending line to result file: " + line
      result_file.append(line)
 #normal_var_max = determine_normal_var_max_list_len(normal_var_concrete_lists)
 #print "normal_var_max = " + str(normal_var_max)
 return result_file
     # now find the 
   #print m.group(0)

def parse_make_output(make_output):
  warnings = []
  for line in make_output:
    if(re.search("Warning", line) or re.search("Warnung", line)):
      warnings.append(line)
  return warnings
  
def call_make():
  make_output = []
  p = subprocess.Popen('make -j4', shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=make_cwd_str)
  #print("MAKE OUTPUT:")
  for line in p.stdout.readlines():
    make_output.append(line)
    #print line,
  #for line in p.stderr.readlines():
    #print line,
  retval = p.wait()
  if(retval != 0):
    print "build error, exiting"
    exit(1)
  warnings = parse_make_output(make_output)
  if(len(warnings)):
    p = subprocess.Popen('touch ' + build_config_file_str, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=make_cwd_str)
    retval = p.wait()
    print("warnings in build: ")
    for line in warnings:
      print line
    exit(1)
  

def call_test():
  p = subprocess.Popen('./build/flea-test', shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=make_cwd_str)
  #print("Test OUTPUT:")
  test_output = []
  for line in p.stdout.readlines():
    test_output.append(line)
  retval = p.wait()
  if(retval != 0):
    print "test error (random test), test output = "
    print "=======================================>"
    print "=======================================>"
    print "=======================================>"
    for line in test_output:
        print line
    print "<======================================="
    print "<======================================="
    print "<======================================="
    print ""
    print "test error (random test), exiting"
    exit(1) 

def parse_vg_output__no_leaks(vg_output):
  no_leaks_text_found = False
  no_leaks_text = "All heap blocks were freed -- no leaks are possible"
  ctr = 0
  for line in vg_output:
    if(ctr == len(vg_output) - 4):
      if(re.search(no_leaks_text, line)):
        no_leaks_text_found = True
    ctr = ctr+1
  return no_leaks_text_found;
   
   

def call_test_vg():
  vg_output = []
  p = subprocess.Popen('valgrind --error-exitcode=10 --leak-check=full --errors-for-leak-kinds=definite,indirect,possible,reachable ./build/flea-test', shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=make_cwd_str)
  #print("VG Test OUTPUT:")
  for line in p.stdout.readlines():
    vg_output.append(line)
  #for line in p.stderr.readlines():
    #print line,
  retval = p.wait()
  if(retval != 0):
    print "vg error, exiting"
    exit(1) 
  #if(False == parse_vg_output__no_leaks(vg_output)):
  #  print("memory leak detected")
  #  exit(1)
  

def iterate_through_configs_with_build_and_tests(stripped_file, concrete_flag_val_list):
 #global normal_var_index
 max_combination_len = determine_max_comb_len(concrete_flag_val_list)
 #print "build_config_file: lines in stripped_file", len(stripped_file)
 #print "max max_comb_len = " + str(max_combination_len)
 for i in range (0, max_combination_len):
   print "testing configuration " + str(i+1) + " of " + str(max_combination_len)
   new_file = [] 
   for line in stripped_file:
     #print "processing line of stripped file: " + line
     if (re.search('#\s*define _flea_build_cfg_gen__H_', line)):
       #print "found insertion tag for flag values"
       new_file.append(line)
       new_file.append("\n")
       for group in concrete_flag_val_list:
         #print "len of group = " + str(len(group))
         index = i
         if(i >= len(group)):
           # if all systematic combinations in that group have been exhausted,
           # choose a random entry
           index = random.randint(0, len(group)-1)
         for comb_set in group[index]:
           #print "comb_set = " + comb_set
           new_file.append(comb_set)
           #for el in comb_set:
             #print "appending element= " + el
             #new_file.append(el)
         #new_file.append(flag)
         #print("setting flag: " + flag)
       #print("done setting core flags\n\n")
       cnt = 0 
       for int_name in range_defs:
         index = i
         if(index >= len(range_lists[cnt])):
           index = random.randint(0, len(range_lists[cnt])-1)
         #print "index = " + str(index)
         #print "cnt = " + str(cnt)
         new_line = int_name + " " +  range_lists[cnt][index] + " " + range_comment[cnt] + "\n"
         cnt = cnt+1
         #print "making int list line = " + new_line
         new_file.append(new_line)
     else:
       # just copy normal lines:
       new_file.append(line)
       trgt_file =  open(build_config_file_str, 'w')
   #print "writing build config file" 
   for line in new_file:
    trgt_file.write("%s" % line)
   trgt_file.close()
   call_make()
   call_test()
   if do_exec_valgrind: 
     call_test_vg()
  

def print_concrete_configs_part(list):
  #print "concrete configurations: "
  for item in list:
    print "--"
    for item2 in item:
      print "  " + item2

def build_concrete_configs_for_one_group(core_flag_list, flag_index, tmp_flag_list, concrete_flag_val_list):
  #print("entering build_and_test_core_config() with flag_idx = ", flag_index, "core_flag_list = ", core_flag_list)
  # randomize on/off s.th. we get different combinations through parallelization
  # each time
  rnd = random.randint(0, 1)
  #print "randint = " + str(rnd)
  on_or_off_1 = ""
  on_or_off_2 = "//"
  if(rnd == 1):
    on_or_off_1 = "//"
    on_or_off_2 = ""
  copy1_concrete_list = list(tmp_flag_list)
  copy1_concrete_list.append(on_or_off_1 + core_flag_list[flag_index] + "\n")
  copy2_concrete_list = list(tmp_flag_list)
  copy2_concrete_list.append(on_or_off_2 + core_flag_list[flag_index] + "\n")
  if(flag_index == len(core_flag_list) - 1):
    #print("this is the last flag idx, calling the build function")
    #build_config_file_and_build_and_exec_test(stripped_file, copy1_concrete_list)
    #build_config_file_and_build_and_exec_test(stripped_file, copy2_concrete_list)
    concrete_flag_val_list.append(list(copy1_concrete_list))   
    concrete_flag_val_list.append(list(copy2_concrete_list))   
    #print "concrete_flag_val_list after appending both = " 
    #print_concrete_configs_part(concrete_flag_val_list)
  else:
    #for flag in core_flag_list:
    #print("not the last index, appending further flag choices")
    build_concrete_configs_for_one_group(core_flag_list, flag_index+1, copy1_concrete_list, concrete_flag_val_list)
    build_concrete_configs_for_one_group(core_flag_list, flag_index+1, copy2_concrete_list, concrete_flag_val_list)


def print_concrete_configs():
  print "concrete configurations: "
  for item in concrete_flag_combinations:
    print "--"
    for item2 in item:
      print item2

def build_concrete_configs_for_all_groups():
  global concrete_flag_combinations
  for item in flag_combinations:
    new_list = []
    build_concrete_configs_for_one_group(item, 0, list(), new_list)
    #print "appending list: "
    #print_concrete_configs_part(new_list)
    concrete_flag_combinations.append(new_list)

def build_variants_and_test():
  global do_exec_valgrind
  iters = 1
  if len(sys.argv) > 1:
    iters = int(sys.argv[1])
  if len(sys.argv) > 2 and sys.argv[2] == "no_vg":
    print "not using valgrind"
    do_exec_valgrind = False
  else:
    print "using valgrind"
  if( not os.path.exists(build_config_file_save_str)):
    shutil.copy(build_config_file_str, build_config_file_save_str)
    print "backup file of build_config_gen.h created" 
  else:
    print "backup file of build_config_gen.h already exists" 
  for i in range(iters):
    print "iter " + str(i+1) + " of " + str(iters)
    clearGlobals()
    # find the core flags    
    stripped_file = make_core_flag_list()
    #print "stripped file = " + '\n'.join(stripped_file)
    build_concrete_configs_for_all_groups()
    #print_concrete_configs()
    #exit(0)
    #print "norm_var max len = " + str(normal_var_max)
    #print "norm var names: " + ', '.join(normal_var_names_list)
    #for item in normal_var_concrete_lists:
    #  print "norm var vals: " + ', '.join(item)
    #stripped_file = stripped_file_and_flag_list['file_wo_core_flags'];
    #flag_list = stripped_file_and_flag_list['flag_list'];
    iterate_through_configs_with_build_and_tests(stripped_file, concrete_flag_combinations)
    #if(len(flag_list) == 0):
    #  print("no core flags found, exiting")
    #  exit(0)
    #exit(1) # TODO:REMOVE THIS LINE
    #build_core_configs(stripped_file, flag_list, 0, list())
    #while normal_var_index < normal_var_max:
    #  build_and_test_core_config(stripped_file, flag_list, 0, list())
  shutil.move(build_config_file_save_str, build_config_file_str)
  # doesn't seem to work!!:
  p = subprocess.Popen('touch ' + build_config_file_str , shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=make_cwd_str)
  call_make() # restore original build
  call_test() # test original build
  print "completed without errors, original build_config_gen.h restored" 

build_variants_and_test()

  
