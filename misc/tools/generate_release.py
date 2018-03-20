# -*- coding: iso-8859-1 -*-

import re
import os
import os.path
import glob
import sys
import shutil
import subprocess
import fileinput

include_dir = "../../include"
src_dir = "../../src"
test_dir = "../../test"
test_data_dir = "../testdata"
build_cfg_dir = "../../build_cfg"
#pltf_supp_dir = "../../pltf_support"
generate_dir = "../../../flea_generated_releases"
cmakelists_file = "../../CMakeLists.txt"
changelog_src_path = "../../misc/changelog.txt"
readme_src_path = "../../misc/README.txt"
examples_src_dir = "../../examples/"

license_name_gpl = "gpl"
license_name_closed_source = "flea"

def ignore_svn_function(a, b):
  result = []
  result.append(".svn")
  result.append("stm32f4")
  result.append("*.elf")
  result.append("*.map")
  result.append("*.swp")
  result.append("*~")
  result.append("makefile")
  return result



def collect_files_with_ending(ending, dir):
  result = []
  for root, dirs, files in os.walk(dir):
    for file in files:
      if file.endswith(ending):
        #print(os.path.join(root, file))
        result.append (os.path.join(root, file))
  return result

def generate_for_license(license_name, work_dir):
  #license_file_name = license_name + ".txt"
  license_notice_file_name = "../../misc/licenses/" + license_name + ".notice"
  license_notice_text = open(license_notice_file_name, 'r').read()
  #license__text = open(license_notice_file_name, 'r').read()
  #print "work_dir = " + work_dir 
  files = collect_files_with_ending(".h", work_dir+"/include")
  files += collect_files_with_ending(".c", work_dir+"/src")
  files += collect_files_with_ending(".c", work_dir+"/test")
  files += collect_files_with_ending(".cpp", work_dir+"/test")
  files += collect_files_with_ending(".h", work_dir+"/test")
  files += collect_files_with_ending(".h", work_dir+"/build_cfg")

  for file_name in files:
    #print "opening file " + file_name
    file = open(file_name, 'r').read()
  #
  #  new_file = re.sub(r'\/\*\*\*\*\*\*\*(.*?)________(.*?)conditions(.*?)\*\/', r'/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */', file,flags=re.DOTALL)
    new_file = re.sub(r'\/\* \#\#__FLEA_LICENSE_TEXT_PLACEHOLDER__\#\# \*\/', license_notice_text, file,flags=re.DOTALL)
    if(file == new_file):
        print ("error: file '" + file_name + "' does not contain a license placeholder")
        exit(1)
    new_file = re.sub(r'\/\/ ##__FLEA_UNCOMMENT_IN_RELEASE__## ', r'', new_file, flags=re.DOTALL)
    new_file = re.sub(r'\/\* ##__FLEA_COMMENT_OUT_IN_RELEASE__## \*\/', r'//', new_file, flags=re.DOTALL)

    #new_file = re.sub(r'__FLEA_LICENSE_TEXT_PLACEHOLDER__', license_text, file,flags=re.DOTALL)
    trgt_file =  open(file_name, 'w')
    for line in new_file:
      trgt_file.write("%s" % line)
    trgt_file.close()
    #print new_file

#print files

def generate_with_license(license_name, have_test_data):
  target_dir = generate_dir + "/" + license_name + "/"
  shutil.copytree(include_dir, generate_dir + "/" + license_name + "/flea/include", False, ignore_svn_function) 
  shutil.copytree(src_dir, generate_dir + "/" + license_name + "/flea/src", False, ignore_svn_function) 
  shutil.copytree(test_dir, generate_dir + "/" + license_name + "/flea/test", False, ignore_svn_function) 
  shutil.copytree(build_cfg_dir, generate_dir + "/" + license_name + "/flea/build_cfg", False, ignore_svn_function) 
  shutil.copytree(examples_src_dir, generate_dir + "/" + license_name + "/flea/examples") 
  for filename in os.listdir(generate_dir + "/" + license_name + "/flea/build_cfg/general"):
    if re.match("internal_*", filename):
      shutil.rmtree(generate_dir + "/" + license_name + "/flea/build_cfg/general/" + filename)
  myfile = fileinput.FileInput(generate_dir + "/" + license_name +
          "/flea/build_cfg/general/default/build_config_gen.h", inplace=True)
  for line in myfile:
      line = re.sub(r"// *FBFLAGS.*$", "", line)
      print (line, end = '')

  shutil.copy(cmakelists_file, generate_dir + "/" + license_name + "/flea")
 
  if(have_test_data):
    shutil.copytree(test_data_dir, target_dir + "/flea/misc/testdata", False, ignore_svn_function) 
    shutil.rmtree(target_dir + "/flea/misc/testdata/internal")
    cert_paths_dir_dst = target_dir + "/flea/misc/testdata/cert_paths/"
    for filename in os.listdir(cert_paths_dir_dst):
      if ((not re.match("fleasuite*", filename)) and (not re.match("CERT_PATH_*", filename)) ):
        shutil.rmtree(cert_paths_dir_dst + filename)
 
  flea_main_dir_dst_path = target_dir + "flea/"
  shutil.copy(changelog_src_path, flea_main_dir_dst_path )
  shutil.copy(readme_src_path, flea_main_dir_dst_path )
 
  license_file_path = "../../misc/licenses/" + license_name + ".txt"
  shutil.copy(license_file_path, generate_dir + "/" + license_name + "/flea/" + license_name + "_license.txt")

  #shutil.copy("../../misc/doc/flea_manual/flea_manual.pdf", generate_dir + "/" + license_name + "/flea/")
  generate_for_license(license_name, generate_dir+ "/" + license_name + "/flea")

have_test_data = True
#have_test_data = False
#if(len(sys.argv) == 2):
#    if(sys.argv[1] == "--with_testdata"):
#        have_test_data = True
#    else:
#        print "error: invalid commandline argument"
#        sys.exit(1)


#shutil.rmtree(generate_dir + "/" + license_name_gpl + "/" + "flea", True)
#shutil.rmtree(generate_dir + "/" + license_name_closed_source + "/" + "flea", True)
if os.path.exists(generate_dir):
  print ("deleted previous release dir")
  shutil.rmtree(generate_dir)

generate_with_license(license_name_gpl, have_test_data)
generate_with_license(license_name_closed_source, have_test_data)

