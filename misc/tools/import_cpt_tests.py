#!/usr/bin/python

import sys
import os
import subprocess
import shutil
from optparse import OptionParser

def get_immediate_subdirectories(a_dir):
    return [name for name in os.listdir(a_dir)
            if os.path.isdir(os.path.join(a_dir, name))]

def get_immediate_subdirectory_paths(a_dir):
    return [os.path.join(a_dir, name) for name in os.listdir(a_dir)
        if os.path.isdir(os.path.join(a_dir, name))]

def get_file_paths_in_dir(a_dir):
    return [a_dir + "/" + name for name in os.listdir(a_dir)
            if os.path.isfile(os.path.join(a_dir, name))]

parser = OptionParser()

parser.add_option("-t", "--test_case_dir", dest="test_cases_dir", 
        help="directory containing all the test cases to process as subdirs",
        metavar = "TEST_CASES_DIR")

parser.add_option("-o", "--output_main_dir", dest="output_main_dir",
        help="main output directory in which the test case directories are created",
        metavar = "DIR")

parser.add_option("-i", "--test_ini_template", dest="test_ini_tmpl",
        help="path to a template for test.ini file which is placed into each newly created test directory",
        metavar = "FILE")


(options, args) = parser.parse_args()
if not options.test_cases_dir or not options.output_main_dir or not options.test_ini_tmpl:
    parser.print_help()
    parser.error("missing arguments") 

src_dirs = get_immediate_subdirectories(options.test_cases_dir)
for test_name in src_dirs:
    src_dir_path = options.test_cases_dir + "/" + test_name 
    src_files = get_file_paths_in_dir(src_dir_path)
    new_dir = options.output_main_dir + "/" + test_name
    if(os.path.exists(new_dir)):
        print "error: output directory '" + new_dir + "' already exists"
        exit(1)
    os.mkdir(new_dir)
    crl_dir = new_dir + "/crls"
    certs_dir = new_dir + "/certs"
    trgt_cert_dir = new_dir + "/target_cert"
    ta_dir = new_dir + "/trust_anchors" 
    os.mkdir(certs_dir)
    os.mkdir(trgt_cert_dir)
    os.mkdir(ta_dir)

    src_crl_dir = src_dir_path + "/crls"
    #print "crl-src-path = " + src_crl_dir
    #src_crls_files = []
    if(os.path.exists(src_crl_dir)):
        #print "crl-src-path exists"
        os.mkdir(crl_dir)
        src_crls_files = get_file_paths_in_dir(src_crl_dir)
        for src_crl in src_crls_files:
            if(str(src_crl).endswith(".crl") and (not str(src_crl).endswith(".pem.crl"))):
                #print "processing crl file = " + src_crl
                shutil.copy(src_crl, crl_dir)
    for src_file in src_files:
        #print "processing file = " + src_file

        if(str(src_file).endswith(".CA.crt")):
            shutil.copy(src_file, certs_dir)
            #print "  copying file"
        if(str(src_file).endswith(".TC.crt")):
            shutil.copy(src_file, trgt_cert_dir)
        if(str(src_file).endswith(".TA.crt")):
            shutil.copy(src_file, ta_dir)
    shutil.copy(options.test_ini_tmpl, new_dir)
