import time

import re
import os
import os.path
import glob
import sys
import shutil
import subprocess

ossl_cwd = "."
ut_cwd = "."
ossl_script_dir = "./misc/tools/tls/tls_certs/"

def find_in_strings(lines, string_to_search):
    for line in lines:
        if(re.search(string_to_search, line.decode("utf-8"))):
            return True 
    return False

def print_string_array(lines):
    for line in lines:
        print (line)

def test_flea_client_against_exernal_server(ext_start_script):
    p = subprocess.Popen(ossl_script_dir + "/" + ext_start_script, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=ossl_cwd)
    time.sleep(1)
    p_test = subprocess.Popen('./build/unit_test --tls_client', shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=ut_cwd)
    ut_output = []
    for line in p_test.stdout.readlines():
        ut_output.append(line)
        # doesn't match so far
    if(not find_in_strings(ut_output, "tls test passed")):
        print_string_array(ut_output)
        print ("error with '" + ext_start_script + "'")
        p.kill()
        return 1 
    #for line in p.stdout.readlines():
        #print line
    retval = p_test.wait()
    p.kill()
    return 0

def test_flea_server_against_external_client(ext_start_script, flea_cmdl_args):
    subprocess.Popen('killall openssl', shell=True)
    p_flea = subprocess.Popen('./build/unit_test --tls_server ' + flea_cmdl_args, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=ut_cwd)
    time.sleep(1)
    p_ossl = subprocess.Popen(ossl_script_dir + "/" + ext_start_script, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=ossl_cwd)
    print ("after p_ossl")
    #stdout_data = p_ossl.communicate(timeout=1, input='data_to_write')[0]
    #p_ossl.stdin.write(b'data_to_write\r\n')
    mydata_ossl = p_ossl.communicate()[0] 
    mydata_flea = p_flea.communicate()[0] 
    #print ("stdout_data = " + stdout_data)
    flea_output = []
    #for line in p.stdout.readlines():
    #for line in mydata_ossl:
    #print ("read line ossl = " + mydata_ossl.decode("utf-8"))
    print ("read line flea = " + mydata_flea.decode("utf-8"))
    flea_output.append(mydata_flea)
    #for line in p_flea.stdout.readlines():
        #print ("read line flea = " + line.decode("utf-8"))
        #flea_output.append(line)
    if(not find_in_strings(flea_output, "handshake done")):
        print_string_array(flea_output)
        print ("error with '" + ext_start_script + "'")
        p_flea.kill()
        p_ossl.kill()
        return 1 
    #p_flea.kill()
    #p_ossl.kill()
    return 0
   
std_certs_args = "--trusted=misc/tools/tls/tls_certs/rootCA.der --own_certs=misc/tools/tls/tls_certs/server.der --own_private_key=./misc/tools/tls/tls_certs/server.pkcs8 --own_ca_chain=misc/tools/tls/tls_certs/rootCA.der --port=4444"

error_cnt = 0
error_cnt += test_flea_server_against_external_client('start_ossl_client_w_cert.sh', std_certs_args) # doesn't work after the 'ossl=server' tests
error_cnt += test_flea_server_against_external_client('start_ossl_client_gcm_w_cert.sh', std_certs_args) 
error_cnt += test_flea_server_against_external_client('start_ossl_client_cbc_w_cert.sh', std_certs_args)
error_cnt += test_flea_client_against_exernal_server('start_ossl_server_request_cert.sh')
error_cnt += test_flea_client_against_exernal_server('start_ossl_server.sh')
error_cnt += test_flea_client_against_exernal_server('start_ossl_server_gcm.sh')
error_cnt += test_flea_client_against_exernal_server('start_ossl_server_cbc.sh')


#print("first 2 passed")
#out##error_cnt += test_flea_client_against_exernal_server('start_ossl_client.sh') // does not work so far
print ("there were " + str(error_cnt) + " failed tests")
subprocess.Popen('killall openssl', shell=True)
