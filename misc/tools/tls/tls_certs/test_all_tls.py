import time

import re
import os
import os.path
import glob
import sys
import shutil
import subprocess

test_run_nr = 1

ossl_cwd = "."
ut_cwd = "."
ossl_script_dir = "./misc/tools/tls/tls_certs/"

global vg_err_count
vg_err_count = 0

def find_in_strings(lines, string_to_search):
    for line in lines:
        if(re.search(string_to_search, line.decode("utf-8"))):
            return True 
    return False

def print_string_array(lines):
    for line in lines:
        print (line)

def open_subprocess_valgrind(cmdl):
    return subprocess.Popen("valgrind --log-file=__vg.log --leak-check=full  --error-exitcode=10 --errors-for-leak-kinds=definite,indirect,possible,reachable " + cmdl, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=ut_cwd)
    #return subprocess.Popen("valgrind --error-exitcode=10 " + cmdl, shell=True, stdout=subprocess.PIPE)
    #return subprocess.Popen(cmdl, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=ut_cwd)

def close_valgrind_process(p, test_name):
    print("waiting for vg process to end")
    retval = p.wait()
    if(retval == 10):
        print("valgrind error(s) detected in test '" + test_name + "'")
        global vg_err_count 
        vg_err_count += 1
        os.rename("__vg.log", "vg.log")
        #return 0
    else:
        os.remove("__vg.log")

def test_flea_client_against_exernal_server(exp_pos_res, ext_start_script, flea_cmdl_args):
    global test_run_nr
    print ("\nTEST NR " + str(test_run_nr))
    test_run_nr += 1
    #p1 = subprocess.Popen('killall openssl', shell=True)
    #p2 = subprocess.Popen('killall unit_test', shell=True)
    #p1.wait()
    #p2.wait()
    result = 0
    p = subprocess.Popen(ossl_script_dir + "/" + ext_start_script, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=ossl_cwd)
    time.sleep(0.1)
    #p_test = subprocess.Popen('./build/unit_test --tls_client ' + flea_cmdl_args, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=ut_cwd)
    print("flea_client_vs_ext: opening vg process")
    p_test = open_subprocess_valgrind('./build/unit_test --tls_client ' + flea_cmdl_args)
    ut_output = []
    print("flea_client_vs_ext: waiting for output")
    for line in p_test.stdout.readlines():
        ut_output.append(line)
        # doesn't match so far
    if(not find_in_strings(ut_output, "tls test passed")):
        print_string_array(ut_output)
        if exp_pos_res:
            print ("== ERROR == with '" + ext_start_script + "'")
        #return 0 if not exp_pos_res else 1
        if(exp_pos_res):
            result = 1
    else:
        if(not exp_pos_res):
            result = 1

    #for line in p.stdout.readlines():
        #print line
    #retval = p_test.wait()
    try:
        p.kill()
    except OSError:
        printf("could not kill process")
    close_valgrind_process(p_test, ext_start_script)
    #p.kill()
    #return 0 if exp_pos_res else 1
    return result

def test_flea_server_against_external_client(exp_pos_res, ext_start_script, flea_cmdl_args):
    global test_run_nr
    print ("\nTEST NR " + str(test_run_nr))
    test_run_nr += 1
    #p1 = subprocess.Popen('killall openssl', shell=True)
    #p2 = subprocess.Popen('killall unit_test', shell=True)
    #p1.wait()
    #p2.wait()
    result = 0
    # running server under valgrind: it hangs at communicate or readlines
    p_flea = subprocess.Popen('./build/unit_test --tls_server ' + flea_cmdl_args, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=ut_cwd)
    print("flea_server vs ext client: opening vg process")
    #p_flea = open_subprocess_valgrind('./build/unit_test --tls_server ' + flea_cmdl_args)
    time.sleep(0.1)
    p_ossl = subprocess.Popen(ossl_script_dir + "/" + ext_start_script, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=ossl_cwd)
    print ("after p_ossl")
    #stdout_data = p_ossl.communicate(timeout=1, input='data_to_write')[0]
    #p_ossl.stdin.write(b'data_to_write\r\n')
    mydata_ossl = p_ossl.communicate()[0] 
    #print ("after ossl communicate")
    mydata_flea = p_flea.communicate()[0] 
    #print ("after flea communicate")
  
    flea_output = []
    #for line in p_flea.stdout.readlines():
    #    flea_output.append(line)
    ##for line in mydata_ossl:
    ##print ("read line ossl = " + mydata_ossl.decode("utf-8"))
    #print ("read line flea = " + mydata_flea.decode("utf-8"))
    flea_output.append(mydata_flea)
    ##for line in p_flea.stdout.readlines():
        ##print ("read line flea = " + line.decode("utf-8"))
        ##flea_output.append(line)
    if(not find_in_strings(flea_output, "handshake done")):
        print_string_array(flea_output)
        if exp_pos_res:
            print ("== ERROR == with '" + ext_start_script + "'")
        #return 0 if not exp_pos_res else 1
            result = 1
    else:
        if(not exp_pos_res):
            print ("== ERROR == with '" + ext_start_script + "'")
            result = 1
    #try: 
        #p_flea.kill()
    #except OSError:
        #print("could not kill process")
    try: 
        p_ossl.kill()
    except OSError:
        print("could not kill process")
    p_flea.wait()
    #return 0 if exp_pos_res else 1
    return result

def build_cmdl_242_for_server(test_name):
    test_crl_base_dir = "misc/tools/pki_tool_242/tls/output/"
    #test_name = "TLS_CRL_EE_UNREV"
    test_crl_ee_unrev_base_dir = test_crl_base_dir + "/" + test_name + "/"
    result = "--port=4444 --trusted=" + test_crl_ee_unrev_base_dir + test_name + "_ROOT_CA.TA.crt --own_ca_chain=" + test_crl_ee_unrev_base_dir + test_name + "_SUB_CA.CA.crt," + test_crl_ee_unrev_base_dir + test_name + "_ROOT_CA.TA.crt --own_certs="  + test_crl_ee_unrev_base_dir + test_name + "_EE.TC.crt --own_private_key=" + test_crl_ee_unrev_base_dir + test_name + "_EE.pkcs8"
    return result

def build_cmdl_242_for_client(test_name, use_ee_crl_bool):
    test_crl_base_dir = "misc/tools/pki_tool_242/tls/output/"
    #test_name = "TLS_CRL_EE_UNREV"
    test_crl_ee_unrev_base_dir = test_crl_base_dir + "/" + test_name + "/"
    result = "--port=4444 --ip_addr=127.0.0.1 --no_hostn_ver --trusted=" + test_crl_ee_unrev_base_dir + test_name + "_ROOT_CA.TA.crt --own_ca_chain=" + test_crl_ee_unrev_base_dir + test_name + "_SUB_CA.CA.crt," + test_crl_ee_unrev_base_dir + test_name + "_ROOT_CA.TA.crt --own_certs="  + test_crl_ee_unrev_base_dir + test_name + "_EE.TC.crt --own_private_key=" + test_crl_ee_unrev_base_dir + test_name + "_EE.pkcs8"
    if(use_ee_crl_bool == True):
        result += " --crls=" + test_crl_ee_unrev_base_dir + "/crls/" + test_name + "_SUB_CA_CRL.crl" + " --rev_chk=only_ee"
    return result

def test_flea_client_against_flea_server(exp_pos_res, test_name, use_ee_crl_bool ):
    global test_run_nr
    print ("\nTEST NR " + str(test_run_nr))
    test_run_nr += 1
    #p1 = subprocess.Popen('killall openssl', shell=True)
    #p2 = subprocess.Popen('killall unit_test', shell=True)
    #p1.wait()
    #p2.wait()
    result = 0
    server_cmdl = './build/unit_test --tls_server ' + build_cmdl_242_for_server(test_name) 
    print server_cmdl
    p_server = subprocess.Popen(server_cmdl, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=ut_cwd)
    #p = subprocess.Popen(ossl_script_dir + "/" + ext_start_script, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=ossl_cwd)
    time.sleep(0.1)
    client_cmdl = './build/unit_test --tls_client ' + build_cmdl_242_for_client(test_name, use_ee_crl_bool=use_ee_crl_bool) 
    print client_cmdl
    #p_test = subprocess.Popen(client_cmdl, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=ut_cwd)
    p_test = open_subprocess_valgrind(client_cmdl)
    ut_output = []
    for line in p_test.stdout.readlines():
        ut_output.append(line)
        # doesn't match so far
    if(not find_in_strings(ut_output, "tls test passed")):
        print_string_array(ut_output)
        if exp_pos_res:
            print ("== ERROR == with '" + test_name + "'")
            result = 1
    else:
        if(not exp_pos_res):
            result = 1
    try:
        p_server.kill()
    except OSError:
        print("could not kill process")
    #for line in p.stdout.readlines():
        #print line
    #retval = p_test.wait()
    close_valgrind_process(p_test, test_name)  
    print("retval from flea server")
    #p.kill()
    #return 0 if exp_pos_res else 1
    return result
   
std_server_args = "--trusted=misc/tools/tls/tls_certs/rootCA.der --own_certs=misc/tools/tls/tls_certs/server.der --own_private_key=./misc/tools/tls/tls_certs/server.pkcs8 --own_ca_chain=misc/tools/tls/tls_certs/rootCA.der --port=4444"
std_client_args = "--trusted=misc/tools/tls/tls_certs/rootCA.der --own_certs=misc/tools/tls/tls_certs/server.der --own_private_key=./misc/tools/tls/tls_certs/server.pkcs8 --own_ca_chain=misc/tools/tls/tls_certs/rootCA.der --port=4444 --ip_addr=127.0.0.1 --no_hostn_ver"

no_cert_client_args = "--trusted=misc/tools/tls/tls_certs/rootCA.der --port=4444 --ip_addr=127.0.0.1 --no_hostn_ver"
no_req_cert_server_args = "--own_certs=misc/tools/tls/tls_certs/server.der --own_private_key=./misc/tools/tls/tls_certs/server.pkcs8 --own_ca_chain=misc/tools/tls/tls_certs/rootCA.der --port=4444"

#test_crl_ee_unrev_client_cmdl = "--port=4444 --ip_addr=127.0.0.1 --no_hostn_ver --trusted=" + test_crl_ee_unrev_base_dir + test_name + "_ROOT_CA.TA.crt --own_ca_chain=" + test_crl_ee_unrev_base_dir + test_name + "_SUB_CA.CA.crt," + test_crl_ee_unrev_base_dir + test_name + "_ROOT_CA.TA.crt --own_certs="  + test_crl_ee_unrev_base_dir + test_name + "_EE.TC.crt --own_private_key=" + test_crl_ee_unrev_base_dir + test_name + "_EE.pkcs8"

error_cnt = 0
# tests splitted in groups of 5 to easily match the test number in the output with the actual test
error_cnt += test_flea_client_against_flea_server(False, 'TLS_CRL_EE_REV',use_ee_crl_bool=True)
error_cnt += test_flea_client_against_flea_server(True, 'TLS_CRL_NO_CRL',use_ee_crl_bool=False)
error_cnt += test_flea_client_against_flea_server(True, 'TLS_CRL_EE_UNREV',use_ee_crl_bool=True)
error_cnt += test_flea_server_against_external_client(True, 'start_ossl_client_w_cert.sh', std_server_args) # doesn't work after the 'ossl=server' tests
error_cnt += test_flea_server_against_external_client(True, 'start_ossl_client_gcm_w_cert.sh', std_server_args) 

error_cnt += test_flea_server_against_external_client(True, 'start_ossl_client.sh', no_req_cert_server_args + " --cipher_suites=TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA")
error_cnt += test_flea_server_against_external_client(True, 'start_ossl_client_cbc_w_cert.sh', std_server_args)
error_cnt += test_flea_client_against_exernal_server(True, 'start_ossl_server_request_cert.sh', std_client_args)
error_cnt += test_flea_client_against_exernal_server(True, 'start_ossl_server.sh', std_client_args)
error_cnt += test_flea_client_against_exernal_server(True, 'start_ossl_server_gcm.sh', std_client_args + " --cipher_suites=TLS_RSA_WITH_AES_128_GCM_SHA256" )

error_cnt += test_flea_client_against_exernal_server(True, 'start_ossl_server_cbc.sh', std_client_args + " --cipher_suites=TLS_RSA_WITH_AES_128_CBC_SHA")
error_cnt += test_flea_client_against_exernal_server(True, 'start_ossl_server.sh', std_client_args + " --cipher_suites=TLS_RSA_WITH_AES_256_GCM_SHA384")
error_cnt += test_flea_client_against_exernal_server(False, 'start_ossl_server_request_cert.sh', no_cert_client_args)
error_cnt += test_flea_client_against_exernal_server(True, 'start_ossl_server.sh', std_client_args + " --cipher_suites=TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA")




#print("first 2 passed")
#out##error_cnt += test_flea_client_against_exernal_server('start_ossl_client.sh') // does not work so far
print ("there were " + str(error_cnt) + " failed tests")

print ("there were " + str(vg_err_count) + " valgrind errors")
#subprocess.Popen('killall openssl', shell=True)

subprocess.Popen('killall openssl', shell=True).wait()
subprocess.Popen('killall unit_test', shell=True).wait()

if(error_cnt > 0 or vg_err_count > 0):
    sys.exit(23)
