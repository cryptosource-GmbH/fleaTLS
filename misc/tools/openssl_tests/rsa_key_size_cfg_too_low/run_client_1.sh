valgrind --leak-check=full ./build/flea-test --tls_client --trusted=../tls_test_tool/misc/test_data/cpt_tests/tls_client_and_server/CERT_PATH_COMMON_01/CERT_PATH_COMMON_01_ROOT_CA.TA.crt --port=4444 --ip_addr=127.0.0.1 --hostname=localhost --allowed_sig_algs=SHA1-RSA,SHA224-RSA,SHA256-RSA,SHA384-RSA,SHA512-RSA --no_hostn_ver --reneg_mode=only_secure_reneg --rev_chk=none
