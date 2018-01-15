#!/bin/sh

valgrind --leak-check=full ./build/unit_test --tls_client --trusted=../tls_test_tool/misc/test_data/cpt_tests/tls_client_and_server/KEYSIZES_RSA_4096_valid/KEYSIZES_RSA_4096_ROOT_CA.TA.crt --port=4444 --ip_addr=127.0.0.1 --hostname=localhost --allowed_sig_algs=SHA1-RSA,SHA224-RSA,SHA256-RSA,SHA384-RSA,SHA512-RSA --no_hostn_ver --reneg_mode=only_secure_reneg --rev_chk=none --allowed_curves=secp192r1
