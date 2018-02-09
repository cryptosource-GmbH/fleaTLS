#!/bin/sh

./build/flea-test --tls_client --trusted=./misc/testdata/KEYSIZES_RSA_4096/KEYSIZES_RSA_4096_ROOT_CA.TA.crt --port=4444 --ip_addr=127.0.0.1 --hostname=localhost --allowed_sig_algs=SHA256-ECDSA,SHA256-RSA,SHA1-RSA,SHA224-RSA,SHA1-ECDSA --no_hostn_ver --reneg_mode=only_secure_reneg --rev_chk=none
