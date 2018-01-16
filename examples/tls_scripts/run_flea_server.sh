#!/bin/sh

./build/flea-test --tls_server --own_certs=./misc/testdata/KEYSIZES_RSA_4096/KEYSIZES_RSA_4096_EE.TC.crt --own_ca_chain=./misc/testdata/KEYSIZES_RSA_4096/KEYSIZES_RSA_4096_SUB_CA.CA.crt,./misc/testdata/KEYSIZES_RSA_4096/KEYSIZES_RSA_4096_ROOT_CA.TA.crt --own_private_key=./misc/testdata/KEYSIZES_RSA_4096/KEYSIZES_RSA_4096_EE.pkcs8 --port=4444 --ip_addr=127.0.0.1 --hostname=localhost --allowed_sig_algs=SHA1-RSA,SHA224-RSA,SHA256-RSA,SHA384-RSA,SHA512-RSA --no_hostn_ver --reneg_mode=only_secure_reneg --rev_chk=none --stay
