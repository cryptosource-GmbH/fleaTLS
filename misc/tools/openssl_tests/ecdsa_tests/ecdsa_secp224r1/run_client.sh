#!/bin/sh

valgrind --leak-check=full ./build/flea-test --tls_client --trusted=misc/tools/openssl_tests/ecdsa_tests/ecdsa_secp224r1/certs/ECDSA_SECP224R1_ROOT_CA.TA.crt --port=4444 --ip_addr=127.0.0.1 --hostname=localhost --allowed_sig_algs=SHA1-ECDSA,SHA256-ECDSA,SHA1-RSA,SHA224-RSA,SHA256-RSA --no_hostn_ver --reneg_mode=only_secure_reneg --rev_chk=none
