#!/bin/sh

openssl s_client -connect 127.0.0.1:4444 -CAfile ../tls_test_tool/misc/test_data/cpt_tests/tls_client_and_server/KEYSIZES_RSA_1024_valid/KEYSIZES_RSA_1024_ROOT_CA.TA.crt
