#!/bin/sh

rm /tmp/cachain.pem
cat ../tls_test_tool/misc/test_data/cpt_tests/tls_client_and_server/KEYSIZES_RSA_4096/KEYSIZES_RSA_4096_ROOT_CA.TA.pem.crt >> /tmp/cachain.pem
echo "" >> /tmp/cachain.pem
cat ../tls_test_tool/misc/test_data/cpt_tests/tls_client_and_server/KEYSIZES_RSA_4096/KEYSIZES_RSA_4096_SUB_CA.CA.pem.crt >> /tmp/cachain.pem

openssl s_server -accept 4444 -CAfile /tmp/cachain.pem -key ../tls_test_tool/misc/test_data/cpt_tests/tls_client_and_server/KEYSIZES_RSA_4096/KEYSIZES_RSA_4096_EE.TC.pem.key -cert ../tls_test_tool/misc/test_data/cpt_tests/tls_client_and_server/KEYSIZES_RSA_4096/KEYSIZES_RSA_4096_EE.TC.pem.crt
