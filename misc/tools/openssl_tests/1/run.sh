#!/bin/sh

rm /tmp/cachain.pem
cat ../tls_test_tool/misc/test_data/cpt_tests/tls_client_and_server/CERT_PATH_COMMON_01/CERT_PATH_COMMON_01_ROOT_CA.TA.pem.crt >> /tmp/cachain.pem
echo "" >> /tmp/cachain.pem
cat ../tls_test_tool/misc/test_data/cpt_tests/tls_client_and_server/CERT_PATH_COMMON_01/CERT_PATH_COMMON_01_SUB_CA.CA.pem.crt >> /tmp/cachain.pem

openssl s_server -accept 4444 -CAfile /tmp/cachain.pem -key ../tls_test_tool/misc/test_data/cpt_tests/tls_client_and_server/CERT_PATH_COMMON_01/CERT_PATH_COMMON_01_EE.TC.pem.key -cert ../tls_test_tool/misc/test_data/cpt_tests/tls_client_and_server/CERT_PATH_COMMON_01/CERT_PATH_COMMON_01_EE.TC.pem.crt


