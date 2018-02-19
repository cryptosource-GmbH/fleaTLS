#!/bin/sh

rm /tmp/cachain.pem
cat misc/tools/openssl_tests/ecdsa_tests/ecdsa_secp160r1/certs/ECDSA_SECP160R1_ROOT_CA.TA.pem.crt >> /tmp/cachain.pem
echo "" >> /tmp/cachain.pem
cat misc/tools/openssl_tests/ecdsa_tests/ecdsa_secp160r1/certs/ECDSA_SECP160R1_SUB_CA.CA.pem.crt >> /tmp/cachain.pem

openssl s_server -accept 4444 -CAfile /tmp/cachain.pem -key misc/tools/openssl_tests/ecdsa_tests/ecdsa_secp160r1/certs/ECDSA_SECP160R1_EE.TC.pem.key -cert misc/tools/openssl_tests/ecdsa_tests/ecdsa_secp160r1/certs/ECDSA_SECP160R1_EE.TC.pem.crt
