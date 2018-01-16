#!/bin/sh

cat ./misc/testdata/KEYSIZES_RSA_4096/KEYSIZES_RSA_4096_ROOT_CA.TA.pem.crt > /tmp/cachain.pem
echo "" >> /tmp/cachain.pem
cat ./misc/testdata/KEYSIZES_RSA_4096/KEYSIZES_RSA_4096_SUB_CA.CA.pem.crt >> /tmp/cachain.pem

openssl s_server -accept 4444 -CAfile /tmp/cachain.pem -key ./misc/testdata/KEYSIZES_RSA_4096/KEYSIZES_RSA_4096_EE.TC.pem.key -cert ./misc/testdata/KEYSIZES_RSA_4096/KEYSIZES_RSA_4096_EE.TC.pem.crt
