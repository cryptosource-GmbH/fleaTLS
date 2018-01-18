#!/bin/sh

openssl s_client -connect 127.0.0.1:4444 -CAfile ./misc/testdata/KEYSIZES_RSA_4096/KEYSIZES_RSA_4096_ROOT_CA.TA.pem.crt
