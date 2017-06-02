#!/bin/bash

BASEDIR=$(dirname "$0")
cd $BASEDIR

valgrind --leak-check=full ../../../../build/unit_test --tls_server --trusted=rootCA.der --own_certs=server.der --own_private_key=server.pkcs8 --own_ca_chain=rootCA.der --port=4444 &
pid=$!
sleep 1
./start_ossl_client_gcm_w_cert.sh
kill $pid
valgrind --leak-check=full ../../../../build/unit_test --tls_server --trusted=rootCA.der --own_certs=server.der --own_private_key=server.pkcs8 --own_ca_chain=rootCA.der --port=4444 &
pid=$!
sleep 1
./start_ossl_client_cbc_w_cert.sh
kill $pid
