#!/bin/bash

# change working directory to the script's path
BASEDIR=$(dirname "$0")
cd $BASEDIR

openssl s_server -accept 4444 -CAfile rootCA_ecdsa.pem -key server_ecdsa.key -cert server_ecdsa.pem
