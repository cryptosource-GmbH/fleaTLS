#!/bin/bash

# change working directory to the script's path
BASEDIR=$(dirname "$0")
cd $BASEDIR

openssl s_server -accept 4444 -CAfile rootCA_1024.pem -key server_1024.key -cert server_1024.pem
