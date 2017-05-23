#!/bin/bash

# change working directory to the script's path
BASEDIR=$(dirname "$0")
cd $BASEDIR

#openssl s_client -connect 127.0.0.1:4444 -CAfile rootCA.pem -cipher AES128-SHA256 -cert server.pem -key server.key
openssl s_client -connect 127.0.0.1:4444 -CAfile rootCA.pem -cert server.pem -key server.key
