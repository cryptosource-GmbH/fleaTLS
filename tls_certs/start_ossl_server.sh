#!/bin/bash

# change working directory to the script's path
BASEDIR=$(dirname "$0")
cd $BASEDIR

openssl s_server -accept 4444 -CAfile rootCA.pem -key server.key -cert server.pem
