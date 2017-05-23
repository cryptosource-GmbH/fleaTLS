#!/bin/bash

BASEDIR=$(dirname "$0")
cd $BASEDIR

openssl s_client -connect 127.0.0.1:4444 -CAfile rootCA.pem -cipher AES128-GCM-SHA256 -cert server.pem -key server.key
