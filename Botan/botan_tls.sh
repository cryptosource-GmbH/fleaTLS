#!/usr/bin/env bash

BASEDIR=$(dirname "$0")

cd $BASEDIR
cd ../Botan
./botan tls_server ../tls_certs/server.pem ../tls_certs/server.pkcs8 --port=4445
