#!/bin/bash
rm certs/*
for i in `seq 1 65000`;
#for i in `seq 1 1`;
do
	openssl req -x509 -sha224 -key key.pem -out certs/cert$i.der -days 365 -new -config ossl_conf -outform DER -subj "/C=UK/ST=fjladsf/L=testl/O=OrgName/OU=IT Department/CN=example.com"
done
