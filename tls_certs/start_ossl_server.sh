#!/bin/bash
openssl s_server -accept 4444 -CAfile rootCA.pem -key server.key -cert server.pem
