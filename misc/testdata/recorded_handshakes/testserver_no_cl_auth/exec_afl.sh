#!/bin/bash
afl-fuzz -m 1000 -i misc/testdata/recorded_handshakes/testserver_no_cl_auth/server_hs_tec1/rec1/ -o afl_out_fleaclient/ ../flea/build/unit_test-asan --tls_client --trusted=/home/fstrenzke/Dokumente/dev/tls_test_tool/build/.././misc/test_data/rsa_default/rootCA.der --port=4449 --ip_addr=127.0.0.1 --hostname=localhost --stay --no_hostn_ver  --reneg_mode=no_reneg --rev_chk=none --deterministic --stream_input_file_dir=misc/testdata/recorded_handshakes/testserver_no_cl_auth/server_hs_tec1/all --path_rpl_stdin=hs_1__rec_1
