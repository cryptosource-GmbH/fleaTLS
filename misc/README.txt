
 __________________
 ***** cryptosource
 ******************
   Cryptography. Security.

 fleaTLS cryptographic library for embedded systems
 Copyright (C) 2015-2018 cryptosource GmbH


compilation
===========

In order to get easily started with flea, the library is shipped with a CMake
configuration to build it on standard Linux. The following describes the
installation on a Debian-based system.

Install the necessary prerequisites
  a. CMake
    $ apt-get install cmake
    $ apt-get install cmake-curses-gui
  b. asan (optional)

In the flea directory, the command sequence
  $ cmake .
  $ make 
builds the library and the unit tests.


In order to start the CMake GUI, where a number of configuration options can be
set, enter
  $ ccmake .

Here, besides the possibility to confige debug mode, AddressSanitizer (asan) and
American Fuzzy Lop (afl) can be configured. For more information on these
tools, visit

https://github.com/google/sanitizers/wiki/AddressSanitizer
http://lcamtuf.coredump.cx/afl/


running the tests
=================

In order to execute the unit tests, run the command
  $ ./build/flea-test


starting TLS server and client
==============================

example scripts to start the fleaTLS client or server as well as OpenSSL client
and server, are found in the folder examples/tls_scripts/ 


configuration of the libary
===========================

The build configuration of the library can be tweaked in the file build_cfg/general/build_config_gen.h


documentation
=============

The API documentation can be found at www.fleatls.com 
