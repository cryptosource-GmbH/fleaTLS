/*! \mainpage Quickstart Manual
 *
 * <PRE>
 * __________________
 * ***** cryptosource
 * ******************
 *  Cryptography. Security.
 *
 * fleaTLS cryptographic library for embedded systems
 * Copyright (C) 2015-2018 cryptosource GmbH
 *
 * </PRE>
 *
 * - \subpage fleaTLSRestrictions "Restrictions of fleaTLS"
 *
 * - \subpage gettingStarted "Getting started with fleaTLS on Linux"
 *
 * - \subpage devolopWflea "Using fleaTLS in development projects"
 *
 */

/*! \page fleaTLSRestrictions Restrictions of fleaTLS
 *
 * fleaTLS supports the functionality for X.509 processing, but excludes some
 * features specified in RFC 5280, that are usually irrelevant to IoT and
 * industry applications.
 *
 * - X.509 Certificate Name Constraints Extension: The Name Constraints
 *   extension, which is typically used in complex heterogeneous PKIs only, can
 *   be used to restrict the set of names that Sub-CAs may issue certificate to.
 *   This extension is not supported by fleaTLS. If fleaTLS encounters an X.509
 *   certificate featuring a Name Constraints extension marked as critical, the
 *   certificate cannot be validated.
 * - Support for X.509 Certificate Policy Extensions: fleaTLS does not process
 *   X.509 Certificate Policy Extension. It ignores such extensions, even if
 *   they are marked as critical. Other policy-related X.509 certificate
 *   extensions, namely the Inhibit anyPolicy and Policy Constraints Extensions,
 *   lead to the rejection of the certificate if they are marked as critical.
 * - X.509 Freshest CRL Extension: This extension, which addresses Delta CRLs,
 *   is of almost no relevance even in the internet PKI. The presence of
 *   this extension marked as critical in an X.509 certificate also lead to the
 *   rejection of that certificate.
 *
 */

/*! \page gettingStarted Getting started with fleaTLS on Linux
 *
 * \section compileFlea Compilation
 * In order to get easily started with flea, the library is shipped with a CMake
 * configuration to build it on standard Linux. The following describes the
 * installation on a Debian-based system.
 *
 * Install CMake as a necessary prerequisite
 *  <PRE>
 *    $ apt-get install cmake
 *    $ apt-get install cmake-curses-gui
 *    </PRE>
 *
 * In the flea directory, the command sequence
 * <PRE>
 *  $ cmake .
 *  $ make
 *  </PRE>
 * builds the library and the unit tests.
 *
 *
 * In order to start the CMake GUI, where a number of configuration options can be
 * set, enter
 * <PRE>
 *  $ ccmake .
 *  </PRE>
 *
 * Here, besides the possibility to configure debug mode, AddressSanitizer (asan) and
 * American Fuzzy Lop (afl) can be configured. For more information on these
 * tools, visit
 * - https://github.com/google/sanitizers/wiki/AddressSanitizer
 * - http://lcamtuf.coredump.cx/afl/

\section runTests Running the tests

In order to execute the unit tests, run the command
<PRE>
  $ ./build/flea-test
  </PRE>


\section tlsTestTools Starting TLS server and client

Example scripts to start the fleaTLS client or server as well as OpenSSL client
and server as a counterpart for testing, are found in the folder examples/tls_scripts/ of the fleaTLS download package.

After compilation of the library and the test-application they can be invoked from the main directory of the flea package as
<PRE>

</PRE>
*/

/*! \page devolopWflea Using fleaTLS in development projects
*
* \section devCfg Configuration of the library

The build configuration of the library can be tweaked in the file build_cfg/general/build_config_gen.h
*/
