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
 * - \subpage fleaApi "About fleaTLS' API"
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
 *   be used to restrict the set of names that Sub-CAs may issue certificates to. The corresponding restriction are reflected by the contents of the Name Constraints Extension.
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
 * The following options are relevant:
 *   - In the field CMAKE_BUILD_TYPE <code>Release</code> <code>Debug</code> build can be activated.
 *   - Under <code>build_cfg</code> one of the directory names in the folder
 *   <code> flea/build_cfg/general/</code> can be provided. The folder
 *   <code>default</code> the default build configuration with all features
 *   enabled.
 *   - the fields <code>asan</code>, and <code>afl</code> can be used to activate the
 *   tools AddressSanitizer and American Fuzzy Lop, respectively. For the
 *   installation of these tools refer to
 *
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

After compilation of the library and the test-application they can be invoked from the main directory of the flea package for instance as
<PRE>
$ ./examples/tls_scripts/run_flea_server.sh
$ ./examples/tls_scripts/run_openssl_client.sh
</PRE>
in two different console windows.
*/

/*! \page fleaApi About fleaTLS' API
 *
 * In the following the main conventions of fleaTLS' API are explained.

 * \section apiErrHandl Error Handling
 *
 * fleaTLS functions starting with <code>THR_
 *
 *
 */

/*! \page devolopWflea Using fleaTLS in Development Projects
*
* In the following it is described which steps have to be taken to include
* fleaTLS into a development project.
*
* \section cstmBuildSys Custom build system
*
* In order to create a custom build system for fleaTLS, the following
* subdirectories of the flea directory must be in the include path:
* - include
* - include/api
* - test/include
* - build_cfg/general/[choose a subdirectory, e.g. <code>default</code>]
  - build_cfg/pltf_spec/32bit_default
*
*
* All the C source files in the folder <code>src/</code> need be compiled to build
* the library. In order to build the unit tests, also the C/C++ source files in  <code>test/src</code> need to be compiled.
*
*
* \section devCfg Configuration of the library
*
* fleaTLS' general compile-time switches can be set in the build_config_gen.h file in
* the respective subdirectory of <code>build_cfg/general/</code>.
* The <code>default</code> subdirectory contains a build configuration with all features activated.

 Architecture specific configuration of the proper integer types are provided in <code>build_cfg/pltf_spec/32bit_default/</code>build_cfg_pltf.h. If using a 16-bit platform, FLEA_WORD_BIT_SIZE has to be adjusted in that file.
*
*
\section devLibInit Initializing the library

Before any functions of fleaTLS are called from an application, a call to THR_flea_lib__init() has to be made.

\subsection libinitRng RNG seed

A fresh and high entropy seed must be supplied to fleaTLS' random number generator. If this is not the case, the usage of fleaTLS will not be secure.

Furthermore, a function for storing a fresh RNG seed can optionally provided.

\subsection libinitNowFunc Current Time

A function to determine the current time needs to be supplied, if X.509 certificate verification is going to be used.

\subsection libinitMutex Concurrency Support

A set of mutex functions needs to be supplied if concurrency support shall be enabled in fleaTLS.


\section enableTls Custom flea_rw_stream_t Implementation for TLS

In order to enable TLS, the application code is required to supply a custom implementation of the type flea_rw_stream_t to the API functions. This type implements a read/write stream which is used by the TLS implementation to send and receive network data. Please refer to the file rw_stream.h for the general description of this type.

\subsection tlsRwStream Supporting the Read Modes

While the implementation of the write functionality is straightforward, the
there exist three read modes (\link flea_stream_read_mode_e flea_stream_read_mode_e \endlink) which must be understood
by the flea_rw_stream_read_f supplied to the custom flea_rw_stream_t type.
- \link flea_stream_read_mode_e::flea_read_nonblocking flea_read_nonblocking \endlink means that the function quickly returns with the available incoming data and thus may return with fewer bytes than requested. If no read data is available on the interface, the function may return with zero bytes read. This mode may *not* cause a timeout (see \ref tlsTimeout ).
- \link flea_stream_read_mode_e::flea_read_blocking flea_read_blocking \endlink mean that the function blocks until at least one byte has been read. Thus in this mode the read function may return with fewer bytes than requested. This mode may cause a timeout (see \ref tlsTimeout ).
- \link flea_stream_read_mode_e::flea_read_full flea_read_full \endlink means that the read call blocks until the full length of the requested data has been read. This mode may cause a timeout (see \ref tlsTimeout ).

The latter two modes can easily be implemented inside the \link flea_rw_stream_read_f flea_rw_stream_read_f \endlink function based on an implementation of \link flea_stream_read_mode_e::flea_read_nonblocking flea_read_nonblocking \endlink by repeatedly performing non blocking reads until the required number of bytes has been read.

\subsection tlsTimeout Timeouts and Error Handling

An implementation of the custom flea_rw_stream_t may choose to implement timeouts for reading data. In this case, the corresponding \link flea_rw_stream_read_f flea_rw_stream_read_f \endlink function shall return \link FLEA_ERR_TIMEOUT_ON_STREAM_READ FLEA_ERR_TIMEOUT_ON_STREAM_READ \endlink.

Otherwise the custom flea_rw_stream_t type shall implement the following error handling:

- When the flea_rw_stream_open_f function fails, it should return \link FLEA_ERR_FAILED_TO_OPEN_CONNECTION FLEA_ERR_FAILED_TO_OPEN_CONNECTION \endlink.
- When encountering a read error, \link FLEA_ERR_FAILED_STREAM_READ FLEA_ERR_FAILED_STREAM_READ \endlink is returned.
- When encountering a write error, \link FLEA_ERR_FAILED_STREAM_WRITE FLEA_ERR_FAILED_STREAM_WRITE \endlink is returned.

\subsection Example Implementation with Unix Sockets

The file <code>test/src/pc/tcpip_stream.c</code> contains a working flea_rw_stream_t for TLS using Unix TCP/IP sockets. It is used by the comman line fleaTLS client and server implementations (see \ref tlsTestTools).


*/
