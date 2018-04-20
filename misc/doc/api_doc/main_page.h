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
 * This quickstart manual explains the steps necessary to run fleaTLS under
 * Linux and how to include it in custom build projects, e.g. for your embedded
 * application.
 *
 * - \subpage gettingStarted "Getting started with fleaTLS on Linux"
 *
 * - \subpage fleaApi "About fleaTLS' API"
 *
 * - \subpage devolopWflea "Using fleaTLS in development projects"
 *
 * - \subpage fleaTLSRestrictions "Restrictions of fleaTLS"
 * - \subpage fleaRng "Random Number Generation"
 * - \subpage tlsPage "The TLS API"
 *
 */

/*! \page fleaTLSRestrictions Restrictions of fleaTLS
 *
 * Here we list some restrictions of the current version of fleaTLS.
 *
 * - fleaTLS does not support the RSA key generation. This operation is
 *   extremely complex and generally not suitable for software implementations on
 *   resource-constrained devices.
 *
 * fleaTLS supports the functionality for X.509 processing, but excludes some
 * features specified in RFC 5280, that are usually irrelevant to IoT and
 * industry applications.
 *
 * - X.509 Certificate Name Constraints extension: The Name Constraints
 *   extension, which is typically used in complex heterogeneous PKIs only, can
 *   be used to restrict the set of names that Sub-CAs may issue certificates to. The corresponding restrictions are reflected by the contents of the Name Constraints extension.
 *   This extension is not supported by fleaTLS. If fleaTLS encounters an X.509
 *   certificate featuring a Name Constraints extension marked as critical, the
 *   certificate cannot be validated.
 * - Support for X.509 Certificate Policy extension: fleaTLS does not process
 *   the
 *   X.509 Certificate Policy extension. It ignores extensions of this type, even if
 *   they are marked as critical. Other policy-related X.509 certificate
 *   extensions, namely the Inhibit anyPolicy and Policy Constraints extension,
 *   lead to the rejection of the certificate if they are marked as critical.
 * - X.509 Freshest CRL extension: This extension, which addresses Delta CRLs,
 *   is of almost no relevance even in the internet PKI. The presence of
 *   this extension marked as critical in an X.509 certificate also leads to the
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
 *    $ apt-get install build-essential cmake cmake-curses-gui
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
 *   - In the field CMAKE_BUILD_TYPE <code>Release</code> or <code>Debug</code> build can be activated.
 *   - Under <code>build_cfg</code> one of the directory names in the folder
 *   <code> flea/build_cfg/general/</code> can be provided. The build
 *   configuration file contained in that folder will be used during
 *   compilation. The folder
 *   <code>default</code> contains the default build configuration with all features
 *   enabled.
 *   - the fields <code>asan</code>, and <code>afl</code> can be used to activate support for the
 *   tools AddressSanitizer and American Fuzzy Lop during compilation, respectively. For the
 *   installation of these tools refer to
 *      - https://github.com/google/sanitizers/wiki/AddressSanitizer
 *      - http://lcamtuf.coredump.cx/afl/
 *
 *

\section runTests Running the tests

In order to execute the unit tests, run the command
<PRE>
  $ ./build/flea-test
  </PRE>
Get help supplying --help as an argument.

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

/*! \page fleaApi The fleaTLS API
 *
 * In the following the principles of fleaTLS' API are explained.
 *
 * \section apiConventions Conventions
 *
 *
  In the function parameter lists, [in], [out], and [in,out] specifies
  whether a parameter is a mere input, a mere output, or both for the function.
  Here, a parameter is considered as an output if it it is a pointer and the
  object it points to is potentially updated by the function. An output
  parameter is guaranteed to be updated by the function to the value specified
  in the API documentation if the function returns without indicating an error,
  i.e. when it returns FLEA_ERR_FINE.

  A function parameter ending <code>_mbn</code> stands for "may be null" and
  indicates that the caller my supply a null pointer for the parameter. The conditions for and effects of supplying a null pointer are explained in the respective parameter description.
 *
 * \section apiErrHandl Error Handling
 *
 * fleaTLS functions starting with <code>THR_...</code>, i.e.  throwing
 * functions, return an error code
 * which has to be checked by the caller.
 *
 * \section apiObjLifeCycle Object Life-Cycle
 *
 * fleaTLS realizes an object oriented API for a number of class-like types. Each type name in
 * fleaTLS ends in <code>..._t</code>.
 * The functions that are belonging to a certain type have the name pattern
 * <code>[THR_]\<type-name\>__\<function-name\></code>.
 * Class-like types are
 * identified by having a <code>ctor</code>, i.e. constructor, and
 * a <code>dtor</code>, i.e. destructor, function.
 *
 * \subsection secClassLikeTypes The Life-Cycle of the Class-Like Types
 *
 * The life-cycle model for the class-like types is as follows.
 *
 * When declaring an object, it will be in the UNINIT state. The first action
 * that must happen to an object in this state is initialization. Initialization
 * can be performed in two ways. The first is using the <code>\<type-name\>__INIT_VALUE</code>
 * macro as the right hand side initialization value when declaring the object.
 * For example like this:
 *
 * <code> flea_ae_ctx_t ctx__t = \link flea_ae_ctx_t__INIT_VALUE flea_ae_ctx_t__INIT_VALUE\endlink; </code>
 *
 * The second possibility is to use the <code>\<type-name\>__INIT(ptr)</code>
 * macro after the declaration and before the object is used:
 *
 * <CODE>
 *
 * flea_ae_ctx_t ctx2__t; <br>
 * ... <br>
 * flea_ae_ctx_t__INIT(&ctx2__t); <br>
 * </CODE>
 *
 * After initialization, the object is in the state INIT. From this state the
 * following state transitions are allowed:
 *
 * - calling the type's dtor function, leaving the object in the state INIT,
 *   e.g. <code> \link flea_ae_ctx_t__dtor flea_ae_ctx_t__dtor\endlink(&ctx__t);</code>
 * - calling a ctor function defined for the type, entering the state CONSTRUCTED, e.g. <br>
 * <code> err = \link THR_flea_ae_ctx_t__ctor THR_flea_ae_ctx_t__ctor\endlink(&ctx__t, ...);</code>
 *
 *
 *
 * In the CONSTRUCTED state, the type's general functions may be called, e.g.
 * <br>
 * <code>err = \link THR_flea_ae_ctx_t__update_encryption THR_flea_ae_ctx_t__update_encryption\endlink(&ctx__t, ...) </code>
 *
 * From the CONSTRUCTED state, the following state transitions are possible:
 * - to the INIT state by calling the type's dtor
 * - to the ERROR state by receiving an error return code from a throwing
 *   function operating on the object.
 *
 * In the ERROR state, only the type's dtor function may be called on the object, which causes it to enter the INIT
 * state again.
 *
 * \subsection useObjLc Properly using fleaTLS Class-Like Types in Application Code
 *
 * In order to achieve a secure and proper object life-cycle for fleaTLS objects
 * in a function, it must be prevented that
 * - an object runs out of scope while being in the CONSTRUCTED or ERROR state,
 * - general functions are called on it while being in the UNINIT, INIT or ERROR state,
 * - and that its dtor is called on it while being in the UNINIT state.
 *
 * In order to meet these requirements, the following approach can be taken:
 * - At the start of the function, declare all objects and initialize them, before entering any code that
 *   performs conditional branching, thus also doesn't possibly encounter any
 *   error conditions that need to be handled.
 * - After having initialized all objects, the function body is entered with all
 *   kinds of conditional control flow and object creation using the fleaTLS
 *   ctor functions.
 * - the function's design ensures that after its completion, the dtor functions on all potentially constructed objects are called.
*
* fleaTLS internally uses a \link FLEA_THR_BEG_FUNC macro framework \endlink which ensures that these
*   requirements are met which may be adopted by the application code.
 *
 * In order to prevent resource leaks, it is crucial that an object returns to
 * the INIT state before it leaves the scope. Note that in many cases the only
 * type of resource that needs to be freed is allocated heap memory. However, it
 * is still recommended to always call the dtor function on an object even in
 * \link FLEA_HEAP_MODE stack mode \endlink, since the dtor function also often overwrites secret values and their usage is thus a best practice for security.
 *
 * \subsection secClassLikeNonThrCtor Class-Like Types with Non-Throwing ctors
 *
 * Some types can enter the CONSTRUCTED state directly without previously
 * entering the INIT state, since they offer right hand side initialization
 * values putting them into the CONSTRUCTED state directly as well as
 * non-throwing ctors. A non-throwing ctor may be used at the start of a
 * function before entering the function body, i.e. where generally the
* initialization calls are made. An example for such types is flea_byte_vec_t.
 *
 */

/*! \page devolopWflea Using fleaTLS in Development Projects
*
* In the following it is described which steps have to be taken to include
* fleaTLS into a development project.
*
* \section cstmBuildSys Custom Build Systems
*
* fleaTLS requires as prerequisite only a C standard library.
*
* When integrating fleaTLS into a custom build system, the following
* subdirectories of the flea directory must be in the compiler's include path:
* - include
* - include/api
* - build_cfg/general/[choose a subdirectory, e.g. <code>default</code>]
  - build_cfg/pltf_spec/32bit_default

  In the case that also the unit tests shall be built, also the folder test/include must be included.
*
*
* All the C source files of the fleaTLS library in the folder <code>src/</code> need be compiled to build
* the library. In order to build the unit tests, also the C/C++ source files in  <code>test/src</code> need to be compiled. Note that the unit tests are resource intensive and that some of them require a Unix file system.
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

Furthermore, a function for storing a fresh RNG seed can optionally be provided.

\subsection libinitNowFunc Current Time

A function to determine the current time needs to be supplied, if X.509 certificate verification is going to be used.

\subsection libinitMutex Concurrency Support

A set of mutex functions needs to be supplied if concurrency support shall be enabled in fleaTLS. Refer to \ref concSupp.


\section enableTls Custom flea_rw_stream_t Implementation for TLS

In order to enable TLS, the application code is required to supply a custom implementation of the type flea_rw_stream_t to the API functions. This type implements a read/write stream which is used by the TLS implementation to send and receive network data. Please refer to the file rw_stream.h for the general description of this type.

\subsection tlsRwStream Supporting the Read Modes

While the implementation of the write functionality is straightforward,
there exist three read modes (\link flea_stream_read_mode_e flea_stream_read_mode_e \endlink) which must be understood
by the \link flea_rw_stream_read_f flea_rw_stream_read_f \endlink supplied to the custom flea_rw_stream_t type.
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

The file <code>test/src/pc/tcpip_stream.c</code> contains a working flea_rw_stream_t for TLS using Unix TCP/IP sockets. It is used by the command line fleaTLS client and server implementations (see \ref tlsTestTools).

\section concSupp Concurrency Support

fleaTLS supports concurrent access for two of its types, namely flea_tls_session_mngr_t and the library's global RNG defined in rng.h. The former needs concurrency support since it is likely that this object is shared between multiple, concurrently running server threads, while the RNG may need to be accessed by multiple threads.

For objects of any other types in the fleaTLS API, if they are to be accessed form different threads, the application code has to implement concurrency support itself.

Refer to \ref mt_cfg, mutex.h, and \link THR_flea_lib__init THR_flea_lib__init() \endlink for further configuration options pertaining to the concurrency support in fleaTLS.

*/
