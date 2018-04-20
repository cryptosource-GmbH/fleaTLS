/*! \page tlsPage The TLS API
 *
fleaTLS implements the TLS 1.2 protocol for the instantiation of TLS clients and
server.

\section secTlsDesc A brief description of the TLS protocol
TLS is a protocol which allows for the establishment of secure connections
between a TLS client and a TLS server. The authenticity of the server, and
optionally that of the client is ensured by the use of X.509 certificates.
During the so-called TLS handshake the authenticity of the X.509 certificate of
the peer is verified and based on the public key presented in that certificate
a key exchange (KEX) is performed. As a result, after the TLS handshake, both
sides share a set of symmetric keys for the encryption and authentiation of the
payload data, also referred to as application data.
At this point, both peers
can send application data to each other in a confidential and authentic manner.
The concrete cryptographic algorithms that are used during the handshake and for the
transmission of the application data, are specified by the so-called TLS
cipher suite.

\subsection secTlsFlowOverv Overview of the TLS Protocol Flow

@image html tlsSeqFlow/tlsSeqFlowSA.svg
@image latex tlsSeqFlow/tlsSeqFlowSA.pdf
<CENTER>Figure: Overview of the potential events during the TLS protocol flow and the
associated functions of the flea TLS Client and Serve API.</CENTER>

The above figure shows the potential events in the TLS protocol flow
and the associated functions of the fleaTLS client and server API. Any TLS
connections starts with a call to the ctor function of the TLS client
 (#flea_tls_client_ctx_t) or server (#flea_tls_server_ctx_t) context object.

\subsubsection secInitHsAndAppData Initial Handshake and Application Data Transfer
After the initial handshake, the TLS channel is established and all subsequent
data exchanges between the peers take place over the secure TLS channel. The
main purpose of the TLS channel is the secure exchange of application data,
which is done using the fleaTLS functions
- <code>THR_flea_tls_client_ctx_t__read_app_data()</code>
- <code>THR_flea_tls_client_ctx_t__send_app_data()</code>
- <code>THR_flea_tls_server_ctx_t__read_app_data()</code>
- <code>THR_flea_tls_server_ctx_t__send_app_data()</code>

Note that in order to ensure the sending of the application over the wire a call
to
- <code>THR_flea_tls_client_ctx_t__flush_write_app_data()</code> or
- <code>#THR_flea_tls_server_ctx_t__flush_write_app_data()</code>
  is necessary since the <code>send_app_data</code> functions may buffer the data.

  \subsubsection secReneg Renegotiation
A renegotiation can be triggered either by a call to the corresponding
renegotiation function

- <code>THR_flea_tls_client_ctx_t__renegotiate()</code> or
- <code>THR_flea_tls_server_ctx_t__renegotiate()</code>

  or during a call to a <code>read_app_data</code> function, if the peer initiates a
  renegotiation during that call which is accepted by flea.

  The conditions for accepting a renegotiation request by the  fleaTLS client or
  server are the following:
    - If in the TLS client or server context object's ctor call the flag <code>::flea_tls_flag__reneg_mode__allow_insecure_reneg </code> is
      set, then the renegotiation request is accepted under any condition.
    - If in the TLS client or server context object's ctor call the flag <code>::flea_tls_flag__reneg_mode__allow_secure_reneg   </code> is
      set, then the renegotiation request is accepted if the peer also supports
      the Renegotiation Indication Extension and behaves correctly with respect
      to this extension.
      - If in the TLS client or server context object's ctor call the flag <code>#flea_tls_flag__reneg_mode__disallow_reneg </code> is
      set, then the renegotiation request is declined unconditionally.

  The closing of a connection happens when dtor function of the respective tls
  client or server context object is called. Furthermore, the connection is
  closed if an error occurs during any of the other TLS client or server context
  objects.

  Note that both the flea client and the flea server suppress session resumption
  during a renegotiation. A renegotiation will thus always be a full handshake.
  However, a session in which a renegotiation has been carried out may normally
  be resumed in an initial handshake.

  \subsubsection secTlsAlerts TLS Alert Handling and Sending

  In the TLS protocol alert messages are specified as a means to signal error
  conditions to the peer. They carry a type and a level field. A variety of possible types
  is specified in the TLS standard. The level can be <code>fatal</code>, indicating an error
  that mandates the ending of the connection, or <code>warning</code>, indicating that,
  depending on the type of the alert, a specific action may be necessary.
  fleaTLS completely handles the treatment of incoming
  TLS alerts and sending of alerts when an error condition is met.

  If fleaTLS receives an alert the reaction is determined according to the
  following rules:
    - If the alert has level <code>fatal</code>, flea closes the connection and the API
        function during the execution of which the alert was received returns an
        error code.
      - Otherwise, if the alert has level <code>warning</code>, and
          - if it is of type <code>close notify</code>, then the connection is closed as
            well, i.e. fleaTLS sends a <code>close notify</code> alert to the peer itself;
          - if it is of type <code>no renegotiation</code>, and fleaTLS is
            currently executing the TLS client's or server's
            <code>renegotiate()</code> function, then it aborts the renegotiation and
            indicates this to the caller. The TLS context object remains valid in
            this case.

\subsection secCipherSuites Cipher Suites

The TLS protocol defines a large variety of cipher suites. fleaTLS
currently supports the following subset of cipher suites.

- <code>TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA</code>
- <code>TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256</code>
- <code>TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256</code>
- <code>TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA</code>
- <code>TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384</code>
- <code>TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384</code>
- <code>TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA</code>
- <code>TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256</code>
- <code>TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256</code>
- <code>TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA</code>
- <code>TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384</code>
- <code>TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384</code>
- <code>TLS_PSK_WITH_AES_128_CBC_SHA</code>
- <code>TLS_PSK_WITH_AES_128_CBC_SHA256</code>
- <code>TLS_PSK_WITH_AES_128_GCM_SHA256</code>
- <code>TLS_PSK_WITH_AES_256_CBC_SHA</code>
- <code>TLS_PSK_WITH_AES_256_CBC_SHA384</code>
- <code>TLS_PSK_WITH_AES_256_GCM_SHA384</code>
- <code>TLS_RSA_WITH_AES_128_CBC_SHA</code>
- <code>TLS_RSA_WITH_AES_128_CBC_SHA256</code>
- <code>TLS_RSA_WITH_AES_128_GCM_SHA256</code>
- <code>TLS_RSA_WITH_AES_256_CBC_SHA</code>
- <code>TLS_RSA_WITH_AES_256_CBC_SHA256</code>
- <code>TLS_RSA_WITH_AES_256_GCM_SHA384</code>


These strings specify the cryptorgraphic algorithms that are used during the TLS
handshake according to the following pattern:

@image html cipher_suite_expl.png

\latexonly
$$
\mathrm{TLS_</code>\underbrace{\mathrm{RSA</code></code>_{\mathrm{KEX</code></code>\mathrm{_WITH_</code>\underbrace{\mathrm{AES_128</code></code>_{\mathrm{cipher</code></code>_\underbrace{\mathrm{CBC</code></code>_{\mathrm{mode</code>
</code>_\underbrace{\mathrm{SHA</code></code>_{\mathrm{hash</code> </code>
$$
  \endlatexonly
  - KEX: The key exchange algorithm specifies the algorithm which is used
    for the exchange of the symmetric keys used in the TLS channel. The current
    version of fleaTLS supports only the RSA and ECDHE_RSA KEX. In the former,
    the RSA key from the certificate of the server is directly used for the KEX,
    Tin the latter the RSA key of the server signs an ephemeral ECDH key, which
    in turn is used for the key exchange. This implies that the
    certificate of the server must be an RSA certificate.
  - cipher: The cipher is the encryption primitive which is used to achieve
    the confidentiality within the TLS channel. fleaTLS only supports the AES
    algorithm (with key sizes 128 and 256 as specified in the TLS protocol).
  - mode: The encryption mode in which the cipher is used.
  - hash: The hash algorithm which is specified here is used for the
    authentication of the channel data.
The support for the individual cipher suites is configured in the general build
configuration file with the corresponding defines prefixed with <code>FLEA_</code>... .

\subsection secTlsReqClServCerts Requirements for Client and Server Certificates

\subsubsection ECDSA Certificates

The current version of fleaTLS only supports named elliptic curves, which is the
usual choice for TLS certificates.


\subsection secTlsExt TLS Extensions

The TLS protocol features a number of so-called TLS extension. These are
optional extensions of the basic protocol. They are sent during the Client Hello
and/or Server Hello messages.

\subsubsection secRenegIndicExt Renegotiation Indication Extension
Renegotiation Indication Extension is specified in RFC 5746 and has the purpose
of preventing certain data injection attacks. fleaTLS supports this extension
according to the standard.

This extension restricts the possibility of performing a TLS renegotiation under
certain conditions. This depends on the support of the peer for this extension
and the configuration of the flea TLS instance.

The renegotiation behaviour of a fleaTLS client or server can be controlled by
adding one out of the flag values
<code>#flea_tls_flag__reneg_mode__disallow_reneg</code>,
<code>#flea_tls_flag__reneg_mode__allow_secure_reneg</code>, or
<code>#flea_tls_flag__reneg_mode__allow_insecure_reneg</code>
in argument of type <code>flea_tls_flag_e</code> in the
fleaTLS client or server ctor function.

\subsubsection secSigAlgExt Signature Algorithm Extension
fleaTLS always uses this extension. The allowed extensions are set by specifying
the parameter of type <code>flea_tls_sigalg_e </code> of the client or server ctor
function.

\subsubsection secSuppECCurveExt Supported Elliptic Curves Extension
fleaTLS always uses the Supported Elliptic Curves Extension when elliptic curve
cipher suites are configured. The set of allowed elliptic curve domain
parameters is defined by
specifying the parameter of type <code>#flea_ec_dom_par_id_e</code> of the client or
server ctor function.

\subsubsection secSuppPointForm Supported Point Formats Extension
fleaTLS always uses the Supported Point Formats Extension when elliptic curve
cipher suites are configured. fleaTLS only supports the uncompressed point
format.

\section secInstTlsClientAndServer Instantiating fleaTLS Server and Client

The fleaTLS server and client API objects are given by the
#flea_tls_server_ctx_t and #flea_tls_client_ctx_t. Their life cycle is modelled such that their
constructor call carries out the TLS handshake. The constructed object is thus
directly in the state where the TLS channel is established and data can be
exchanged.

\subsection secInstTlsClient Instantiating a TLS Client

\snippet tls/tls_client_exmp.c whole_file

\subsection secInstTlsServer Instantiating a TLS Server
fleaTLS offers concurrency support (see Section \ref secConcurrency) for the TLS server session manager object
that may be shared among different server context objects. Note that in this
case all connections must be closed - i.e. server context objects destroyed -- before the session manager object is destroyed.


\section secConcurrency Concurrency Support in fleaTLS

Generally, fleaTLS objects do not implement any concurrency support. If
objects are shared between threads by client code, then the client code is
required to implement respective measures to prevent concurrent read/write
access to them.

However, fleaTLS offers concurrency support for its global RNG (see Section \ref fleaRng)
and the TLS server (see Section \ref secInstTlsServer), as these instances are
commonly used in multithreading contexts. If the global RNG's
functions for reseeding with high entropy seed data and generating output are
called from different threads (or interrupt routines), or multiple TLS
server context objects running in different threads and using a common shared
<code>#flea_tls_session\_mngr_t</code> employed, a mutex mechanism needs
to configured for fleaTLS. This is achieved by providing the appropriate compile
time and run-time configurations to fleaTLS.

\subsection secMutexCompTimeConf Compile-Time Configurations

In the "multithreading" section of the file <code>build_config_gen.h</code>
appropriate configuration settings must be made. In the shipped version of flea,
the use of Unix pthread mutexes is preconfigured.

\subsubsection Enabling Mutex Support
In order to enable mutex support in fleaTLS the line

<PRE>
# define FLEA_HAVE_MUTEX
</PRE>
must be present.

In the line
<PRE>
# include <pthread.h>
</PRE>
the header filename must be replaced by the appropriate header file.

Furthermore, the appropriate mutex type must be set in the line

<PRE>
# define FLEA_MUTEX_TYPE  the_mutex_type
</PRE>

\subsubsection secDisableMutex Disabling Mutex Support
In order to disable mutex support in fleaTLS, remove the two lines
<PRE>
# define FLEA_HAVE_MUTEX
</PRE>
and
<PRE>
# include <pthread.h>
</PRE>

\subsubsection secMutexRunTimeConf Run-Time Configuration

The actual implementation of the mutex functionality is provided to fleaTLS in
the call to the function #THR_flea_lib__init(). If compile-time support is enabled, a
<code>flea_mutex_func_set_t</code> must be provided to that function. In this object,
all four member function pointers must be set to point to appropriate functions.
These functions will be called with objects of type <code>FLEA_MUTEX_TYPE</code>
defined in the build configuration.

An example for the invocation #THR_flea_lib__init() for the pthread implementation is
found in the flea unit test file:


<PRE>
  flea_mutex_func_set_t mutex_func_set__t = {
    .init   = flea_linux__pthread_mutex_init,
    .destr  = pthread_mutex_destroy,
    .lock   = pthread_mutex_lock,
    .unlock = pthread_mutex_unlock
  };

  if(THR_flea_lib__init(
      &THR_flea_linux__get_current_time,
      (const flea_u8_t*) &rnd,
      sizeof(rnd),
      NULL,
      &mutex_func_set__t
    ))
  {
    // signal error
    ...
  }
</PRE>

  The requirements for the implementation of the four mutex related functions
  are specificed in the API documentation in the file <code>mutex.h</code>.
*/
