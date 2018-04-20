/*! \page tlsPage The TLS API
 *
fleaTLS implements the TLS 1.2 protocol for the instantiation of TLS clients and
servers.

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

\section secTlsFlowOverv Overview of the TLS Protocol Flow

@image html tlsSeqFlow/tlsSeqFlowSA.svg
@image latex tlsSeqFlow/tlsSeqFlowSA.pdf
<CENTER>Figure: Overview of the potential events during the TLS protocol flow and the
associated functions of the fleaTLS client and server API.</CENTER>

The above figure shows the potential events in the TLS protocol flow
and the associated functions of the fleaTLS client and server API. Any TLS
connections starts with a call to the ctor function of the TLS client
 (#flea_tls_client_ctx_t) or server (#flea_tls_server_ctx_t) context object.

\section secInitHsAndAppData Initial Handshake and Application Data Transfer
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

  \section secReneg Renegotiation
A renegotiation can be triggered either by a call to the corresponding
renegotiation function

- <code>THR_flea_tls_client_ctx_t__renegotiate()</code> or
- <code>THR_flea_tls_server_ctx_t__renegotiate()</code>.

Before a call one of these functions #flea_tls_client_ctx_t__is_reneg_allowed or #flea_tls_server_ctx_t__is_reneg_allowed() should be made in order to determine whether renegotiation is possible according to the current configuration.


Furthermore, a renegotiation can be executed during a call to a <code>read_app_data</code> function, if the peer initiates a
  renegotiation during that call and the fleaTLS instance accepts it.


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

  Note that fleaTLS suppresses session resumption
  during a renegotiation. A renegotiation will thus always be a full handshake.
  However, a session in which a renegotiation has been carried out may normally
  be resumed in an initial handshake.

  \section secTlsSessRes Session Resumption


  fleaTLS supports session resumption for both the client and the server.


  \subsection secTlsSessResServer TLS Server
  For the TLS server, session resumption is enabled by providing a non-null pointer to a constructed #flea_tls_session_mngr_t  object in the call to #THR_flea_tls_server_ctx_t__ctor(). The configuration property #FLEA_TLS_MAX_NB_MNGD_SESSIONS determines how many sessions can be cached.


  \subsection secTlsSessResClient TLS Client
For the client, a session can be saved for later resumption by creating an object of type #flea_tls_client_session_t using the function #flea_tls_client_session_t__ctor() and providing it in the call to #THR_flea_tls_client_ctx_t__ctor().
After the successful completion of #THR_flea_tls_client_ctx_t__ctor(), the #flea_tls_client_session_t object should now contain a valid session. This can be tested with the function #flea_tls_client_session_t__has_valid_session(). The valid session can be serialized using #THR_flea_tls_client_session_t__serialize().

In order to resume a session, first an object of type #flea_tls_client_session_t containing a valid session has to be present. This can be achieved either

- by keeping the object after the above described procedure to record a session during a handshake,
- or by creating a new #flea_tls_client_session_t via #flea_tls_client_session_t__ctor() and then deserializing a previously serialized session using the function #THR_flea_tls_client_session_t__deserialize() on the same object.

Afterwards, this object is provided to the call to #THR_flea_tls_client_ctx_t__ctor(), causing the client to attempt to resume that session.

      \section secTlsCloseConn Closing the connection
  The closing of a connection happens when dtor function of the respective tls
  client or server context object is called. Furthermore, the connection is
  closed if an error occurs during any of the other functions of #flea_tls_client_ctx_t or #flea_tls_server_ctx_t.

  \section secTlsAlerts TLS Alert Handling and Sending

  In the TLS protocol alert messages are specified as a means to signal error
  conditions to the peer. They carry a type and a level field. A variety of possible types
  is specified in the TLS standard. The level can be <code>fatal</code>, indicating an error
  that mandates the ending of the connection, or <code>warning</code>, indicating that,
  depending on the type of the alert, a specific action may be necessary.
  fleaTLS completely hides the treatment of incoming
  TLS alerts from the application and sends appropriate error alerts when an error condition is met.

  If fleaTLS receives an alert the reaction is determined according to the
  following rules:
    - If the alert has level <code>fatal</code>, fleaTLS closes the connection and the API
        function during the execution of which the alert was received returns an
        error code.
      - Otherwise, if the alert has level <code>warning</code>, and
          - if it is of type <code>close notify</code>, then the connection is closed as
            well, i.e. fleaTLS sends a <code>close notify</code> alert to the peer itself and the current function
            returns FLEA_ERR_TLS_REC_CLOSE_NOTIFY;
          - if it is of type <code>no renegotiation</code>, and fleaTLS is
            currently executing the TLS client's or server's
            <code>..._renegotiate()</code> function, then it aborts the renegotiation and
            indicates this to the caller. The TLS context object remains valid in
            this case.

\section secCipherSuites Cipher Suites

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


These strings specify the cryptographic algorithms that are used during the TLS
handshake according to the following pattern:

@image html cipher_suite_expl.png

\latexonly
$$
\mathrm{TLS_}\underbrace{\mathrm{RSA}}_{\mathrm{KEX}}\mathrm{_WITH_}\underbrace{\mathrm{AES_128}}_{\mathrm{cipher}}_\underbrace{\mathrm{CBC}}_{\mathrm{mode}
}_\underbrace{\mathrm{SHA}}_{\mathrm{hash} }
$$
  \endlatexonly

  - KEX: The key exchange algorithm specifies the algorithm which is used
    for the exchange of the symmetric keys used in the TLS channel. The current
    version of fleaTLS supports the RSA, ECDHE_RSA, ECDHE_ECDSA, and PSK KEX.
  - cipher: The cipher is the encryption primitive which is used to achieve
    the confidentiality within the TLS channel. fleaTLS only supports the AES
    algorithm (with key sizes 128 and 256 as specified in the TLS protocol).
  - mode: The encryption mode in which the cipher is used.
  - hash: The hash algorithm which is specified here is used for the
    authentication of the channel data.
The support for the individual cipher suites is configured in the file build_config_gen.h with the corresponding define is the name of the cipher suite prefixed with <code>FLEA_HAVE_TLS_CS_...</code>.

\section secTlsReqClServCerts Requirements for Client and Server Certificates

\subsection ECDSA Certificates

For any cipher suites featuring a KEX including "ECDSA", the client's or server's certificate must contain an EC public key. The analogously those cipher suites including "RSA" require a  certificate featuring an RSA public key.

Note that the current version of fleaTLS only supports named elliptic curves, which is the
usual choice for TLS certificates.


\section secTlsExt TLS Extensions

The TLS protocol features a number of so-called TLS extension. These are
optional extensions of the basic protocol. They are sent during the Client Hello
and/or Server Hello messages.

\subsection secRenegIndicExt Renegotiation Indication Extension
Renegotiation Indication Extension is specified in RFC 5746 and has the purpose
of preventing certain data injection attacks. fleaTLS supports this extension
according to the standard. Refer to \ref secReneg for further information.


\subsection secSigAlgExt Signature Algorithm Extension
fleaTLS always uses this extension. The allowed extensions are set by specifying
the parameter of type <code>#flea_tls_sigalg_e </code> of the client or server ctor
function.

\subsection secSuppECCurveExt Supported Elliptic Curves Extension
fleaTLS always uses the Supported Elliptic Curves Extension when elliptic curve
cipher suites are configured. The set of allowed elliptic curve domain
parameters is defined by
specifying the parameter of type <code>#flea_ec_dom_par_id_e</code> of the client or
server ctor function.

\subsection secSuppPointForm Supported Point Formats Extension
fleaTLS always uses the Supported Point Formats Extension when elliptic curve
cipher suites are configured. fleaTLS only supports the uncompressed point
format.

\section secTlsConc Concurrency Support
fleaTLS offers concurrency support (see Section \ref secConcurrency) for the TLS server. For this reason the session manager object
offers mutex support and may be shared among different server context objects.

The server's private key may be shared among threads as well.

\section secInstTlsClientAndServer Instantiating TLS Server and Client

The fleaTLS server and client API types are given by the
#flea_tls_server_ctx_t and #flea_tls_client_ctx_t. Their life cycle is modelled such that their
constructor call carries out the TLS handshake. The constructed object is thus
directly in the state where the TLS channel is established and data can be
exchanged.

Note that for both the client and the server it must be ensured that all pointers provided in the respective ctor call must remain valid throughout the whole life-time of the #flea_tls_client_ctx_t or #flea_tls_server_ctx_t object, i.e. until the dtor function is called.

\section secInstTlsClient Instantiating a TLS Client

The following example is found under <code>examples/tls/client_basic/</code> and can be invoked by typing
<PRE>
$ ./build/tls_client_basic
</PRE>
in the flea main directory.
The directory contains also a script to start a fleaTLS server against which the client example can run. The script must be invoked from the flea main directory. The TLS client connects to the server and executes a handshake with hostname verification (in this case using the IP address 127.0.0.1) and verifies the authenticity of the server certificate.  Afterwards, it sends some application data which is pinged back by the server. The example does not use client authentication. In order to enable client authentication, #THR_flea_tls_client_ctx_t__ctor() must be invoked with a certificate chain and a private key in the same way as it is shown for the TLS server in Section \ref secInstTlsServer.

\snippet tls/client_basic/tls_client_basic.c whole_file

\section secInstTlsServer Instantiating a TLS Server

In the following we give an example of setting up a fleaTLS server. The example
is located at <code>examples/tls/server_basic/</code>
<PRE>
$ ./build/tls_server_basic
</PRE>
in the flea main directory.
It can be run against
the client example from Section \ref secInstTlsClient. The server doesn't
request client authentication. In order to enforce client authentication, the flea_cert_store_t
parameter in the THR_flea_tls_server_ctx_t__ctor() must be non-null and contain
the root certificates that are trusted for client authentication. For setting
up the cert store see Section \ref secInstTlsClient. Revocation checking is also not used by the server. A flea_tls_session_mngr_t object is used so that the server supports session resumption.

\snippet tls/server_basic/tls_server_basic.c whole_file


*/
