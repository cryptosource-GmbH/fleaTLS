/*
For the TLS functionality, it is not
necessary to support all three modes. The fleaTLS handshake code only uses the
mode \link flea_stream_read_mode_e::flea_read_full flea_read_full \endlink. The
support for the other two modes in the custom flea_rw_stream_t type is only
necessary if the application code makes a calls to
THR_flea_tls_client_ctx_t__read_app_data() or
THR_flea_tls_server_ctx_t__read_app_data() with other read modes specified in
the call. If an application only makes calls to these two function specifying \link flea_stream_read_mode_e::flea_read_full flea_read_full \endlink as the read mode, then the custom flea_rw_stream_t type only needs to support that read mode as well.

*/
