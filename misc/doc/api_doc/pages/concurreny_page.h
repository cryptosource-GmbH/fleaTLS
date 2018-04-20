/*! \page pageConcurrency Concurrency
 *
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

In the \ref mt_cfg "multithreading support" section of the file <code>build_config_gen.h</code>
appropriate configuration settings must be made. In the shipped version of flea,
the use of Unix pthread mutexes is preconfigured.

\subsection Enabling Mutex Support
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

\subsection secDisableMutex Disabling Mutex Support
In order to disable mutex support in fleaTLS, remove the two lines
<PRE>
# define FLEA_HAVE_MUTEX
</PRE>
and
<PRE>
# include <pthread.h>
</PRE>

\subsection secMutexRunTimeConf Run-Time Configuration

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
