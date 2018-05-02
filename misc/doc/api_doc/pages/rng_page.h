/*! \page fleaRng Random Number Generation
 *
As random number generation is a precondition for many cryptographic operations,
fleaTLS features support for random number generation. On the one hand, there is the type flea_ctr_mode_prng_t, defined in the file
ctr_mode_prng.h, for the instantiation of
pseudo random number generator (PRNG) objects, on the other hand there is the flea's
global random number generator (RNG). Its interface is defined in the file
flea/rng.h. flea's global RNG is based on a
flea_ctr_mode_prng_t, but features additional functions and has a
specific life cycle.


* \section secRngLifeCycle The Global RNG's Life Cycle

The global RNG's life cycle starts with the call to the function
THR_flea_lib__init(). This function takes an initial seed value for
the global RNG as its argument. It the caller's responsibility to provide a high
entropy seed of an appropriate length here. fleaTLS makes no checks in this
respect.

The function #THR_flea_lib__init() also supports the configuration of the seed file
management support of fleaTLS. For details seed Section \ref secSeedFile.


After the initialization of the global RNG through the call to
THR_flea_lib__init(), it can be used for the generation of random
byte arrays by the function THR_flea_rng__randomize(). Furthermore,
it is possible to reseed the generator using one of the functions
THR_flea_rng__reseed_volatile() or
THR_flea_rng__reseed_persistent(). The former updates the global
RNG's internal state with the provided seed data. The latter does the same, but
also updates the managed seed file (see Section \ref secSeedFile ).


* \subsection secSeedFile Seed Management

The default recommended approach is to make use of fleaTLS' support for
the management of a continuously managed seed file. In this case, the caller
of #THR_flea_lib__init() should provide the optional parameter for a function of type
<code>flea_prng_save_f</code> to #THR_flea_lib__init(). This function has to be implemented
by the user of fleaTLS. It will be called by
fleaTLS whenever the function THR_flea_rng__reseed_volatile() from
the global RNG's interface is called. In this case the global RNG produces a new
random output which is provided to the <code>flea_prng_save_f</code> as the
argument. The function is expected to save the byte array it received in its
argument to non-volatile memory and signal any potentially occurring errors by
returning appropriate non-zero error values. The size of the byte array provided
to flea_prng_safe_f() is always 32 bytes.

If a flea_prng_safe_f() function is provided to #THR_flea_lib__init(), the following seed-file-based life cycle model
is supported by fleaTLS, which is also shown in the Figure \ref figRngLc "RNG Life Cycle". This model ensures secure random number generation over
all power cycles of the device under the
assumption that no malicious entity gained knowledge of the initial seed, the
seed file managed by fleaTLS or the global RNG's state directly.

During the unique initial device initialization, e.g.
during production, an initial high entropy seed is provided to the
function #THR_flea_lib__init(). Furthermore, the function pointer argument of the type
flea_prng_safe_f(), implemented as explained above, is also provided to
#THR_flea_lib__init(). In any subsequent call to #THR_flea_lib__init(), the latest seed value that was
provided to flea_prng_safe_f() as its argument is used as the seed file argument
by the application code.

The function #THR_flea_lib__init(), after having initialized the global RNG's state with the seed value provided as its function argument, internally calls the function
#THR_flea_rng__reseed_persistent(), which causes flea_prng_safe_f() to be
invoked with freshly generated output from the global RNG. Thus during each
subsequent call to #THR_flea_lib__init(), it is ensured that a fresh high entropy seed is
used to initialize the global RNG.

In order to achieve a lasting of effect of any reseeding of the global RNG
by calls to the functions  THR_flea_rng__reseed_volatile() (see
Section \ref secRngLifeCycle) or
flea_rng__feed_low_entropy_data_to_pool() (see Section
\ref secLowEntropyReseed ), i.e. a subsequent update of the seed file, application code
should occasionally call the function
THR_flea_rng__reseed_persistent(), which triggers a call to the
function flea_prng_safe_f(), provided that such a function was specified in the
call #THR_flea_lib__init().

@image html rngLifeCyc/rngLifeCycSA.svg
@image latex rngLifeCyc/rngLifeCycSA.pdf
<CENTER>\anchor figRngLc
Figure RNG Life Cycle: Overview of the life cycle of fleaTLS' global RNG. The dashed line represents fleaTLS' API and shows the direction of time.  The functions after \link THR_flea_lib__init THR_flea_lib__init\endlink() may actually be called in an arbitrary order.  The sequence shown here serves merely as an example.  The paths labelled with <code>flea_prng_save_f</code> are only actually relevant if the corresponding function pointer is provided to the function THR_flea_lib__init(). Refer to the text for a detailed explanation.</CENTER>

\subsection secLowEntropyReseed Reseeding the Global RNG with Low Entropy Data

fleaTLS' global RNG also features a function for the feeding of low entropy seed
data in the form of 32-bit values, namely
flea_rng__feed_low_entropy_data_to_pool(). This function is
intended to receive for instance time stamp counter values from asynchronously
triggered events in order to provide fresh entropy to the global RNG. The caller
is required to provide an estimate of the entropy contained in that value in
bits. This estimation is used for the management of fleaTLS' global RNG's
entropy pool. In this pool the low entropy feeds are accumulated. Whenever the
accumulated estimated entropy reaches the threshold of 128 bits, in the next
call to the function THR_flea_rng__randomize() the global RNG will
reseed itself with the content of the entropy pool. This is also shown in Figure \ref figRngLc "RNG Life Cycle".

The function  #flea_rng__feed_low_entropy_data_to_pool() does not
use any mutexes to prevent concurrent access. This is intentional, since it is
expected to be called from interrupt routines which may never be blocked.
fleaTLS' functions which access the
entropy pool are written in such a way that a potentially concurrent access does
not cause program errors. In actual cases of concurrent accesses, it may happen that
the fed low level entropy is not optimally transferred to the pool or that a
randomize function prematurely uses the pool for reseeding the RNG state. Any
such event does not actually degrade security of the RNG state, but only reduces the effect of
the pooled entropy under certain conditions to a certain degree. Note that the low entropy reseeding is a feature aiming at the goal to achieve backward security (i.e. security against disclosure of the RNG's state in the past) in the long run. The secure operation of the RNG the beginning of the device's operational phase should always rely on a high entropy seed passed to #THR_flea_lib__init().

If an
implementer considers the pooling functionality essential to the secure
operation of his product, and actually expects simultaneous calls to the functions
#flea_rng__feed_low_entropy_data_to_pool() and
THR_flea_rng__randomize() with a high frequency, a mutex mechanism should be implemented.


*/
