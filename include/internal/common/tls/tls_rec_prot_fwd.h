/* fleaTLS cryptographic library
Copyright (C) 2015-2019 cryptosource GmbH

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License. */

#ifndef _flea_tls_rec_prot_fwd__H_
#define _flea_tls_rec_prot_fwd__H_


#ifdef __cplusplus
extern "C" {
#endif

struct struct_flea_recprot_t;

typedef struct struct_flea_recprot_t flea_recprot_t;

typedef enum
{
  FLEA_TLS_CLIENT,
  FLEA_TLS_SERVER
} flea_tls__connection_end_t;

typedef enum { flea_tls_read, flea_tls_write } flea_tls_stream_dir_e;

#ifdef __cplusplus
}
#endif
#endif /* h-guard */
