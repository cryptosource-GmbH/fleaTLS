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


#ifndef _flea_ecc_named_curves__H_
#define _flea_ecc_named_curves__H_

#include "flea/ec_dom_par.h"
#include "flea/types.h"

#ifdef FLEA_HAVE_ECC

flea_err_e THR_flea_ecc_gfp_dom_par_t__set_by_named_curve_oid(
  flea_ec_dom_par_ref_t* dp_to_set__pt,
  const flea_u8_t*       oid__pcu8,
  flea_al_u8_t           oid_len__alu8
) FLEA_ATTRIB_UNUSED_RESULT;

#endif /* #ifdef FLEA_HAVE_ECC */
#endif /* h-guard */
