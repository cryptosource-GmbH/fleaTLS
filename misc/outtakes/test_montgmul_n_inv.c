
/*static flea_err_t THR_flea_test_montgm_mul_comp_n_prime_32bit_exhaustive()
{
  flea_u64_t i;  
  flea_u64_t limit = ((flea_u64_t) 0xFFFFFFFF) + 1;
  FLEA_THR_BEG_FUNC();
  for(i = 1; i < limit; i = i+2)
  {
    flea_dbl_uword_t prod, q, rem;
    const flea_dbl_uword_t mod = ((flea_dbl_uword_t)FLEA_UWORD_MAX) + 1;
    flea_uword_t inv = flea_montgomery_compute_n_prime((flea_u32_t)i);
    prod = inv * i;
    q = prod / mod; // reduce modulo mod ...
    rem = prod - q*mod; // ... completed
    if(rem != 1) // n*n^{-1} modulo "mod" = 1
    {
      printf("to invert = %u, rem = %u\n", i, rem);
      FLEA_THROW("error in computing n'", FLEA_ERR_FAILED_TEST);
    }
    if(i % 100000000 == 1)
    {
      float percentage = ((float) i) / limit;
      printf("completed %f\%\n", percentage);
    }
    
  }
  FLEA_THR_FIN_SEC_ON_ERR();
  FLEA_THR_FIN_SEC_ALWAYS();
}*/
