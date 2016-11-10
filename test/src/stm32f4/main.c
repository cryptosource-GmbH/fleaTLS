/* ##__FLEA_LICENSE_TEXT_PLACEHOLDER__## */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <math.h>
#include "stm32f4xx_conf.h"
#include "utils.h"
#include "flea/types.h"
#include "cycle_cnt.h"

// Private variables
volatile uint32_t time_var1, time_var2;

// Private function prototypes
void Delay(volatile uint32_t nCount);
void init();
void calculation_test();
void dac_test();

flea_err_t THR_flea_test_rsa_crt();

flea_err_t THR_flea_test_ecdsa_256bit_sign_loop(unsigned count);

void test_loop(unsigned limit);

enum sysclk_freq
{
  SYSCLK_42_MHZ=0,
  SYSCLK_84_MHZ,
  SYSCLK_168_MHZ,
  SYSCLK_200_MHZ,
  SYSCLK_240_MHZ,
};

#if 0
// doesn't work, causes trap
void rcc_set_frequency (enum sysclk_freq freq)
{
  int freqs[]   = { 42, 84, 168, 200, 240 };

  /* USB freqs: 42MHz, 42Mhz, 48MHz, 50MHz, 48MHz */
  int pll_div[] = { 2, 4, 7, 10, 10 };

  /* PLL_VCO = (HSE_VALUE / PLL_M) * PLL_N */
  /* SYSCLK = PLL_VCO / PLL_P */
  /* USB OTG FS, SDIO and RNG Clock =  PLL_VCO / PLLQ */
  uint32_t PLL_P = 2;
  uint32_t PLL_N = freqs[freq] * 2;
  uint32_t PLL_M = (HSE_VALUE / 1000000);
  uint32_t PLL_Q = pll_div[freq];

  RCC_DeInit();

  /* Enable HSE osscilator */
  RCC_HSEConfig(RCC_HSE_ON);

  if(RCC_WaitForHSEStartUp() == ERROR)
  {
    return;
  }

  /* Configure PLL clock M, N, P, and Q
   * dividers */
  RCC_PLLConfig(RCC_PLLSource_HSE, PLL_M, PLL_N, PLL_P, PLL_Q);

  /* Enable PLL clock */
  RCC_PLLCmd(ENABLE);

  /* Wait until PLL clock is
   * stable */
  while((RCC->CR & RCC_CR_PLLRDY) == 0)
  {
    ;
  }

  /* Set PLL_CLK as system clock source
   * SYSCLK */
  RCC_SYSCLKConfig(RCC_SYSCLKSource_PLLCLK);

  /* Set AHB clock divider */
  RCC_HCLKConfig(RCC_SYSCLK_Div1);

  /* Set APBx clock dividers */
  switch(freq)
  {
  /* Max freq APB1: 42MHz
   * APB2: 84MHz */
  case SYSCLK_42_MHZ:
    RCC_PCLK1Config(RCC_HCLK_Div1);   /* 42MHz */
    RCC_PCLK2Config(RCC_HCLK_Div1);   /* 42MHz */
    break;
  case SYSCLK_84_MHZ:
    RCC_PCLK1Config(RCC_HCLK_Div2);   /* 42MHz */
    RCC_PCLK2Config(RCC_HCLK_Div1);   /* 84MHz */
    break;
  case SYSCLK_168_MHZ:
    RCC_PCLK1Config(RCC_HCLK_Div4);   /* 42MHz */
    RCC_PCLK2Config(RCC_HCLK_Div2);   /* 84MHz */
    break;
  case SYSCLK_200_MHZ:
    RCC_PCLK1Config(RCC_HCLK_Div4);   /* 50MHz */
    RCC_PCLK2Config(RCC_HCLK_Div2);   /* 100MHz */
    break;
  case SYSCLK_240_MHZ:
    RCC_PCLK1Config(RCC_HCLK_Div4);   /* 60MHz */
    RCC_PCLK2Config(RCC_HCLK_Div2);   /* 120MHz */
    break;
  }

  /* Update SystemCoreClock
   * variable */
  SystemCoreClockUpdate();
}
#endif
int main (void)
{

  RCC_ClocksTypeDef clocks;
  unsigned i;
  flea_u32_t cnt;
  volatile unsigned dummy;
  //init();
//rcc_set_frequency(SYSCLK_42_MHZ);
/*RCC_GetClocksFreq(&clocks);
   dummy = clocks.SYSCLK_Frequency;
   dummy = clocks.HCLK_Frequency;
   dummy = clocks.PCLK1_Frequency;
   dummy = clocks.PCLK2_Frequency;*/

  int retval1 = flea_unit_tests();

  STOPWATCH_START();
  //int retval = THR_flea_test_rsa_loop(10);
  int retval = THR_flea_test_ecdsa_256bit_sign_loop(10);
  STOPWATCH_STOP();
  cyc_start = cyc_final;
  if(retval != 0 || retval1 != 0)
  {
    while(1)
    {
      ;
    }
  }
  for(;; )
  {

  }

  return 0;
}


/*
 * Called from systick handler
 */
void timing_handler ()
{
  if(time_var1)
  {
    time_var1--;
  }

  time_var2++;
}

/*
 * Delay a number of systick cycles (1ms)
 */
void Delay (volatile uint32_t nCount)
{
  time_var1 = nCount;
  while(time_var1--)
  {
  }
  ;
}

/*
 * Dummy function to avoid compiler error
 */
void _init ()
{

}

