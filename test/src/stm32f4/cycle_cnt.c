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

#include "cycle_cnt.h"

volatile unsigned int cyc_start;
volatile unsigned int cyc_final;

volatile unsigned int* DWT_CYCCNT  = (volatile unsigned int *) 0xE0001004; // address of the register
volatile unsigned int* DWT_CONTROL = (volatile unsigned int *) 0xE0001000; // address of the register
volatile unsigned int* SCB_DEMCR   = (volatile unsigned int *) 0xE000EDFC; // address of the register
