/*
Copyright 2018 Embedded Microprocessor Benchmark Consortium (EEMBC)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

Original Author: Shay Gal-on
*/

/* Topic : Description
        This file contains configuration constants required to execute on
   different platforms
*/
#ifndef CORE_PORTME_H
#define CORE_PORTME_H

/************************/
/* Freestanding config  */
/************************/
#define HAS_FLOAT    1
#define HAS_TIME_H   0
#define USE_CLOCK    0
#define HAS_STDIO    0
#define HAS_PRINTF   0

/* Timing: 64-bit tick counter */
typedef unsigned long long CORE_TICKS;

/* Compiler info */
#ifndef COMPILER_VERSION
#define COMPILER_VERSION "zig cc"
#endif
#ifndef COMPILER_FLAGS
#define COMPILER_FLAGS "-Doptimize=ReleaseFast -march=rv32imf_zicsr_zba_zbb -mabi=ilp32f -freestanding"
#endif
#ifndef MEM_LOCATION
#define MEM_LOCATION "STACK"
#endif

/************************/
/* Data types (RV32)    */
/************************/
typedef signed short   ee_s16;
typedef unsigned short ee_u16;
typedef signed int     ee_s32;
typedef double         ee_f32;
typedef unsigned char  ee_u8;
typedef unsigned int   ee_u32;
typedef ee_u32         ee_ptr_int;
typedef unsigned int   ee_size_t;

#define align_mem(x) (void *)(4 + (((ee_ptr_int)(x) - 1) & ~3))

/************************/
/* Configuration        */
/************************/
#define SEED_METHOD SEED_VOLATILE
#define MEM_METHOD  MEM_STACK

#define MULTITHREAD 1
#define USE_PTHREAD 0
#define USE_FORK    0
#define USE_SOCKET  0

#define MAIN_HAS_NOARGC   1
#define MAIN_HAS_NORETURN 0

extern ee_u32 default_num_contexts;

typedef struct CORE_PORTABLE_S {
    ee_u8 portable_id;
} core_portable;

void portable_init(core_portable *p, int *argc, char *argv[]);
void portable_fini(core_portable *p);

#if !defined(PROFILE_RUN) && !defined(PERFORMANCE_RUN) && !defined(VALIDATION_RUN)
#define PERFORMANCE_RUN 1
#endif

/* Iterations - increase for longer runs */
#ifndef ITERATIONS
#define ITERATIONS 10000
#endif

#endif /* CORE_PORTME_H */