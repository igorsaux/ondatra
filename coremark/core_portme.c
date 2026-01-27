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

#include "coremark.h"

/************************/
/* Ecall syscall numbers */
/************************/
#define SYS_EXIT      0
#define SYS_PUTCHAR   1
#define SYS_GET_TIME  2  /* Returns 64-bit cycle count in a0(lo), a1(hi) */

/************************/
/* Ecall wrappers       */
/************************/
static inline void sys_exit(int code) {
    register int a0 __asm__("a0") = code;
    register int a7 __asm__("a7") = SYS_EXIT;
    __asm__ volatile("ecall" : : "r"(a0), "r"(a7));
    __builtin_unreachable();
}

static inline void sys_putchar(int c) {
    register int a0 __asm__("a0") = c;
    register int a7 __asm__("a7") = SYS_PUTCHAR;
    __asm__ volatile("ecall" : : "r"(a0), "r"(a7) : "memory");
}

static inline CORE_TICKS sys_get_time(void) {
    register unsigned int a0 __asm__("a0");
    register unsigned int a1 __asm__("a1");
    register int a7 __asm__("a7") = SYS_GET_TIME;
    __asm__ volatile("ecall" : "=r"(a0), "=r"(a1) : "r"(a7));
    return ((CORE_TICKS)a1 << 32) | a0;
}

/************************/
/* Seeds                */
/************************/
#if VALIDATION_RUN
volatile ee_s32 seed1_volatile = 0x3415;
volatile ee_s32 seed2_volatile = 0x3415;
volatile ee_s32 seed3_volatile = 0x66;
#endif
#if PERFORMANCE_RUN
volatile ee_s32 seed1_volatile = 0x0;
volatile ee_s32 seed2_volatile = 0x0;
volatile ee_s32 seed3_volatile = 0x66;
#endif
#if PROFILE_RUN
volatile ee_s32 seed1_volatile = 0x8;
volatile ee_s32 seed2_volatile = 0x8;
volatile ee_s32 seed3_volatile = 0x8;
#endif

volatile ee_s32 seed4_volatile = ITERATIONS;
volatile ee_s32 seed5_volatile = 0;

ee_u32 default_num_contexts = 1;

/************************/
/* Timing               */
/************************/
#define EE_TICKS_PER_SEC 1000000000ULL

static CORE_TICKS start_time_val, stop_time_val;

void start_time(void) {
    start_time_val = sys_get_time();
}

void stop_time(void) {
    stop_time_val = sys_get_time();
}

CORE_TICKS get_time(void) {
    return stop_time_val - start_time_val;
}

secs_ret time_in_secs(CORE_TICKS ticks) {
    return (secs_ret)ticks / (secs_ret)EE_TICKS_PER_SEC;
}

/************************/
/* Portable init/fini   */
/************************/
void portable_init(core_portable *p, int *argc, char *argv[]) {
    (void)argc;
    (void)argv;
    p->portable_id = 1;
}

void portable_fini(core_portable *p) {
    p->portable_id = 0;
}

/************************/
/* Minimal printf       */
/************************/
static void print_str(const char *s) {
    while (*s) {
        sys_putchar(*s++);
    }
}

static void print_unsigned(unsigned int val, int base, int min_digits) {
    char buf[12];
    int i = 0;
    
    if (val == 0) {
        buf[i++] = '0';
    } else {
        while (val > 0) {
            int digit = val % base;
            buf[i++] = (digit < 10) ? ('0' + digit) : ('a' + digit - 10);
            val /= base;
        }
    }
    
    while (i < min_digits) {
        buf[i++] = '0';
    }
    
    while (i > 0) {
        sys_putchar(buf[--i]);
    }
}

static void print_int(int val) {
    if (val < 0) {
        sys_putchar('-');
        val = -val;
    }
    print_unsigned((unsigned int)val, 10, 1);
}

static void print_double(double val, int precision) {
    if (val < 0) {
        sys_putchar('-');
        val = -val;
    }
    
    unsigned int int_part = (unsigned int)val;
    print_unsigned(int_part, 10, 1);
    
    sys_putchar('.');
    
    double frac = val - (double)int_part;
    for (int i = 0; i < precision; i++) {
        frac *= 10.0;
        int digit = (int)frac;
        sys_putchar('0' + digit);
        frac -= digit;
    }
}

/* Minimal ee_printf implementation */
int ee_printf(const char *fmt, ...) {
    __builtin_va_list ap;
    __builtin_va_start(ap, fmt);
    
    int count = 0;
    
    while (*fmt) {
        if (*fmt != '%') {
            sys_putchar(*fmt++);
            count++;
            continue;
        }
        
        fmt++; /* skip '%' */
        
        /* Parse width */
        int width = 0;
        int zero_pad = 0;
        if (*fmt == '0') {
            zero_pad = 1;
            fmt++;
        }
        while (*fmt >= '0' && *fmt <= '9') {
            width = width * 10 + (*fmt - '0');
            fmt++;
        }
        
        /* Parse precision for floats */
        int precision = 6;
        if (*fmt == '.') {
            fmt++;
            precision = 0;
            while (*fmt >= '0' && *fmt <= '9') {
                precision = precision * 10 + (*fmt - '0');
                fmt++;
            }
        }
        
        /* Handle 'l' modifier */
        int is_long = 0;
        if (*fmt == 'l') {
            is_long = 1;
            fmt++;
        }
        
        switch (*fmt) {
            case 'd':
            case 'i': {
                int val = __builtin_va_arg(ap, int);
                print_int(val);
                break;
            }
            case 'u': {
                unsigned int val = __builtin_va_arg(ap, unsigned int);
                print_unsigned(val, 10, width);
                break;
            }
            case 'x':
            case 'X': {
                unsigned int val = __builtin_va_arg(ap, unsigned int);
                print_unsigned(val, 16, width);
                break;
            }
            case 'f': {
                double val = __builtin_va_arg(ap, double);
                print_double(val, precision);
                break;
            }
            case 's': {
                const char *s = __builtin_va_arg(ap, const char *);
                if (s) print_str(s);
                else print_str("(null)");
                break;
            }
            case 'c': {
                int c = __builtin_va_arg(ap, int);
                sys_putchar(c);
                break;
            }
            case 'p': {
                void *ptr = __builtin_va_arg(ap, void *);
                print_str("0x");
                print_unsigned((unsigned int)ptr, 16, 8);
                break;
            }
            case '%':
                sys_putchar('%');
                break;
            default:
                sys_putchar('%');
                sys_putchar(*fmt);
                break;
        }
        fmt++;
    }
    
    __builtin_va_end(ap);
    return count;
}

/************************/
/* Entry point          */
/************************/
extern int main(void);

#define MSTATUS_FS_OFFSET  13
#define MSTATUS_FS_INITIAL (1 << MSTATUS_FS_OFFSET)  /* 0x00002000 */
#define MSTATUS_FS_DIRTY   (3 << MSTATUS_FS_OFFSET)  /* 0x00006000 */

/* _start: setup FPU, stack and call main */
void __attribute__((naked, section(".text.start"))) _start(void) {
    __asm__ volatile(
        /* Enable FPU: set FS = Initial (01) in mstatus */
        "li t0, %0\n"
        "csrs mstatus, t0\n"
        
        /* Clear FCSR (floating-point CSR) */
        "csrw fcsr, zero\n"
        
        /* Setup global pointer */
        ".option push\n"
        ".option norelax\n"
        "la gp, __global_pointer$\n"
        ".option pop\n"
        
        /* Setup stack pointer */
        "la sp, __stack_top\n"
        
        /* Clear BSS section */
        "la t0, __bss_start\n"
        "la t1, __bss_end\n"
        "1:\n"
        "bge t0, t1, 2f\n"
        "sw zero, 0(t0)\n"
        "addi t0, t0, 4\n"
        "j 1b\n"
        "2:\n"
        
        /* Call main */
        "call main\n"
        
        /* Exit with return value from main */
        "mv a0, a0\n"
        "li a7, 0\n"       /* SYS_EXIT */
        "ecall\n"
        
        /* Infinite loop if ecall returns */
        "3: j 3b\n"
        :
        : "i"(MSTATUS_FS_INITIAL)
    );
}
