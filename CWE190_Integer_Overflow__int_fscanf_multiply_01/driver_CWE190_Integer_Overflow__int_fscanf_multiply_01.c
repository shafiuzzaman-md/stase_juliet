/* driver_CWE190_Integer_Overflow__int_fscanf_multiply_01.c */
#include "../klee/klee.h"

/* symbolic source consumed by the instrumented file */
int __klee_source(void) {
    int data;
    klee_make_symbolic(&data, sizeof(data), "data");
    return data;
}

/* pull in the instrumented TU after the KLEE include */
#define USE_KLEE_SOURCE 1
#include "instrumented_CWE190_Integer_Overflow__int_fscanf_multiply_01.c"

int main(void) {
    CWE190_Integer_Overflow__int_fscanf_multiply_01_bad();
    return 0;
}
