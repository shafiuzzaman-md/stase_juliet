/* driver_CWE122_Heap_Based_Buffer_Overflow__c_CWE805_wchar_t_memmove_01.c
 *
 * KLEE driver:
 *  - Exposes a symbolic copy length via __klee_source().
 *  - Includes the instrumented TU and calls the Juliet bad entrypoint.
 */

#include "../klee/klee.h"

/* Symbolic source used by the instrumented TU */
int __klee_source(void) {
    int copy_len;
    klee_make_symbolic(&copy_len, sizeof(copy_len), "copy_len");
    /* Helpful bounds; adjust/remove as needed */
    klee_assume(copy_len >= 0);
    klee_assume(copy_len <= 120);  /* a bit beyond 100 to allow exploration */
    return copy_len;
}

/* Pull in the instrumented implementation */
#include "instrumented_CWE122_Heap_Based_Buffer_Overflow__c_CWE805_wchar_t_memmove_01.c"

int main(void) {
    CWE122_Heap_Based_Buffer_Overflow__c_CWE805_wchar_t_memmove_01_bad();
    return 0;
}
