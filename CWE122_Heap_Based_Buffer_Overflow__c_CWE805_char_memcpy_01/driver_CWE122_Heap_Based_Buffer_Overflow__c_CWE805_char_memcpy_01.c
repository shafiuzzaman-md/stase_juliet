/* KLEE driver for CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memcpy_01
 *
 * Pattern: provide symbolic knobs (optional), include instrumented TU,
 *          then call the bad entrypoint.
 */

#include "klee/klee.h"

/* Optional symbolic capacity override used only if TU compiled with -DOVERRIDE_CAP */
int __klee_source_cap(void) {
    int cap;
    klee_make_symbolic(&cap, sizeof(cap), "dest_capacity");
    /* keep it within a practical range for search */
    klee_assume(cap >= 1 && cap <= 256);
    return cap;
}

/* Pull in the instrumented implementation directly */
#define USE_KLEE_SOURCE
#define OVERRIDE_CAP          /* remove this line if you want the original fixed 50 bytes */
#include "instrumented_CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memcpy_01.c"

int main(void) {
    CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memcpy_01_bad();
    return 0;
}
