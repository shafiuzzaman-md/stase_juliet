/* instrumented_CWE190_Integer_Overflow__int_fscanf_multiply_01.c */
#include <limits.h>
#include "../klee/klee.h"

/* ---- input source: KLEE driver or stdin ---- */
static int read_int(void) {
  extern int __klee_source(void);
  return __klee_source();
}

/* ===== Instrumented bad =====
 * Safety property: data*2 must not overflow → data <= INT_MAX/2
 */
void CWE190_Integer_Overflow__int_fscanf_multiply_01_bad(void)
{
    int data = read_int();

    if (data > 0) {
        /* assertion right before the vulnerable multiply */
        klee_assert(data <= INT_MAX / 2);
        int result = data * 2;
    }
}
