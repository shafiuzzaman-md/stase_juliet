/* instrumented_CWE122_Heap_Based_Buffer_Overflow__c_CWE805_wchar_t_memmove_01.c
 *
 * Minimal, stand-alone instrumented TU for KLEE:
 *  - Keeps Juliet bad path semantics (small heap dst, large src).
 *  - Makes copy length symbolic when USE_KLEE_SOURCE is defined.
 *  - Injects klee_assert to encode "no heap OOB write".
 *
 * Build with KLEE:
 *   clang -I$KLEE_INCLUDE_DIR -DKLEE -DUSE_KLEE_SOURCE -c driver_*.c -emit-llvm -o driver.bc
 *   klee driver.bc
 */

#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <wchar.h>

#ifdef KLEE
#  include "../klee/klee.h"
#  define CB_ASSERT(e) klee_assert(e)
#else
#  include <assert.h>
#  define CB_ASSERT(e) assert(e)
#endif

/* Juliet std_testcase shims (enough to link) */
static void printWLine(const wchar_t *ws) {
  if (ws) { /* print narrow fallback */ fputws(ws, stdout); fputwc(L'\n', stdout); }
}

/* If compiled with -DUSE_KLEE_SOURCE, pull copy length from driver; else 100 */
static int read_copy_len_default_100(void) {
#ifdef USE_KLEE_SOURCE
  extern int __klee_source(void);
  return __klee_source();
#else
  return 100;
#endif
}

/* ===== Instrumented bad() ==================================================
 * Juliet bad pattern:
 *   - alloc dst = malloc(50 * sizeof(wchar_t))  (too small)
 *   - src is 100 wchar_t 'C'
 *   - memmove(dst, src, 100*sizeof(wchar_t))    <-- overflow
 *
 * We preserve allocation sizes but let the third memmove argument be
 * a variable 'copy_len' (symbolic under KLEE). Assertion before the sink:
 *
 *     CB_ASSERT(copy_len <= alloc_wchars);
 *
 * A counterexample corresponds to a heap OOB write.
 * ==========================================================================*/
void CWE122_Heap_Based_Buffer_Overflow__c_CWE805_wchar_t_memmove_01_bad(void)
{
    /* Small destination heap buffer (50 wchar_t), exactly as in Juliet */
    size_t alloc_wchars = 50;
    wchar_t *data = (wchar_t *)malloc(alloc_wchars * sizeof(wchar_t));
    if (!data) exit(-1);
    data[0] = L'\0';

    /* Source buffer initialized to 100 'C' (as in Juliet) */
    wchar_t source[100];
    wmemset(source, L'C', 100 - 1);
    source[100 - 1] = L'\0';

    /* Make the copy length a value tools can control */
    int copy_len = read_copy_len_default_100(); /* in wchar_t units */
#ifdef KLEE
    /* Friendly bounds so KLEE doesn't explode; feel free to remove or widen */
    klee_assume(copy_len >= 0 && copy_len <= 120);
#endif

    /* ---- Injected safety assertion right before the sink ----
       We assert that we won't write past 'data' (heap OOB write guard). */
    CB_ASSERT((size_t)copy_len <= alloc_wchars);

    /* Vulnerable sink (now guarded by the assertion) */
    memmove(data, source, (size_t)copy_len * sizeof(wchar_t));
    data[alloc_wchars - 1] = L'\0';
    printWLine(data);

    free(data);
}

/* Optional native harness for quick testing (remove if not needed)
#ifdef INCLUDEMAIN
int main(void) {
  CWE122_Heap_Based_Buffer_Overflow__c_CWE805_wchar_t_memmove_01_bad();
  return 0;
}
#endif
*/
