/* Minimal, stand-alone instrumented TU for CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memcpy_01
 *
 * What we encode:
 *   - Keep the Juliet bad logic, but track the destination capacity explicitly
 *     and assert it before memcpy (safety property for writes).
 *   - Assertion: dest_capacity >= 100 (bytes copied)
 *
 * Notes:
 *   - With the original bad source, dest_capacity = 50 → assertion fails.
 *   - If you later want to vary sizes symbolically, you can #define OVERRIDE_CAP
 *     and have the driver set a symbolic capacity via __klee_source_cap().
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#ifdef KLEE
#  include "klee/klee.h"
#  define CB_ASSERT(c) klee_assert(c)
#else
#  include <assert.h>
#  define CB_ASSERT(c) assert(c)
#endif

/* Juliet std_testcase shims (just enough to link) */
static void printLine(const char *s) { if (s) { fputs(s, stdout); fputc('\n', stdout); } }

/* Optional symbolic capacity override hook (off by default) */
#ifdef OVERRIDE_CAP
static int read_cap(void){
# ifdef USE_KLEE_SOURCE
  extern int __klee_source_cap(void);
  return __klee_source_cap();
# else
  int x = 50; /* default */
  return x;
# endif
}
#endif

/* ===== Instrumented bad() =====
 * Original bad path:
 *   data = malloc(50); ... memcpy(data, source, 100);
 * We add 'int data_capacity = 50;' and assert (data_capacity >= 100) before memcpy.
 */
void CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memcpy_01_bad(void)
{
    char *data = NULL;
    int data_capacity = 50;              /* track destination size explicitly */

#ifdef OVERRIDE_CAP
    /* If you define OVERRIDE_CAP, capacity can be provided by the driver. */
    int maybe_cap = read_cap();
    /* keep it sane to avoid UB in malloc */
    if (maybe_cap > 0 && maybe_cap < (1<<20)) data_capacity = maybe_cap;
#endif

    /* FLAW: small allocation as in Juliet bad source */
    data = (char *)malloc((size_t)data_capacity * sizeof(char));
    if (!data) exit(-1);
    data[0] = '\0';

    /* fixed 100-byte source as in Juliet */
    char source[100];
    memset(source, 'C', 100 - 1);
    source[100 - 1] = '\0';

    /* ===== Injected safety property for write sink =====
       We are about to copy 100 bytes → require capacity >= 100. */
    CB_ASSERT(data_capacity >= 100);

    /* Vulnerable sink (now guarded by the assertion) */
    memcpy(data, source, 100 * sizeof(char));
    data[100 - 1] = '\0';
    printLine(data);
    free(data);
}

#ifdef INCLUDEMAIN
int main(void){
    CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_memcpy_01_bad();
    return 0;
}
#endif
