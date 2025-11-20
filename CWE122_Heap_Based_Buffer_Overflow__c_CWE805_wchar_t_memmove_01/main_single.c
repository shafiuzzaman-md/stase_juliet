/* main_single.c for CWE122_Heap_Based_Buffer_Overflow__c_CWE805_wchar_t_memmove_01
 *
 * This is the ONLY entrypoint tools need.
 * It models:
 *   (1) Attacker input: CB.plane[0..plane_len) loaded from payload model
 *   (2) Exposure channel (STDIN / ENV / FILE)
 *   (3) ONE abstract region + ONE abstract effect
 *   (4) Call Juliet's CWE122_Heap_Based_Buffer_Overflow__c_CWE805_wchar_t_memmove_01_bad()
 *
 * To run:
 *   - STDIN mode: put bytes in "payload.bin" next to the app (REQUIRED).
 *   - ENV  mode:  set the content in your launcher, or place payload.bin and
 *                 we will copy it into ENV["ADD"] as a C-string.
 *   - FILE mode:  same; we write "input.bin" with payload bytes.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>  
#include <errno.h>
#include "state.h"

/* Juliet entrypoint (provided by source.c) */
int CWE122_Heap_Based_Buffer_Overflow__c_CWE805_wchar_t_memmove_01_bad(void);

/* ------------------ payload helpers ------------------ */

/* Load bytes from "payload.bin" if present; return length, or -1 if missing. */
static long read_payload_file(unsigned char* buf, size_t cap){
  FILE* f = fopen("payload.bin","rb");
  if (!f) return -1;
  size_t n = fread(buf,1,cap ? cap-1 : 0,f);
  fclose(f);
  if (cap) buf[n] = '\0'; /* C-string friendly for ENV/FILE users */
  return (long)n;
}

/* Load into CB.plane; caller decides what to do on missing file. */
static int load_payload_into_plane(void){
  memset(CB.plane, 0, sizeof(CB.plane));
  CB.plane_len = 0;
  long n = read_payload_file(CB.plane, sizeof(CB.plane));
  if (n < 0) return 0;            /* not found */
  CB.plane_len = (unsigned)n;
  return 1;                       /* loaded */
}

/* Expose CB.plane -> STDIN (dup2 temp file to stdin). */
static void expose_stdin(void){
  FILE* tmp = tmpfile(); if(!tmp) return;
  if (CB.plane_len) fwrite(CB.plane, 1, CB.plane_len, tmp);
  fflush(tmp); fseek(tmp, 0, SEEK_SET);
  dup2(fileno(tmp), fileno(stdin));
}

/* Expose CB.plane -> ENV["ADD"] */
static void expose_env(void){
  if (CB.plane_len == 0) { CB.plane[0] = '\0'; CB.plane_len = 1; }
  else CB.plane[CB.plane_len-1] = '\0';
  setenv("ADD", (const char*)CB.plane, 1);
}

/* Expose CB.plane -> file "input.bin" */
static void expose_file(void){
  FILE* f = fopen("input.bin", "wb"); if (!f) return;
  if (CB.plane_len) fwrite(CB.plane, 1, CB.plane_len, f);
  fclose(f);
}

/* ------------------ main: input + effect + call ------------------ */

int main(void){
  cb_reset();

  /* (1) attacker input */
  int have_payload = load_payload_into_plane();

  /* (2) exposure channel (from YAML "io") */
#if 1
  if (!have_payload) {
    fprintf(stderr, "[CB] ERROR: STDIN mode requires payload.bin next to the app.\n");
    return 2;
  }
  expose_stdin();
#endif

#if 0
  if (!have_payload) {
    /* ENV mode: missing payload.bin is allowed; ENV becomes empty string */
    CB.plane[0] = '\0'; CB.plane_len = 1;
  }
  expose_env();
#endif

#if 0
  if (!have_payload) {
    /* FILE mode: missing payload.bin → empty file */
    CB.plane_len = 0;
  }
  expose_file();
#endif

  /* (3) abstract region + effect (from YAML) */
  uint32_t rid = cb_region(SEG_HEAP, 0, 1);
  cb_effect_push(rid, 0, 0, ACT_WRITE);

  /* (4) run the vulnerable path */
  (void)CWE122_Heap_Based_Buffer_Overflow__c_CWE805_wchar_t_memmove_01_bad();

  printf("[CB] single_done effects=%u regions=%u payload_len=%u\n",
         CB.effect_count, CB.region_count, CB.plane_len);
  return 0;
}
