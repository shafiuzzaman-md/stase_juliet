# Per-item Makefile (Linux)
CC ?= cc
CFLAGS ?= -O2 -g -std=c11 -Wall -Wextra
CFLAGS += -D_POSIX_C_SOURCE=200809L

INCLUDE = -I ../../include -I ../../src
# Optional: interpose libc I/O with tiny loggers (getenv/fgets/fread)
INCLUDE += -include ../../include/cb_interpose.h

SUPPORT_SRCS = $(wildcard ../../support/*.c)
SRCS = main_single.c source.c ../../src/state.c ../../src/cb_io.c $(SUPPORT_SRCS)

all: app
app: $(SRCS)
	$(CC) $(CFLAGS) $(INCLUDE) $(SRCS) -o $@

clean:
	rm -f app
