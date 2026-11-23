CFLAGS := -O2 -Wall -D_GNU_SOURCE
all: pstate_latency
pstate_latency: pstate_latency.c
	$(CC) $(CFLAGS) -o $@ $<
clean:
	rm -f pstate_latency
.PHONY: all clean
