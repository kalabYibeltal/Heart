// pstate_latency.c — measure software-requested P-state transition latency.
//
// Method: pin to one CPU, run a fixed dependent-ALU loop of constant cycle
// count and timestamp every iteration with rdtsc (TSC is invariant, so an
// iteration's TSC duration is inversely proportional to core frequency).
// For each trial: hold ratio A for --settle ms, calibrate the steady-state
// iteration period at A and B, then write IA32_PERF_CTL=B and record how long
// (TSC time) until iteration periods are within 3% of B's steady state.
// Also reports the longest single-iteration gap (the core halts during the
// voltage/frequency switch on many Intel parts).
//
// On HWP CPUs (IA32_PM_ENABLE=1, e.g. c220g5) it writes IA32_HWP_REQUEST
// min=max=ratio instead (auto-detected; set hwp_dynamic_boost=0 first) and
// restores the original request at exit.
// Otherwise requires root, `modprobe msr`, and intel_pstate in passive mode with the
// userspace governor (defense/scripts/hbctl.sh pstate-passive) so the kernel
// does not fight the PERF_CTL writes.
//
// Usage: sudo ./pstate_latency <cpu> <ratioA> <ratioB> [trials=50]
// Output (stdout, CSV): trial,from,to,latency_us,max_gap_us
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <fcntl.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <x86intrin.h>

#define ITER_WORK 2000   // dependent adds per iteration (~2000 cycles)
#define MAX_ITERS 200000 // enough for >100 ms at 800 MHz

static uint64_t ts[MAX_ITERS];

static inline void work(void)
{
	uint64_t x = 1;
	for (int i = 0; i < ITER_WORK; i++)
		asm volatile("add $1, %0" : "+r"(x));
}

static int msr_fd;
static int sib_fd[8], nsib;  // HWP: SMT siblings' msr fds (core window = max over siblings)
static uint64_t sib_orig[8];
static int hwp;              // IA32_PM_ENABLE[0]: HWP owns P-states, PERF_CTL ignored
static uint64_t hwp_orig;    // IA32_HWP_REQUEST at start (restored at exit)
static void set_ratio(uint64_t r)
{
	r &= 0xff;
	uint64_t v = hwp ? (hwp_orig & ~0xffffffULL) | r << 8 | r : r << 8;
	if (pwrite(msr_fd, &v, 8, hwp ? 0x774 : 0x199) != 8) {
		perror(hwp ? "pwrite HWP_REQUEST" : "pwrite PERF_CTL");
		exit(1);
	}
	for (int i = 0; i < nsib; i++)  // siblings AFTER own cpu: latency t0 is own write
		if (pwrite(sib_fd[i], &v, 8, 0x774) != 8) { perror("pwrite sibling HWP_REQUEST"); exit(1); }
}
static void restore_hwp(void)
{
	if (hwp && pwrite(msr_fd, &hwp_orig, 8, 0x774) != 8) perror("restore HWP_REQUEST");
	for (int i = 0; i < nsib; i++)
		if (pwrite(sib_fd[i], &sib_orig[i], 8, 0x774) != 8) perror("restore sibling HWP_REQUEST");
}

static double tsc_per_us(void)
{
	struct timespec a, b;
	clock_gettime(CLOCK_MONOTONIC_RAW, &a);
	uint64_t t0 = __rdtsc();
	do clock_gettime(CLOCK_MONOTONIC_RAW, &b);
	while ((b.tv_sec - a.tv_sec) * 1e9 + (b.tv_nsec - a.tv_nsec) < 2e8);
	uint64_t t1 = __rdtsc();
	return (t1 - t0) / (((b.tv_sec - a.tv_sec) * 1e9 + (b.tv_nsec - a.tv_nsec)) / 1e3);
}

// median iteration period (TSC ticks) over n iterations
static double steady_period(int n)
{
	static uint64_t d[4096];
	if (n > 4096) n = 4096;
	uint64_t prev = __rdtsc();
	for (int i = 0; i < n; i++) {
		work();
		uint64_t now = __rdtsc();
		d[i] = now - prev;
		prev = now;
	}
	// insertion sort is fine for 4096
	for (int i = 1; i < n; i++) {
		uint64_t k = d[i]; int j = i - 1;
		while (j >= 0 && d[j] > k) { d[j + 1] = d[j]; j--; }
		d[j + 1] = k;
	}
	return d[n / 2];
}

static void spin_ms(double ms, double tpu)
{
	uint64_t end = __rdtsc() + (uint64_t)(ms * 1000 * tpu);
	while (__rdtsc() < end) work();
}

int main(int argc, char **argv)
{
	if (argc < 4) {
		fprintf(stderr, "usage: %s <cpu> <ratioA> <ratioB> [trials]\n", argv[0]);
		return 1;
	}
	int cpu = atoi(argv[1]);
	uint64_t ra = strtoull(argv[2], 0, 0), rb = strtoull(argv[3], 0, 0);
	int trials = argc > 4 ? atoi(argv[4]) : 50;
	double settle_ms = 50;

	cpu_set_t set;
	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	if (sched_setaffinity(0, sizeof(set), &set)) { perror("affinity"); return 1; }
	char path[64];
	snprintf(path, sizeof path, "/dev/cpu/%d/msr", cpu);
	if ((msr_fd = open(path, O_RDWR)) < 0) { perror(path); return 1; }

	uint64_t pm = 0;
	if (pread(msr_fd, &pm, 8, 0x770) == 8 && (pm & 1)) {
		hwp = 1;
		if (pread(msr_fd, &hwp_orig, 8, 0x774) != 8) { perror("pread HWP_REQUEST"); return 1; }
		char sp[96], buf[64];
		snprintf(sp, sizeof sp, "/sys/devices/system/cpu/cpu%d/topology/thread_siblings_list", cpu);
		FILE *tf = fopen(sp, "r");
		if (tf && fgets(buf, sizeof buf, tf)) {
			for (char *tok = strtok(buf, ",\n"); tok && nsib < 8; tok = strtok(0, ",\n")) {
				int a = atoi(tok), b = strchr(tok, '-') ? atoi(strchr(tok, '-') + 1) : a;
				for (int c = a; c <= b && nsib < 8; c++) {
					if (c == cpu) continue;
					snprintf(path, sizeof path, "/dev/cpu/%d/msr", c);
					if ((sib_fd[nsib] = open(path, O_RDWR)) < 0) { perror(path); return 1; }
					if (pread(sib_fd[nsib], &sib_orig[nsib], 8, 0x774) != 8) { perror("pread sibling"); return 1; }
					fprintf(stderr, "HWP sibling cpu%d also written\n", c);
					nsib++;
				}
			}
		}
		if (tf) fclose(tf);
		atexit(restore_hwp);
		fprintf(stderr, "HWP enabled: using IA32_HWP_REQUEST min=max (orig 0x%lx)\n", hwp_orig);
	}

	double tpu = tsc_per_us();
	fprintf(stderr, "TSC %.1f ticks/us\n", tpu);

	set_ratio(rb); spin_ms(settle_ms, tpu);
	double pb = steady_period(4096);
	set_ratio(ra); spin_ms(settle_ms, tpu);
	double pa = steady_period(4096);
	fprintf(stderr, "steady period: ratio %lu = %.0f ticks, ratio %lu = %.0f ticks (ratio of periods %.3f, expected %.3f)\n",
		ra, pa, rb, pb, pa / pb, (double)rb / ra);

	printf("trial,from,to,latency_us,max_gap_us\n");
	for (int t = 0; t < trials; t++) {
		set_ratio(ra);
		spin_ms(settle_ms, tpu);
		uint64_t t0 = __rdtsc();
		set_ratio(rb);
		int n = 0;
		uint64_t prev = __rdtsc();
		uint64_t deadline = prev + (uint64_t)(100000 * tpu); // 100 ms
		while (n < MAX_ITERS && prev < deadline) {
			work();
			prev = ts[n++] = __rdtsc();
		}
		// latency = end of first run of 20 consecutive iterations within 3% of pb
		double lat = -1, maxgap = 0;
		int run = 0;
		uint64_t last = t0;
		for (int i = 0; i < n; i++) {
			double d = (double)(ts[i] - last);
			if (d > maxgap) maxgap = d;
			if (d > 0.97 * pb && d < 1.03 * pb) {
				if (++run == 20) { lat = (ts[i - 19] - t0 - pb) / tpu; break; }
			} else run = 0;
			last = ts[i];
		}
		printf("%d,%lu,%lu,%.2f,%.2f\n", t, ra, rb, lat, (maxgap - pb) / tpu);
	}
	return 0;
}
