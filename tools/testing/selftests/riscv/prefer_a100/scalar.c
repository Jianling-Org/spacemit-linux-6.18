// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

/* Build with -march=rv64gc -fno-tree-vectorize: this is a scheduling test. */
int main(void)
{
	volatile uint64_t value = 1;

	printf("pid=%ld ready\n", (long)getpid());
	fflush(stdout);
	for (;;)
		value = value * UINT64_C(6364136223846793005) + 1;
}
