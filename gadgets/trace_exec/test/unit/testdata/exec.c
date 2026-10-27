// SPDX-License-Identifier: Apache-2.0
// Compile with either cc or musl-gcc to exercise both libc implementations.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <wordexp.h>

extern char **environ;

static void fail(const char *operation)
{
	perror(operation);
	exit(1);
}

int main(int argc, char **argv)
{
	if (argc != 3)
		return 1;
	if (!strcmp(argv[1], "system"))
		return system(":") != 0;
	if (!strcmp(argv[1], "popen")) {
		FILE *pipe = popen("printf :", "r");
		if (!pipe)
			fail("popen");
		int value = fgetc(pipe);
		return pclose(pipe) != 0 || value != ':';
	}
	if (!strcmp(argv[1], "wordexp")) {
		wordexp_t words;
		int ret = wordexp("$(printf :)", &words, 0);
		if (ret)
			return 1;
		ret = words.we_wordc != 1 || strcmp(words.we_wordv[0], ":");
		wordfree(&words);
		return ret;
	}

	char *args[] = { "probe-argv0", "cold-argument", NULL };
	if (!strcmp(argv[1], "execveat") ||
	    !strcmp(argv[1], "execveat-empty")) {
		int empty = !strcmp(argv[1], "execveat-empty");
		char *directory = strdup(argv[2]);
		if (!directory)
			fail("strdup");
		char *name = strrchr(directory, '/');
		if (!name)
			return 1;
		*name++ = '\0';
		int fd = open(empty ? argv[2] : directory, O_PATH | O_CLOEXEC);
		if (fd < 0)
			fail("open execveat target");
		syscall(SYS_execveat, fd, empty ? "" : name, args, environ,
			empty ? AT_EMPTY_PATH : 0);
		fail("execveat");
	}

	// Each input occupies a separate, valid file-backed private mapping page.
	// Write the backing file rather than dirtying the mapping: MADV_DONTNEED
	// must drop PTEs without discarding the input bytes needed by execve.
	long size = sysconf(_SC_PAGESIZE);
	int fd = memfd_create("exec-cold-pages", MFD_CLOEXEC);
	if (size <= 0 || fd < 0 || ftruncate(fd, 3 * size))
		fail("create backing file");
	char *mapping = mmap(NULL, 3 * size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (mapping == MAP_FAILED)
		fail("mmap");
	char *mapped_args[] = { mapping + size, mapping + size + 64, NULL };
	size_t path_size = strlen(argv[2]) + 1;
	if (path_size > (size_t)size) {
		errno = ENAMETOOLONG;
		fail("target path");
	}
	const char arg0[] = "probe-argv0";
	const char arg1[] = "cold-argument";
	if (pwrite(fd, argv[2], path_size, 0) != (ssize_t)path_size ||
	    pwrite(fd, arg0, sizeof(arg0), size) != sizeof(arg0) ||
	    pwrite(fd, arg1, sizeof(arg1), size + 64) != sizeof(arg1) ||
	    pwrite(fd, mapped_args, sizeof(mapped_args), 2 * size) !=
		    sizeof(mapped_args))
		fail("write backing file");
	close(fd);
	for (int i = 0; i < 3; i++)
		(void)*(volatile char *)(mapping + i * size);

	unsigned mask;
	if (!strcmp(argv[1], "warm"))
		mask = 0;
	else if (!strcmp(argv[1], "cold-path"))
		mask = 1;
	else if (!strcmp(argv[1], "cold-argument"))
		mask = 2;
	else if (!strcmp(argv[1], "cold-vector"))
		mask = 4;
	else if (!strcmp(argv[1], "cold-all"))
		mask = 7;
	else if (!strncmp(argv[1], "unmapped-", 9)) {
		int page;
		if (!strcmp(argv[1], "unmapped-path"))
			page = 0;
		else if (!strcmp(argv[1], "unmapped-argument"))
			page = 1;
		else if (!strcmp(argv[1], "unmapped-vector"))
			page = 2;
		else
			return 1;
		if (munmap(mapping + page * size, size))
			fail("munmap");
		syscall(SYS_execve, mapping, mapping + 2 * size, environ);
		return errno != EFAULT;
	} else {
		return 1;
	}
	for (int i = 0; i < 3; i++) {
		if ((mask & (1U << i)) &&
		    madvise(mapping + i * size, size, MADV_DONTNEED))
			fail("madvise");
	}
	execve(mapping, (char **)(mapping + 2 * size), environ);
	fail("execve");
}
