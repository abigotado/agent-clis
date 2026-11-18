// inject.c is the library TestHardenedRuntimeRefusesInjection puts in
// DYLD_INSERT_LIBRARIES. Its constructor runs when, and only when, the dynamic
// loader loads it into a process, and then writes a marker file named by
// SECRETSTORE_INJECT_MARKER. The marker holds a fixed word and nothing else.
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor)) static void secretstore_inject_marker(void) {
	const char *path = getenv("SECRETSTORE_INJECT_MARKER");
	if (path == NULL) {
		return;
	}
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0) {
		return;
	}
	static const char word[] = "loaded\n";
	ssize_t written = write(fd, word, sizeof(word) - 1);
	(void)written; // a short write still leaves the file, which is all the test reads
	close(fd);
}
