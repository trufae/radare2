#include <r_util.h>
#include <r_socket.h>
#include "minunit.h"

bool test_r2pipe(void) {
	// R2Pipe *r = r2pipe_open ("/usr/local/bin/r2");
	R2Pipe *r = r2pipe_open ("r2 -q0 -");
	mu_assert("r2pipe can spawn", r);
	char *hello = r2pipe_cmd (r, "?e hello world");
	mu_assert_streq(hello, "hello world\n", "r2pipe hello world");
	free (hello);
	r2pipe_close (r);
	mu_end;
}

int all_tests() {
	mu_run_test(test_r2pipe);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
