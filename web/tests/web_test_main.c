#include <signal.h>

#include "wtest.h"

int wt_pass, wt_fail;

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    run_acl_tests();
    run_config_tests();
    run_http_tests();
    run_routes_tests();
    run_server_tests();
    printf("slothweb tests: %d passed, %d failed\n", wt_pass, wt_fail);
    return wt_fail ? 1 : 0;
}
