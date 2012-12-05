#ifndef _MEASURED_TEST_H
#define _MEASURED_TEST_H

#include <stdint.h>
#include <libwandevent.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>


/* TODO move elsewhere to more global config file */
#define MAX_PATH_LENGTH 10000

typedef enum {
    AMP_TEST_INVALID,
    AMP_TEST_SKELETON,
    AMP_TEST_SKELETON_CALLBACK,
    AMP_TEST_ICMP,
    AMP_TEST_DNS,
    AMP_TEST_LAST,
} test_type_t;

struct test_schedule_item;


typedef struct test {
    /* */
    test_type_t id;

    /* 
     * Name of the test, used for schedule files and reporting. It is 
     * traditionally fairly short though still descriptive, a single word 
     * with no spaces.
     */
    char *name;

    /* 
     * Maximum number of targets this test can operate on in a single instance.
     * If more targets are specified then multiple instances of the test will 
     * be run. A value of 0 means there is no limit.
     */
    uint16_t max_targets;

    /* 
     * Maximum duration in seconds that this test can run for. If the test runs
     * for longer than this it will be killed with a SIGKILL.
     */
    uint16_t max_duration;

#if 0
    /* 
     * Pointer to a function that will perform any pre-test configuration
     * that is required (such as starting remote programs). It can report any
     * extra configuration information to the test through the return value.
     * If no extra setup or configuration is required this pointer can be null.
     */
    void * (*setup_callback)(void *data);

    /*
     * Pointer to a function that will convert the extra configuration into
     * useful arguments to the binary and passes them through to amp_test_exec.
     */
    void (*run_callback)(/*test_info_t *info, */void *data);
#endif

    /*
     * Pointer to a function that will perform any pre-test configuration that
     * is required (such as asking a remote measured process to start server 
     * programs or negotiating port numbers). It is also a chance to add any
     * negotiated or calculated values as command line options to the test
     * binary. This function is also responsible for starting the test.
     */
    //void (*run_callback)(const struct test_schedule_item * const info);
    int (*run_callback)(int argc, char *argv[], int count, 
	    struct addrinfo **dests);

#if 0
    /*
     * A string containing the name of the binary that should be run to perform
     * this test. The name will be taken relative to the test path configured
     * by XXX
     */
    char *run_binary;
#endif

    /* 
     * Pointer to the module that implements the callback functions for
     * this test.
     */
    void *dlhandle;
} test_t;

/* Array containing pointers to all the available tests. */
test_t *amp_tests[AMP_TEST_LAST];


typedef test_t * (*test_reg_ptr) ();

test_type_t get_test_id(const char *testname);
int register_tests(char *location);
void unregister_tests(void);
void run_scheduled_test(struct wand_timer_t *timer);
#endif
