#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <time.h>
#include <sys/resource.h>
#include <glob.h>
#include <string.h>
#include <dlfcn.h>

#include <libwandevent.h>

#include "schedule.h"
#include "watchdog.h"
#include "test.h"
#include "amp_exec.h"



/* 
 * XXX
 * TODO how to do destinations on the command line? talk to shane tomorrow! 
 * XXX
 */
#if 0
void amp_exec_test(test_schedule_item_t *item) {
    char full_path[MAX_PATH_LENGTH];
    test_t *test;
    
    assert(item);
    assert(item->test_id < AMP_TEST_LAST);
    assert(amp_tests[item->test_id]);
    
    test = amp_tests[item->test_id];

    strcpy(full_path, AMP_TEST_DIRECTORY);
    strcat(full_path, test->run_binary);

    printf("Running test: %s (%s)\n", test->name, full_path);
    execl(full_path, test->run_binary, NULL);

    /* should not get to this point */
    perror("execl");
    exit(1);
}
#endif


/*
 * Test function to investigate forking, rescheduling, setting maximum 
 * execution timers etc.
 * TODO maybe just move the contents of this into run_scheduled_test()?
 */
static void fork_test(wand_event_handler_t *ev_hdl,test_schedule_item_t *item) {
    pid_t pid;
    test_t *test;

    assert(item);
    assert(item->test_id < AMP_TEST_LAST);
    assert(amp_tests[item->test_id]);
    
    test = amp_tests[item->test_id];

    if ( (pid = fork()) < 0 ) {
	perror("fork");
	return;
    } else if ( pid == 0 ) {
	/* child, prepare the environment and run the test functions */
	//struct rlimit cpu_limits;
	//cpu_limits.rlim_cur = 60;
	//cpu_limits.rlim_max = 60;
	/* XXX if this kills a test, how to distinguish it from the watchdog
	 * doing so? in this case the watchdog timer still needs to be removed
	 */
	//setrlimit(RLIMIT_CPU, &cpu_limits);
	/* TODO prepare environment */
	/* TODO run pre test setup */
	/* TODO run test */
	//execl("/bin/ping", "ping", "-c", "5", "localhost", NULL);

	if ( test->run_callback == NULL ) {
	    /* if there is no callback just run the binary directly */
	    /*
	    char full_path[MAX_PATH_LENGTH];
	    strcpy(full_path, AMP_TEST_DIRECTORY);
	    strcat(full_path, test->run_binary);
	    printf("Running test: %s (%s)\n", test->name, full_path);
	    execl(full_path, test->run_binary, NULL);
	    perror("execl");
	    */
	    amp_exec_test(item, NULL);
	} else {
	    /* the callback will be responsible for running the binary */
	    test->run_callback(item);
	}

	fprintf(stderr, "%s test failed to run, aborting.\n", test->name);
	exit(1);
    }

    /* schedule the watchdog to kill it if it takes too long */
    add_test_watchdog(ev_hdl, pid, test->max_duration);
}



/*
 * TODO start forking a real program to test with: ls, ping? 
 */
void run_scheduled_test(struct wand_timer_t *timer) {
    schedule_item_t *item = (schedule_item_t *)timer->data;
    test_schedule_item_t *data;
    struct timeval next;

    assert(item->type == EVENT_RUN_TEST);

    data = (test_schedule_item_t *)item->data.test;
    
    printf("running a %s test at %d\n", amp_tests[data->test_id]->name, 
	    (int)time(NULL));
    
    /* 
     * run the test as soon as we know what it is, so it happens as close to 
     * the right time as we can get it.
     */
    fork_test(item->ev_hdl, data);

    /* while the test runs, reschedule it again */
    next = get_next_schedule_time(item->ev_hdl, data->repeat, data->start, 
	    data->end, MS_FROM_TV(data->interval));
    timer->expire = wand_calc_expire(item->ev_hdl, next.tv_sec, next.tv_usec);
    timer->prev = NULL;
    timer->next = NULL;
    wand_add_timer(item->ev_hdl, timer);
}



/*
 *
 */
test_type_t get_test_id(const char *testname) {
    int i;

    for ( i=0; i<AMP_TEST_LAST; i++ ) {
	if ( amp_tests[i] != NULL ) {
	    if ( strcmp(amp_tests[i]->name, testname) == 0 ) {
		return i;
	    }
	}
    }
    return AMP_TEST_INVALID;
}



/*
 * Register all the tests in the given directory as being available.
 */
int register_tests(char *location) {
    glob_t glob_buf;
    void *hdl;
    test_t *new_test;
    const char *error = NULL;
    char full_loc[MAX_PATH_LENGTH];
    uint32_t i;

    
    if ( location == NULL ) {
	/* TODO log error */
	return -1;
    }

    if ( strlen(location) >= MAX_PATH_LENGTH - 6 ) {
	/* TODO log error */
	return -1;
    }

    /* initialise all possible tests to NULL */
    for ( i=0; i<AMP_TEST_LAST; i++ ) {
	amp_tests[i] = NULL;
    }

    /* find all the .so files that exist in the directory */
    strcpy(full_loc, location);
    strcat(full_loc, "/*.so");
    glob(full_loc, 0, NULL, &glob_buf);
    
    printf("Loading test modules from %s (found %zd candidates)\n", 
	    location, glob_buf.gl_pathc);

    for ( i=0; i<glob_buf.gl_pathc; i++ ) {
	hdl = dlopen(glob_buf.gl_pathv[i], RTLD_LAZY);

	if ( !hdl ) {
	    /* TODO log error */
	    printf("failed to dlopen");
	    continue;
	}

	test_reg_ptr r_func = (test_reg_ptr)dlsym(hdl, "register_test");
	if ( (error = dlerror()) != NULL ) {
	    /* it doesn't have this function, it's not one of ours, ignore */
	    printf("failed to find register_test");
	    dlclose(hdl);
	    continue;
	}

	new_test = r_func();

	if ( new_test == NULL ) {
	    /* TODO log error */
	    printf("didn't get useful struct from register_test");
	    dlclose(hdl);
	    continue;
	}

	new_test->dlhandle = hdl;

	/* add the test to the list of all available tests */
	amp_tests[new_test->id] = new_test;
	printf("LOADED %s (%d)\n", new_test->name, new_test->id);
    }

    globfree(&glob_buf);

    return 0;
}


/*
 *
 */
void unregister_tests() {
    int i = 0;
    for ( i=0; i<AMP_TEST_LAST; i++) {
	if ( amp_tests[i] != NULL ) {
	    dlclose(amp_tests[i]->dlhandle);
	    free(amp_tests[i]->name);
	    free(amp_tests[i]->run_binary);
	    free(amp_tests[i]);
	}
    }
}
