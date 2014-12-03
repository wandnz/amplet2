#include <stdio.h>
#include <assert.h>
#include <string.h>
#include "schedule.h"


typedef struct test_schedule {
    char repeat;
    struct timeval offset;
    uint64_t start;
    uint64_t end;
    uint64_t freq;
} test_schedule_t;


/*
 * Make sure that specific time periods start at the correct time and have
 * the appropriate duration.
 */
static void check_period_time(void) {
    /* check the Hourly, Daily, Weekly identifiers get the correct duration */
    assert(amp_test_get_period_max_value(SCHEDULE_PERIOD_HOURLY) == 60*60);
    assert(amp_test_get_period_max_value(SCHEDULE_PERIOD_DAILY) == 60*60*24);
    assert(amp_test_get_period_max_value(SCHEDULE_PERIOD_WEEKLY) == 60*60*24*7);

    /* check that the period start values are the start of the period */
    assert(amp_test_get_period_start(SCHEDULE_PERIOD_HOURLY) % 60 == 0);
    assert(amp_test_get_period_start(SCHEDULE_PERIOD_DAILY) % 86400 == 0);
    /* weekly period is awkward cause 01-01-1970 is Thursday and Sunday is 0 */
    assert((amp_test_get_period_start(SCHEDULE_PERIOD_WEEKLY) +
                60*60*24*4) % 604800 == 0);
}



/*
 * Check that the time values are correctly parsed and fit within the period.
 */
static void check_time_parsing(void) {
    /* check that hourly repeated times are correctly validated */
    assert(amp_test_check_time_range(0, SCHEDULE_PERIOD_HOURLY) == 0);
    assert(amp_test_check_time_range(1000000,
                SCHEDULE_PERIOD_HOURLY) == 1000000);
    assert(amp_test_check_time_range(60000000,
                SCHEDULE_PERIOD_HOURLY) == 60000000);
    assert(amp_test_check_time_range(3600000000,
                SCHEDULE_PERIOD_HOURLY) == 3600000000);
    assert(amp_test_check_time_range(-1,
                SCHEDULE_PERIOD_HOURLY) == -1);
    assert(amp_test_check_time_range(-12345,
                SCHEDULE_PERIOD_HOURLY) == -1);
    assert(amp_test_check_time_range(3600000001,
                SCHEDULE_PERIOD_HOURLY) == -1);
    assert(amp_test_check_time_range(86400000000,
                SCHEDULE_PERIOD_HOURLY) == -1);
    assert(amp_test_check_time_range(86400000001,
                SCHEDULE_PERIOD_HOURLY) == -1);
    assert(amp_test_check_time_range(604800000000,
                SCHEDULE_PERIOD_HOURLY) == -1);
    assert(amp_test_check_time_range(604800000001,
                SCHEDULE_PERIOD_HOURLY) == -1);

    /* check that daily repeated times are correctly validated */
    assert(amp_test_check_time_range(0, SCHEDULE_PERIOD_DAILY) == 0);
    assert(amp_test_check_time_range(1000000,
                SCHEDULE_PERIOD_DAILY) == 1000000);
    assert(amp_test_check_time_range(60000000,
                SCHEDULE_PERIOD_DAILY) == 60000000);
    assert(amp_test_check_time_range(3600000000,
                SCHEDULE_PERIOD_DAILY) == 3600000000);
    assert(amp_test_check_time_range(3600000001,
                SCHEDULE_PERIOD_DAILY) == 3600000001);
    assert(amp_test_check_time_range(86400000000,
                SCHEDULE_PERIOD_DAILY) == 86400000000);
    assert(amp_test_check_time_range(-1,
                SCHEDULE_PERIOD_DAILY) == -1);
    assert(amp_test_check_time_range(-12345,
                SCHEDULE_PERIOD_DAILY) == -1);
    assert(amp_test_check_time_range(86400000001,
                SCHEDULE_PERIOD_DAILY) == -1);
    assert(amp_test_check_time_range(604800000000,
                SCHEDULE_PERIOD_DAILY) == -1);
    assert(amp_test_check_time_range(604800000001,
                SCHEDULE_PERIOD_DAILY) == -1);

    /* check that weekly repeated times are correctly validated */
    assert(amp_test_check_time_range(0, SCHEDULE_PERIOD_WEEKLY) == 0);
    assert(amp_test_check_time_range(1000000,
                SCHEDULE_PERIOD_WEEKLY) == 1000000);
    assert(amp_test_check_time_range(60000000,
                SCHEDULE_PERIOD_WEEKLY) == 60000000);
    assert(amp_test_check_time_range(3600000000,
                SCHEDULE_PERIOD_WEEKLY) == 3600000000);
    assert(amp_test_check_time_range(3600000001,
                SCHEDULE_PERIOD_WEEKLY) == 3600000001);
    assert(amp_test_check_time_range(86400000000,
                SCHEDULE_PERIOD_WEEKLY) == 86400000000);
    assert(amp_test_check_time_range(86400000001,
                SCHEDULE_PERIOD_WEEKLY) == 86400000001);
    assert(amp_test_check_time_range(604800000000,
                SCHEDULE_PERIOD_WEEKLY) == 604800000000);
    assert(amp_test_check_time_range(-1,
                SCHEDULE_PERIOD_WEEKLY) == -1);
    assert(amp_test_check_time_range(-12345,
                SCHEDULE_PERIOD_WEEKLY) == -1);
    assert(amp_test_check_time_range(604800000001,
                SCHEDULE_PERIOD_WEEKLY) == -1);

}



/*
 * Check that the next scheduled times are correct.
 */
static void check_next_schedule_time(void) {
    wand_event_handler_t ev_hdl;
    struct timeval offset;
    int i, count;
    struct test_schedule schedule[] = {
        /* daily */
        /* period start */
        {SCHEDULE_PERIOD_DAILY, {0, 0}, 0, 86400000, 30000},
        /* period end */
        {SCHEDULE_PERIOD_DAILY, {30, 0}, 0, 86400000, 30000},
        /* 1s into period */
        {SCHEDULE_PERIOD_DAILY, {1, 0}, 0, 86400000, 60000},
        /* 1s before period end */
        {SCHEDULE_PERIOD_DAILY, {89, 0}, 0, 86400000, 90000},
        /* 0.5s into period */
        {SCHEDULE_PERIOD_DAILY, {0, 500000}, 0, 86400000, 30000},
        /* 10.9s into period */
        {SCHEDULE_PERIOD_DAILY, {10, 900000}, 0, 86400000, 60000},
        /* very early end time */
        {SCHEDULE_PERIOD_DAILY, {9, 900000}, 0, 10000, 10000},
        /* very early end time */
        {SCHEDULE_PERIOD_DAILY, {10, 900000}, 0, 10000, 10000},
        /* early end time, cycle */
        {SCHEDULE_PERIOD_DAILY, {86398, 123000}, 0, 80000000, 10000},
        /* cycle to next period */
        {SCHEDULE_PERIOD_DAILY, {86398, 123000}, 0, 86400000, 10000},
        /* frequency 0 */
        {SCHEDULE_PERIOD_DAILY, {123, 123000}, 0, 0, 0},
        /* freq 0, late start */
        {SCHEDULE_PERIOD_DAILY, {35, 987000}, 60000, 0, 0},
        /* late start before time */
        {SCHEDULE_PERIOD_DAILY, {61, 0}, 360000, 86400000, 60000},
        /* late start after time */
        {SCHEDULE_PERIOD_DAILY, {361, 0}, 360000, 86400000, 60000},

        /* weekly */
        /* period start */
        {SCHEDULE_PERIOD_WEEKLY, {0, 0}, 0, 604800000, 30000},
        /* period end */
        {SCHEDULE_PERIOD_WEEKLY, {30, 0}, 0, 604800000, 30000},
        /* 1s into period */
        {SCHEDULE_PERIOD_WEEKLY, {1, 0}, 0, 604800000, 60000},
        /* 1s before period end */
        {SCHEDULE_PERIOD_WEEKLY, {604799, 0}, 0, 604800000, 90000},
        /* 0.567890 into period */
        {SCHEDULE_PERIOD_WEEKLY, {0, 567000}, 0, 604800000, 30000},
        /* 10.9s into period */
        {SCHEDULE_PERIOD_WEEKLY, {10, 900000}, 0, 604800000, 60000},
        /* 1 day frequency */
        {SCHEDULE_PERIOD_WEEKLY, {68, 500000}, 0, 604800000, 86400000},
        /* last cycle in period */
        {SCHEDULE_PERIOD_WEEKLY, {10000, 0}, 0, 10000000, 10000},
        /* frequency 0 */
        {SCHEDULE_PERIOD_WEEKLY, {123, 123000}, 0, 0, 0},
        /* freq 0, late start */
        {SCHEDULE_PERIOD_WEEKLY, {86000, 987000}, 86400000, 0, 0},
        /* late start before time */
        {SCHEDULE_PERIOD_WEEKLY, {61, 0}, 360000, 604800000, 60000},
        /* late start after time*/
        {SCHEDULE_PERIOD_WEEKLY, {361, 0}, 360000, 86400000, 60000},
    };
    struct timeval expected[] = {
        /* daily */
        {30, 0},
        {30, 0},
        {59, 0},
        {1, 0},
        {29, 500000},
        {49, 100000},
        {0, 100000},
        {86389, 100000},
        {1, 877000},
        {1, 877000},
        {86276, 877000},
        {24, 13000},
        {299, 0},
        {59, 0},
        /* weekly */
        {30, 0},
        {30, 0},
        {59, 0},
        {1, 0},
        {29, 433000},
        {49, 100000},
        {86331, 500000},
        {594800, 0},
        {604676, 877000},
        {399, 13000},
        {299, 0},
        {59, 0},
    };

    memset(&ev_hdl, 0, sizeof(ev_hdl));
    ev_hdl.walltimeok = 1;

    assert((sizeof(schedule) / sizeof(struct test_schedule)) ==
            sizeof(expected) / sizeof(struct timeval));
    count = sizeof(schedule) / sizeof(struct test_schedule);

    for ( i = 0; i < count; i++ ) {
        /* set offset from start of period to be the "now" time */
        ev_hdl.walltime.tv_sec = amp_test_get_period_start(schedule[i].repeat) +
            schedule[i].offset.tv_sec;
        ev_hdl.walltime.tv_usec = schedule[i].offset.tv_usec;

        /*
         * start, end and freq are all now in usec rather than msec, easier to
         * just change them here rather than add a heap of zeroes above
         */
        /* get when the algorithm thinks the next scheduled test should be */
        offset = get_next_schedule_time(&ev_hdl, schedule[i].repeat,
                schedule[i].start*1000, schedule[i].end*1000,
                schedule[i].freq*1000, 0, NULL);

        /*
        printf("%d\t%d.%d vs %d.%d\n", i, offset.tv_sec, offset.tv_usec,
                expected[i].tv_sec, expected[i].tv_usec);
        */

        /* check that it is correct */
        assert(offset.tv_sec == expected[i].tv_sec);
        assert(offset.tv_usec == expected[i].tv_usec);
    }
}



/*
 * Test the timing functions used in scheduling.
 */
int main(void) {

    check_period_time();
    check_time_parsing();
    check_next_schedule_time();

    return 0;
}
