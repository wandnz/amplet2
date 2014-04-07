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
    assert(amp_test_get_period_max_value('H') == 60 * 60);
    assert(amp_test_get_period_max_value('D') == 60 * 60 * 24);
    assert(amp_test_get_period_max_value('W') == 60 * 60 * 24 * 7);

    /* check that the period start values are the start of the period */
    assert(amp_test_get_period_start('H') % 60 == 0);
    assert(amp_test_get_period_start('D') % 86400 == 0);
    /* weekly period is awkward cause 01-01-1970 is Thursday and Sunday is 0 */
    assert((amp_test_get_period_start('W') + 60*60*24*4) % 604800 == 0);
}



/*
 * Check that the time values are correctly parsed and fit within the period.
 */
static void check_time_parsing(void) {
    /* check that hourly repeated times are correctly validated */
    assert(amp_test_get_time_value("0", 'H') == 0);
    assert(amp_test_get_time_value("1000", 'H') == 1000);
    assert(amp_test_get_time_value("60000", 'H') == 60000);
    assert(amp_test_get_time_value("3600000", 'H') == 3600000);
    assert(amp_test_get_time_value("-1", 'H') == -1);
    assert(amp_test_get_time_value("-12345", 'H') == -1);
    assert(amp_test_get_time_value("3600001", 'H') == -1);
    assert(amp_test_get_time_value("86400000", 'H') == -1);
    assert(amp_test_get_time_value("86400001", 'H') == -1);
    assert(amp_test_get_time_value("604800000", 'H') == -1);
    assert(amp_test_get_time_value("604800001", 'H') == -1);

    /* check that daily repeated times are correctly validated */
    assert(amp_test_get_time_value("0", 'D') == 0);
    assert(amp_test_get_time_value("1000", 'D') == 1000);
    assert(amp_test_get_time_value("60000", 'D') == 60000);
    assert(amp_test_get_time_value("3600000", 'D') == 3600000);
    assert(amp_test_get_time_value("3600001", 'D') == 3600001);
    assert(amp_test_get_time_value("86400000", 'D') == 86400000);
    assert(amp_test_get_time_value("-1", 'D') == -1);
    assert(amp_test_get_time_value("-12345", 'D') == -1);
    assert(amp_test_get_time_value("86400001", 'D') == -1);
    assert(amp_test_get_time_value("604800000", 'D') == -1);
    assert(amp_test_get_time_value("604800001", 'D') == -1);

    /* check that weekly repeated times are correctly validated */
    assert(amp_test_get_time_value("0", 'W') == 0);
    assert(amp_test_get_time_value("1000", 'W') == 1000);
    assert(amp_test_get_time_value("60000", 'W') == 60000);
    assert(amp_test_get_time_value("3600000", 'W') == 3600000);
    assert(amp_test_get_time_value("3600001", 'W') == 3600001);
    assert(amp_test_get_time_value("86400000", 'W') == 86400000);
    assert(amp_test_get_time_value("86400001", 'W') == 86400001);
    assert(amp_test_get_time_value("604800000", 'W') == 604800000);
    assert(amp_test_get_time_value("-1", 'W') == -1);
    assert(amp_test_get_time_value("-12345", 'W') == -1);
    assert(amp_test_get_time_value("604800001", 'W') == -1);

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
        {'D', {0, 0}, 0, 86400000, 30000},          /* period start */
        {'D', {30, 0}, 0, 86400000, 30000},         /* period end */
        {'D', {1, 0}, 0, 86400000, 60000},          /* 1s into period */
        {'D', {89, 0}, 0, 86400000, 90000},         /* 1s before period end */
        {'D', {0, 500000}, 0, 86400000, 30000},     /* 0.5s into period */
        {'D', {10, 900000}, 0, 86400000, 60000},    /* 10.9s into period */
        {'D', {9, 900000}, 0, 10000, 10000},        /* very early end time */
        {'D', {10, 900000}, 0, 10000, 10000},       /* very early end time */
        {'D', {86398, 123000}, 0, 80000000, 10000}, /* early end time, cycle */
        {'D', {86398, 123000}, 0, 86400000, 10000}, /* cycle to next period */
        {'D', {123, 123000}, 0, 0, 0},              /* frequency 0 */
        {'D', {35, 987000}, 60000, 0, 0},           /* freq 0, late start */
        {'D', {61, 0}, 360000, 86400000, 60000},    /* late start before time */
        {'D', {361, 0}, 360000, 86400000, 60000},   /* late start after time */
        /* weekly */
        {'W', {0, 0}, 0, 604800000, 30000},         /* period start */
        {'W', {30, 0}, 0, 604800000, 30000},        /* period end */
        {'W', {1, 0}, 0, 604800000, 60000},         /* 1s into period */
        {'W', {604799, 0}, 0, 604800000, 90000},    /* 1s before period end */
        {'W', {0, 567000}, 0, 604800000, 30000},    /* 0.567890 into period */
        {'W', {10, 900000}, 0, 604800000, 60000},   /* 10.9s into period */
        {'W', {68, 500000}, 0, 604800000, 86400000},/* 1 day frequency */
        {'W', {10000, 0}, 0, 10000000, 10000},      /* last cycle in period */
        {'W', {123, 123000}, 0, 0, 0},              /* frequency 0 */
        {'W', {86000, 987000}, 86400000, 0, 0},     /* freq 0, late start */
        {'W', {61, 0}, 360000, 604800000, 60000},   /* late start before time */
        {'W', {361, 0}, 360000, 86400000, 60000},   /* late start after time*/
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

        /* get when the algorithm thinks the next scheduled test should be */
        offset = get_next_schedule_time(&ev_hdl, schedule[i].repeat,
                schedule[i].start, schedule[i].end, schedule[i].freq);

        /*
        printf("%d.%d vs %d.%d\n", offset.tv_sec, offset.tv_usec,
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
