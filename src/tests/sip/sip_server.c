/*
 * This file is part of amplet2.
 *
 * Copyright (c) 2019-2020 The University of Waikato, Hamilton, New Zealand.
 *
 * Author: Brendon Jones
 *
 * All rights reserved.
 *
 * This code has been developed by the University of Waikato WAND
 * research group. For further information please see http://www.wand.net.nz/
 *
 * amplet2 is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations including
 * the two.
 *
 * You must obey the GNU General Public License in all respects for all
 * of the code used other than OpenSSL. If you modify file(s) with this
 * exception, you may extend this exception to your version of the
 * file(s), but you are not obligated to do so. If you do not wish to do
 * so, delete this exception statement from your version. If you delete
 * this exception statement from all source files in the program, then
 * also delete it here.
 *
 * amplet2 is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with amplet2. If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <time.h>
#include <unistd.h>

#include <pjsua-lib/pjsua.h>

#include "config.h"
#include "tests.h"
#include "sip.h"
#include "debug.h"



/*
 * Automatically answer any incoming calls.
 */
static void on_incoming_call(pjsua_acc_id acc_id, pjsua_call_id call_id,
        pjsip_rx_data *rdata) {
    pjsua_call_setting call_settings;

    PJ_UNUSED_ARG(acc_id);
    PJ_UNUSED_ARG(rdata);

    /* disable video on this call */
    pjsua_call_setting_default(&call_settings);
    call_settings.vid_cnt = 0;

    pjsua_call_answer2(call_id, &call_settings, 200, NULL, NULL);
}



/*
 * Once connected, the server should set a callback to drop clients that run
 * too long.
 */
static void on_call_state(pjsua_call_id call_id, pjsip_event *e) {
    pjsua_call_info call_info;
    pjsua_call_get_info(call_id, &call_info);

    PJ_UNUSED_ARG(e);

    Log(LOG_DEBUG, "Call %d state changed: %d (%.*s)\n",
            call_id, call_info.state,
            (int)call_info.state_text.slen, call_info.state_text.ptr);

    if ( call_info.state == PJSIP_INV_STATE_CONFIRMED ) {
        start_duration_timer(SIP_SERVER_MAX_CALL_DURATION);
    }
}



/*
 * Wait a short while for a call to be established, and if a call is
 * established then wait a longer time for the call to be disconnected.
 */
static void run_sip_server_loop(void) {
    pjsua_call_id call_id;
    time_t timeout;

    Log(LOG_DEBUG, "Waiting for call");

    /* assuming this is always allocated from zero */
    call_id = 0;

    /* wait for up to SIP_SERVER_WAIT_TIMEOUT for a client to connect */
    timeout = time(NULL) + SIP_SERVER_WAIT_TIMEOUT;

    do {
        usleep(100000);
    } while ( time(NULL) < timeout && !pjsua_call_is_active(call_id) );

    /* if connected, wait for it to disconnect or max duration to be reached */
    while ( pjsua_call_is_active(call_id) == PJ_TRUE ) {
        sleep(1);
    }
}



/*
 * Run the server side of the test that will wait for a call.
 */
void run_sip_server(int argc, char *argv[], __attribute__((unused))BIO *ctrl) {
    pj_status_t status;
    char errmsg[PJ_ERR_MSG_SIZE];
    pjsua_config cfg;
    pjsua_logging_config log_cfg;
    struct opt_t *options;

    Log(LOG_DEBUG, "Running sip test as server");

    /* set default values that can be overridden by the command line */
    pjsua_config_default(&cfg);
    cfg.cb.on_call_media_state = &on_call_media_state;
    cfg.cb.on_incoming_call = &on_incoming_call;
    cfg.cb.on_call_state = &on_call_state;
    cfg.max_calls = 1;

    /* minimise the data we send so it doesn't blow out the packet size */
    set_use_minimal_messages();

    /* silence very noisy logging output during pjsua_create() */
    pj_log_set_level(0);

    if ( (status = pjsua_create()) != PJ_SUCCESS ) {
        pj_strerror(status, errmsg, sizeof(errmsg));
        Log(LOG_WARNING, "%s", errmsg);
        exit(EXIT_FAILURE);
    }

    options = parse_options(argc, argv);
    cfg.user_agent = options->user_agent;

    pjsua_logging_config_default(&log_cfg);
    log_cfg.console_level = 0;

    if ( (status = pjsua_init(&cfg, &log_cfg, NULL)) != PJ_SUCCESS ) {
        pj_strerror(status, errmsg, sizeof(errmsg));
        Log(LOG_WARNING, "%s", errmsg);
        exit(EXIT_FAILURE);
    }

    status = register_transports(options, AMP_SIP_SERVER);
    if ( status != PJ_SUCCESS ) {
        pj_strerror(status, errmsg, sizeof(errmsg));
        Log(LOG_WARNING, "%s", errmsg);
        pjsua_destroy();
        exit(EXIT_FAILURE);
    }

    status = register_account(options);
    if ( status != PJ_SUCCESS ) {
        pj_strerror(status, errmsg, sizeof(errmsg));
        Log(LOG_WARNING, "%s\n", errmsg);
        goto end;
    }

    /* use the null sound device, we don't want to actually play sound */
    Log(LOG_DEBUG, "Setting null sound device");
    pjsua_set_null_snd_dev();

    Log(LOG_DEBUG, "Starting pjsua");
    if ( (status = pjsua_start()) != PJ_SUCCESS ) {
        pj_strerror(status, errmsg, sizeof(errmsg));
        Log(LOG_WARNING, "%s", errmsg);
        pjsua_destroy();
        exit(EXIT_FAILURE);
    }

    /* set options as account user data so it's available in callbacks */
    pjsua_acc_set_user_data(pjsua_acc_get_default(), options);

    /* loop till test completes */
    run_sip_server_loop();

end:
    free(options);
    pjsua_destroy();
}
