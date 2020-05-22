#ifndef _TESTS_SIP_H
#define _TESTS_SIP_H

#include <netdb.h>
#include <stdint.h>
#include <pjsua-lib/pjsua.h>

#include "config.h"
#include "tests.h"

/* server should wait up to 10 seconds for a client to connect */
#define SIP_SERVER_WAIT_TIMEOUT 10
/* server should terminate any call that lasts this long */
#define SIP_SERVER_MAX_CALL_DURATION 300
/* server should listen on this port for a client to connect */
#define SIP_SERVER_LISTEN_PORT 5060
/* WAV file to play once connected */
#define SIP_WAV_FILE AMP_EXTRA_DIRECTORY "/sip-test-8000.wav"

/* server/client flags used for determining which protocols to register */
#define AMP_SIP_CLIENT 0
#define AMP_SIP_SERVER 1


struct sip_stats_t {
    pjsua_stream_stat *stream_stats;
    uint64_t response_time;
    uint64_t connect_time;
    uint64_t duration;
};

struct opt_t {
    struct sip_stats_t *stats;
    char *sourcev4;
    char *sourcev6;
    char *device;
    char *hostname;
    pj_sockaddr_t *address;
    pj_str_t registrar;
    pj_str_t username;
    pj_str_t password;
    pj_str_t id;
    pj_str_t uri;
    pj_str_t filename;
    pj_str_t user_agent;
    pj_str_t outbound_proxy[4];
    unsigned outbound_proxy_cnt;
    int perturbate;
    uint16_t control_port;
    uint16_t sip_port;
    uint8_t max_duration;
    uint8_t forcev4;
    uint8_t forcev6;
    uint8_t dscp;
    uint8_t repeat;
    uint8_t family;
};

amp_test_result_t* run_sip(int argc, char *argv[], int count,
        struct addrinfo **dests);
void run_sip_server(int argc, char *argv[], BIO *ctrl);
amp_test_result_t* run_sip_client(int argc, char *argv[], int count,
        struct addrinfo **dests);
void print_sip(amp_test_result_t *result);
void usage(void);
char* copy_and_null_terminate(pj_str_t *src);
void start_duration_timer(int duration);
void set_use_minimal_messages(void);
void on_call_media_state(pjsua_call_id call_id);
char* get_host_from_uri(pj_pool_t *pool, pj_str_t uri_str);
test_t *register_test(void);

struct opt_t* parse_options(int argc, char *argv[]);
pj_status_t register_transports(struct opt_t *options, int is_server);
pj_status_t register_account(struct opt_t *options);
pj_status_t register_codecs(void);

#endif
