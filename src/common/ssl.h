#ifndef _MEASURED_SSL_H
#define _MEASURED_SSL_H

#include <openssl/ssl.h>

/* man ERR_error_string says "buf must be at least 120 bytes long" */
#define SSL_ERROR_BUFFER_LENGTH 120

/*
 * This list is the TLSv1.2 ciphers from the current "modern" configuration
 * recommended by mozilla.
 *
 * https://wiki.mozilla.org/Security/Server_Side_TLS
 * http://wiki.openssl.org/index.php/FIPS_mode_and_TLS
 */
#define SECURE_CIPHER_LIST "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:DHE-RSA-AES128-SHA256:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK"

/* disable everything below TLSv1.2 */
#define SSL_OP_MIN_TLSv1_2 (SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | \
                            SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1)

/* default location where all keys are stored */
#define AMP_KEYS_DIR AMP_CONFIG_DIR "/keys"

typedef struct amp_ssl_opt {
    char *cacert;
    char *key;
    char *cert;
    char *keys_dir;
} amp_ssl_opt_t;


SSL_CTX *ssl_ctx;

void reseed_openssl_rng(void);
int initialise_ssl(amp_ssl_opt_t *sslopts, char *collector);
SSL_CTX *initialise_ssl_context(amp_ssl_opt_t *sslopts);
SSL* ssl_accept(SSL_CTX *ssl_ctx, int fd);
SSL* ssl_connect(SSL_CTX *ssl_ctx, int fd);
void ssl_shutdown(SSL *ssl);
void ssl_cleanup(void);
int matches_common_name(const char *hostname, const X509 *cert);

#endif
