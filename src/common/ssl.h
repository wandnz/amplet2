#ifndef _MEASURED_SSL_H
#define _MEASURED_SSL_H

#include <openssl/ssl.h>

/* man ERR_error_string says "buf must be at least 120 bytes long" */
#define SSL_ERROR_BUFFER_LENGTH 120

/* See: https://github.com/iSECPartners/ssl-conservatory/ */
#define SECURE_CIPHER_LIST "RC4-SHA:HIGH:!ADH:!AECDH:!CAMELLIA"

SSL_CTX *ssl_ctx;

int initialise_ssl(void);
SSL_CTX *initialise_ssl_context(void);
SSL* ssl_accept(SSL_CTX *ssl_ctx, int fd);
SSL* ssl_connect(SSL_CTX *ssl_ctx, int fd);
void ssl_shutdown(SSL *ssl);
void ssl_cleanup(void);
int matches_common_name(const char *hostname, const X509 *cert);

#endif
