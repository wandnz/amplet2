/*
 * This file is part of amplet2.
 *
 * Copyright (c) 2013-2016 The University of Waikato, Hamilton, New Zealand.
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

#ifndef _COMMON_SSL_H
#define _COMMON_SSL_H

#include <openssl/ssl.h>

/* man ERR_error_string says "buf must be at least 120 bytes long" */
#define SSL_ERROR_BUFFER_LENGTH 120

/*
 * This list is the TLSv1.2 ciphers from the current "modern" configuration
 * recommended by mozilla. This list was last updated 20160601.
 *
 * https://wiki.mozilla.org/Security/Server_Side_TLS
 * http://wiki.openssl.org/index.php/FIPS_mode_and_TLS
 */
#define SECURE_CIPHER_LIST "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK"

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
BIO* establish_control_socket(SSL_CTX *ssl_ctx, int fd, int client);
void ssl_cleanup(void);
char* get_common_name(const X509 *cert);
int matches_common_name(const char *hostname, const X509 *cert);

#endif
