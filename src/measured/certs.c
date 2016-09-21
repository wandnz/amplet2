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

#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <curl/curl.h>

#include "config.h"
#include "debug.h"
#include "ssl.h"
#include "certs.h"
#include "testlib.h" /* XXX just for check_exists(), is that the best place? */



/*
 * Generate the sha256 hash of the given string. Expects the length field to
 * initially describe the length of the string, and will be overwritten with
 * the length of the resulting hash.
 *
 * https://www.openssl.org/docs/crypto/EVP_DigestInit.html
 */
static unsigned char *hash(char *str, unsigned int *length, const EVP_MD *type){
    EVP_MD_CTX *mdctx;
    unsigned char *hashstr = calloc(1, EVP_MAX_MD_SIZE);

    assert(str);
    assert(hashstr);
    assert(length);
    assert(type);

    if ( (mdctx = EVP_MD_CTX_create()) == NULL ) {
        free(hashstr);
        *length = 0;
        return NULL;
    }

    if ( EVP_DigestInit_ex(mdctx, type, NULL) != 1 ) {
        free(hashstr);
        *length = 0;
        return NULL;
    }

    if ( EVP_DigestUpdate(mdctx, str, *length) != 1 ) {
        free(hashstr);
        *length = 0;
        return NULL;
    }

    if ( EVP_DigestFinal_ex(mdctx, hashstr, length) != 1 ) {
        free(hashstr);
        *length = 0;
        return NULL;
    }

    EVP_MD_CTX_destroy(mdctx);

    return hashstr;
}



/*
 *
 */
static void set_curl_ssl_opts(CURL *curl, char *cacert) {
    /*
     * Setting CURL_SSLVERSION_TLSv1 seems to negotiate V1.0 rather than the
     * best 1.X version, so none of our ciphers work if we use an old version
     * of libcurl. Don't bother even trying to set this for now and instead
     * rely on the cipher selection to keep things sensible.
     */
#if 0
    /* force only TLSv1.2 or better (if we can, otherwise >= TLSv1.X) */
#if LIBCURL_VERSION_NUM >= 0x072200
    curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
#else
    //curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1);
#endif
#endif

    /* limit ciphers to those we believe are secure */
    curl_easy_setopt(curl, CURLOPT_SSL_CIPHER_LIST, SECURE_CIPHER_LIST);

    /* use the cacert we've been given */
    curl_easy_setopt(curl, CURLOPT_CAINFO, cacert);

    /* Try to verify the server certificate */
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1);

    /* Try to verify the server hostname/commonname */
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2);
}



/*
 * Load an existing private RSA key from a file.
 */
static RSA *load_existing_key_file(char *filename) {
    FILE *privfile;
    RSA *key;

    Log(LOG_INFO, "Using existing private key %s", filename);

    if ( (privfile = fopen(filename, "r")) == NULL ) {
        Log(LOG_WARNING, "Failed to open key file: %s", strerror(errno));
        return NULL;
    }

    if ( (key = PEM_read_RSAPrivateKey(privfile, NULL, NULL, NULL)) == NULL ) {
        Log(LOG_WARNING, "Failed to read private key");
        fclose(privfile);
        return NULL;
    }

    fclose(privfile);
    return key;
}



/*
 * Create a new private RSA key file.
 */
static RSA *create_new_key_file(char *filename) {
    FILE *privfile;
    RSA *key;
    mode_t oldmask;

    Log(LOG_INFO, "Private key doesn't exist, creating %s", filename);

    if ( (key = RSA_generate_key(2048, RSA_F4, NULL, NULL)) == NULL ) {
        Log(LOG_WARNING, "Failed to generate RSA key");
        return NULL;
    }

    /* restrict access outside user and group (either root or rabbitmq) */
    oldmask = umask(0027);
    if ( (privfile = fopen(filename, "w")) == NULL ) {
        Log(LOG_WARNING, "Failed to open key file: %s", strerror(errno));
        RSA_free(key);
        umask(oldmask);
        return NULL;
    }
    umask(oldmask);

    if ( PEM_write_RSAPrivateKey(privfile, key, NULL, NULL, 0, NULL,
                NULL) != 1 ) {
        Log(LOG_WARNING, "Failed to write private key");
        RSA_free(key);
        fclose(privfile);
        return NULL;
    }

    fclose(privfile);
    return key;
}



/*
 * If the private key file is specified, try to load it (not existing is an
 * error). If it is not specified, try to guess the filename and load that,
 * or create it if it doesn't exist.
 */
static RSA *get_key_file(char *filename) {
    RSA *key;

    Log(LOG_DEBUG, "Get private key");

    /* check if the keyfile exists, creating it if it doesn't */
    switch ( check_exists(filename, 0) ) {
        case 0: key = load_existing_key_file(filename); break;
        case 1: key = create_new_key_file(filename); break;
        default: key = NULL; break;
    };

    return key;
}



/*
 *
 */
static X509_REQ *create_new_csr(RSA *key, char *ampname) {
    X509_REQ *request;
    X509_NAME *name;
    EVP_PKEY *pkey;

    Log(LOG_DEBUG, "Creating certificate signing request");

    if ( (request = X509_REQ_new()) == NULL ) {
        Log(LOG_WARNING, "Failed to create X509 signing request");
        return NULL;
    }

    if ( (pkey = EVP_PKEY_new()) == NULL ) {
        Log(LOG_WARNING, "Failed to create PKEY");
        X509_REQ_free(request);
        return NULL;
    }

    /*
     * Using EVP_PKEY_set1_RSA() rather than EVP_PKEY_assign_RSA() means we
     * keep control of the key structure, and can free it ourselves later.
     */
    if ( !EVP_PKEY_set1_RSA(pkey, key) ) {
        Log(LOG_WARNING, "Failed to assign private key to PKEY");
        EVP_PKEY_free(pkey);
        X509_REQ_free(request);
        return NULL;
    }

    if ( !X509_REQ_set_pubkey(request, pkey) ) {
        Log(LOG_WARNING, "Failed to set public key for CSR");
        EVP_PKEY_free(pkey);
        X509_REQ_free(request);
        return NULL;
    }

    name = X509_REQ_get_subject_name(request);

    /* add the ampname as common name to the signing request */
    if ( !X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                (unsigned char*)ampname, -1, -1, 0) ) {
        Log(LOG_WARNING, "Failed to set Common Name in CSR");
        EVP_PKEY_free(pkey);
        X509_REQ_free(request);
        return NULL;
    }

    /*
     * TODO this might need to be a different/custom label, as amplets need
     * to be both servers and clients. The signing server does its own thing
     * anyway so this might not really matter.
     */
    if ( !X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
                (unsigned char*)"client", -1, -1, 0) ) {
        Log(LOG_WARNING, "Failed to set Organisation in CSR");
        EVP_PKEY_free(pkey);
        X509_REQ_free(request);
        return NULL;
    }

    /* sign the request */
    if ( !X509_REQ_sign(request, pkey, EVP_sha256()) ) {
        Log(LOG_WARNING, "Failed to sign the CSR");
        EVP_PKEY_free(pkey);
        X509_REQ_free(request);
        return NULL;
    }

    EVP_PKEY_free(pkey);

    return request;
}



/*
 * The CSR needs to be in the same format as if it was written to disk,
 * so we need to convert it from the X509_REQ struct.
 */
static char *get_csr_string(X509_REQ *request) {
    FILE *out;
    char *csrstr;
    size_t size;

    Log(LOG_DEBUG, "Writing X509_REQ to string");

    if ( (out = open_memstream(&csrstr, &size)) == NULL ) {
        Log(LOG_WARNING, "Failed to open memory stream: %s", strerror(errno));
        return NULL;
    }

    if ( !PEM_write_X509_REQ(out, request) ) {
        Log(LOG_WARNING, "Failed to write X509_REQ");
        return NULL;
    }

    fclose(out);
    return csrstr;
}



/*
 * POST the CSR to the server over HTTPS on a custom port.
 */
static int send_csr(X509_REQ *request, char *collector, char *cacert) {
    CURL *curl;
    CURLcode res;
    FILE *csrfile;
    long code;
    char *url;
    char *csrstr;
    struct curl_slist *slist = NULL;
    unsigned char *hashstr;
    unsigned int length;
    unsigned int i;
    char fingerprint[33];

    /* try to read the CSR into a string so we have it in textual form */
    if ( (csrstr = get_csr_string(request)) == NULL ) {
        return -1;
    }

    /* we need to use an https url to get curl to use the cert/ssl options */
    if ( asprintf(&url, "https://%s:%d/sign", collector,
                AMP_PKI_SSL_PORT) < 0 ) {
        Log(LOG_WARNING, "Failed to build cert signing url");
        free(csrstr);
        return -1;
    }

    /*
     * Display the MD5 hash for the CSR that is being sent, in case someone
     * wants to double check the request. Using just the MD5 for now, because
     * the SHA256 is too long to easily look at.
     */
    length = strlen(csrstr);
    if ( (hashstr = hash(csrstr, &length, EVP_md5())) == NULL || length == 0 ) {
        free(csrstr);
        return -1;
    }

    /* turn the byte string into printable hex */
    for ( i = 0; i < length; i++ ) {
        snprintf(fingerprint + (i * 2), 3, "%02x", (uint8_t)hashstr[i]);
    }

    free(hashstr);

    Log(LOG_INFO, "Sending certificate signing request to %s", url);
    Log(LOG_INFO, "Request MD5: %s", fingerprint);

    /* open the string as a file pointer to give to curl */
    if ( (csrfile = fmemopen(csrstr, strlen(csrstr), "r")) == NULL ) {
        Log(LOG_ALERT, "Failed to open CSR as a stream");
        free(url);
        free(csrstr);
        return -1;
    }

    curl = curl_easy_init();
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, PACKAGE_STRING);
    curl_easy_setopt(curl, CURLOPT_POST, 1);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, strlen(csrstr));
    curl_easy_setopt(curl, CURLOPT_READDATA, csrfile);
    set_curl_ssl_opts(curl, cacert);

    /* make it a binary data stream so there is no encoding */
    slist = curl_slist_append(slist, "Content-Type: application/octet-stream");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist);

    res = curl_easy_perform(curl);

    curl_slist_free_all(slist);
    free(url);
    free(csrstr);
    fclose(csrfile);

    if ( res != CURLE_OK ) {
        Log(LOG_WARNING, "Failed to send CSR: %s", curl_easy_strerror(res));
        curl_easy_cleanup(curl);
        return 1;
    }

    /* check return code and that data was received */
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    curl_easy_cleanup(curl);

    /* we should get a 202, meaning the server has accepted the CSR */
    if ( code != 202 ) {
        Log(LOG_WARNING, "Error sending CSR, code:%d", code);
        return 1;
    }

    Log(LOG_DEBUG, "CSR was accepted but has yet to be signed");

    return 0;
}



/*
 * https://www.openssl.org/docs/crypto/RSA_sign.html
 */
static unsigned char *sign(char *keyname, unsigned char *hashstr,
        unsigned int *length) {
    unsigned char *signature;
    FILE *privfile;
    RSA *key;
    unsigned int siglen;

    assert(hashstr);
    assert(length);

    if ( (privfile = fopen(keyname, "r")) == NULL ) {
        *length = 0;
        return NULL;
    }

    if ( (key = PEM_read_RSAPrivateKey(privfile, NULL, NULL, NULL)) == NULL ) {
        fclose(privfile);
        *length = 0;
        return NULL;
    }

    fclose(privfile);

    if ( (signature = calloc(1, RSA_size(key))) == NULL ) {
        *length = 0;
        return NULL;
    }

    if ( RSA_sign(NID_sha256, hashstr, *length, signature, &siglen, key) != 1 ){
        *length = 0;
        return NULL;
    }

    RSA_free(key);
    *length = siglen;

    return signature;
}



/*
 * Return:  0 on success
 *          -1 on permanent error
 *          1 if query was ok, but no certificate available, try again later
 *          2 if query failed non-permanently, try again later
 */
static int fetch_certificate(amp_ssl_opt_t *sslopts, char *ampname,
        char *collector) {
    CURL *curl;
    CURLcode res;
    FILE *certfile;
    double size;
    long code;
    char *url, *urlsig;
    unsigned char *hashstr, *signature;
    unsigned int length;
    unsigned int i;
    BIO *bio;

    Log(LOG_DEBUG, "Fetch signed certificate");

    /* hash the data that we are about to sign */
    length = strlen(ampname);
    if ( (hashstr = hash(ampname, &length, EVP_sha256())) == NULL ||
            length == 0 ) {
        return -1;
    }

    /*
     * sign the ampname, so the server can confirm we sent the CSR and should
     * have access to the signed certificate
     */
    if ( (signature = sign(sslopts->key, hashstr, &length)) == NULL ||
            length == 0 ) {
        free(hashstr);
        return -1;
    }

    free(hashstr);

    /*
     * base64 encode the signature so we can transmit it as printable chars
     * https://gist.github.com/barrysteyn/7308212
     */
    bio = BIO_push(BIO_new(BIO_f_base64()), BIO_new(BIO_s_mem()));
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, signature, length);
    if ( BIO_flush(bio) != 1 ) {
        free(signature);
        BIO_free_all(bio);
        return -1;
    }
    length = BIO_get_mem_data(bio, &urlsig);

    /*
     * Modify the encoding slightly, as we can't use these chars in a url.
     * This will be decoded fine by python base64.urlsafe_b64decode().
     */
    for ( i = 0; i < length; i++ ) {
        switch ( urlsig[i] ) {
            case '+': urlsig[i] = '-'; break;
            case '/': urlsig[i] = '_'; break;
            default: /* do nothing */ break;
        };
    }

    free(signature);

    /* we need to use an https url to get curl to use the cert/ssl options */
    if ( asprintf(&url, "https://%s:%d/cert/%s/%.*s", collector,
                AMP_PKI_SSL_PORT, ampname, length, urlsig) < 0 ) {
        Log(LOG_ALERT, "Failed to build cert fetching url");
        BIO_free_all(bio);
        return -1;
    }

    /* generally we don't want to expose the signature, don't log by default */
    Log(LOG_INFO, "Checking for signed certificate at https://%s:%d/cert/%s/",
            collector, AMP_PKI_SSL_PORT, ampname);
    Log(LOG_DEBUG, "Signature: %s", urlsig);

    /* open the file that the certificate will be written to */
    if ( (certfile = fopen(sslopts->cert, "w")) == NULL ) {
        Log(LOG_WARNING, "Failed to open certfile '%s' for writing",
                sslopts->cert);
        BIO_free_all(bio);
        return -1;
    }

    curl = curl_easy_init();
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, PACKAGE_STRING);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, certfile);
    set_curl_ssl_opts(curl, sslopts->cacert);

    res = curl_easy_perform(curl);

    fclose(certfile);
    free(url);
    BIO_free_all(bio);

    if ( res != CURLE_OK ) {
        Log(LOG_WARNING, "Failed to fetch signed certificate: %s",
                curl_easy_strerror(res));
        curl_easy_cleanup(curl);

        if ( unlink(sslopts->cert) < 0 ) {
            Log(LOG_WARNING, "Failed to remove cert '%s': %s",
                    sslopts->cert, strerror(errno));
        }

        return 2;
    }

    /* check return code and that data was received */
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    curl_easy_getinfo(curl, CURLINFO_SIZE_DOWNLOAD, &size);
    curl_easy_cleanup(curl);

    /* if no cert, return failure and we might try again later */
    if ( code != 200 || size <= 0 ) {
        if ( unlink(sslopts->cert) < 0 ) {
            Log(LOG_WARNING, "Failed to remove cert '%s': %s",
                    sslopts->cert, strerror(errno));
        }

        /* certificate has not yet been signed, wait and try again */
        if ( code == 403 ) {
            Log(LOG_INFO, "Certificate has not yet been signed");
            return 1;
        }

        Log(LOG_WARNING, "Error fetching signed cert, code:%d, size:%fB",
                code, size);
        return 2;
    }

    Log(LOG_INFO, "Signed certificate stored in %s", sslopts->cert);

    return 0;
}



/*
 * Check that the key directories exist, creating them if they don't.
 */
static int check_key_directories(char *keydir) {
    struct stat statbuf;
    int stat_result;

    /* make sure top level keys directory exists */
    stat_result = stat(AMP_KEYS_DIR, &statbuf);
    if ( stat_result < 0 && errno == ENOENT) {
        Log(LOG_DEBUG, "Top level key directory doesn't exist, creating %s",
                AMP_KEYS_DIR);
        /* doesn't exist, try to create it */
        if ( mkdir(AMP_KEYS_DIR, 0750) < 0 ) {
            Log(LOG_WARNING, "Failed to create key directory %s: %s",
                    AMP_KEYS_DIR, strerror(errno));
            return -1;
        }
    } else if ( stat_result < 0 ) {
        /* error calling stat, report it and return */
        Log(LOG_WARNING, "Failed to stat key directory %s: %s",
                AMP_KEYS_DIR, strerror(errno));
        return -1;
    }

    /* make sure ampname specific keys directory exists inside that */
    stat_result = stat(keydir, &statbuf);
    if ( stat_result < 0 && errno == ENOENT) {
        Log(LOG_DEBUG, "Key directory doesn't exist, creating %s", keydir);
        /* doesn't exist, try to create it */
        if ( mkdir(keydir, 0750) < 0 ) {
            Log(LOG_WARNING, "Failed to create key directory %s: %s", keydir,
                    strerror(errno));
            return -1;
        }
    } else if ( stat_result < 0 ) {
        /* error calling stat, report it and return */
        Log(LOG_WARNING, "Failed to stat key directory %s: %s", keydir,
                strerror(errno));
        return -1;
    }

    return 0;
}



/*
 * Exponentially backoff the timeout values so we can initially query often
 * to see if the certificate has been signed, but without hammering the server
 * in the long term.
 */
static int get_next_timeout(int timeout) {
    if ( timeout < AMP_MIN_PKI_QUERY_INTERVAL ) {
        timeout = AMP_MIN_PKI_QUERY_INTERVAL;
    } else if ( timeout >= AMP_MAX_PKI_QUERY_INTERVAL ) {
        timeout = AMP_MAX_PKI_QUERY_INTERVAL;
    } else {
        timeout = timeout << 1;
    }

    return timeout;
}



/*
 * Make sure that all the SSL variables are pointing to certificates, keys,
 * etc that exist. If they don't exist then we try to create them as best
 * as we can.
 */
int get_certificate(amp_ssl_opt_t *sslopts, char *ampname, char *collector,
        int waitforcert) {
    X509_REQ *request = NULL;
    RSA *key;
    int res;
    int timeout;

    /* if the private key and certificate exist then thats all we need */
    if ( check_exists(sslopts->key, 0) == 0 &&
            check_exists(sslopts->cert, 0) == 0 ) {
        Log(LOG_DEBUG, "Private key and certificate both exist");
        return 0;
    }

    /* make sure the proper directories exist, so we can put files in them */
    if ( check_key_directories(sslopts->keys_dir) < 0 ) {
        return -1;
    }

    /*
     * Make sure that the key file exists, generating it if needed.
     * TODO maybe pass key into fetch certificate function for signing, at
     * the moment the pointer we get back is only used if we need to create
     * a new CSR.
     */
    if ( (key = get_key_file(sslopts->key)) == NULL ) {
        return -1;
    }

    /* query for the certificate, a previous CSR might have been signed */
    if ( fetch_certificate(sslopts, ampname, collector) == 0 ) {
        RSA_free(key);
        return 0;
    }

    /* build certificate signing request */
    request = create_new_csr(key, ampname);
    RSA_free(key);

    if ( request == NULL ) {
        return -1;
    }

    /*
     * If we didn't get a certificate then try to send a certificate signing
     * request until the server accepts it.
     * TODO if we fail to connect to the server above, maybe we should sleep
     * instead of immediately sending the CSR to a server we know is down?
     */
    timeout = AMP_MIN_PKI_QUERY_INTERVAL;
    while ( (res = send_csr(request, collector, sslopts->cacert)) > 0 &&
            waitforcert ) {
        Log(LOG_INFO, "Sleeping for %d seconds before trying again", timeout);
        sleep(timeout);
        timeout = get_next_timeout(timeout);
    }

    X509_REQ_free(request);

    /*
     * We got an error that we can't easily recover from, or we only wanted
     * to try once and that failed, abort.
     */
    if ( res != 0 ) {
        return -1;
    }

    /*
     * Now query for the signed certificate in response to our CSR until we
     * get one or we run out of time
     */
    timeout = AMP_MIN_PKI_QUERY_INTERVAL;
    while ( (res = fetch_certificate(sslopts, ampname, collector)) > 0 &&
            waitforcert ) {
        Log(LOG_INFO, "Sleeping for %d seconds before trying again", timeout);
        sleep(timeout);
        timeout = get_next_timeout(timeout);
    }

    return res;
}
