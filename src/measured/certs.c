#include <config.h>

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <errno.h>
#include <curl/curl.h>

#include "debug.h"
#include "messaging.h"
#include "global.h"
#include "ssl.h"
#include "certs.h"


/* XXX cert/csr files are currently named after the server they are for */

/*
 * how much can we do in this file, compared to things that need to be common?
 * - init ssl
 * - generate any keys
 * - send csr, get cert
 * - load certs and keys into ctx
 */


/*
 * Check if a given directory exists, failure to exist is only an error if
 * the strict flag is set.
 */
static int check_exists(char *path, int strict) {
    struct stat statbuf;
    int stat_result;

    stat_result = stat(path, &statbuf);

    /* error calling stat, report it and return and error */
    if ( stat_result < 0 && errno != ENOENT ) {
        Log(LOG_WARNING, "Failed to stat file %s: %s", path, strerror(errno));
        return -1;
    }

    /* file exists */
    if ( stat_result == 0 ) {
        /* check it's a normal file or a symbolic link */
        if ( S_ISREG(statbuf.st_mode) || S_ISLNK(statbuf.st_mode) ) {
            return 0;
        }

        Log(LOG_WARNING, "File %s exists, but is not a regular file", path);
        return -1;
    }

    /* file was manually specified, but doesn't exist, that's an error */
    if ( strict ) {
        Log(LOG_WARNING, "Manually specified file %s not found", path);
        return -1;
    }

    /* file doesn't exist, but that's ok as strict isn't set */
    return 1;
}



/*
 *
 */
static void set_curl_ssl_opts(CURL *curl) {
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
    curl_easy_setopt(curl, CURLOPT_CAINFO, vars.amqp_ssl.cacert);

    /* Try to verify the server certificate */
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1);

    /* Try to verify the server hostname/commonname */
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2);
}



/*
 * Load an existing private RSA key from a file.
 */
static RSA *load_existing_key_file(void) {
    FILE *privfile;
    RSA *key;

    Log(LOG_INFO, "Using existing private key %s", vars.amqp_ssl.key);

    if ( (privfile = fopen(vars.amqp_ssl.key, "r")) == NULL ) {
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
static RSA *create_new_key_file(void) {
    FILE *privfile;
    RSA *key;
    mode_t oldmask;

    Log(LOG_INFO, "Private key doesn't exist, creating %s", vars.amqp_ssl.key);

    if ( (key = RSA_generate_key(2048, RSA_F4, NULL, NULL)) == NULL ) {
        Log(LOG_WARNING, "Failed to generate RSA key");
        return NULL;
    }

    oldmask = umask(0077);
    if ( (privfile = fopen(vars.amqp_ssl.key, "w")) == NULL ) {
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
 * XXX can we pass in all the things that are referenced globally? not heaps?
 */
/*
 * If the private key file is specified, try to load it (not existing is an
 * error). If it is not specified, try to guess the filename and load that,
 * or create it if it doesn't exist.
 */
static RSA *get_key_file(void) {
    RSA *key;

    Log(LOG_DEBUG, "Get private key");

    /* check if the keyfile exists, creating it if it doesn't */
    switch ( check_exists(vars.amqp_ssl.key, 0) ) {
        case 0: key = load_existing_key_file(); break;
        case 1: key = create_new_key_file(); break;
        default: key = NULL; break;
    };

    return key;
}



/*
 *
 */
static X509_REQ *create_new_csr(RSA *key) {
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

    /*XXX any other options we want to set? server will just add whatever? */
    if ( !X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, vars.ampname,
                -1, -1, 0) ) {
        Log(LOG_WARNING, "Failed to set Common Name in CSR");
        EVP_PKEY_free(pkey);
        X509_REQ_free(request);
        return NULL;
    }

    if ( !X509_NAME_add_entry_by_txt(name,"O", MBSTRING_ASC, "client",
                -1, -1, 0) ) {
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



static int send_csr(X509_REQ *request) {
    CURL *curl;
    CURLcode res;
    FILE *csrfile;
    long code;
    char *url;
    char *csrstr;
    struct curl_slist *slist = NULL;

    /* try to read the CSR into a string so we have it in textual form */
    if ( (csrstr = get_csr_string(request)) == NULL ) {
        return -1;
    }

    /* we need to use an https url to get curl to use the cert/ssl options */
    if ( asprintf(&url, "https://%s:%d/sign", vars.collector,
                AMP_PKI_SSL_PORT) < 0 ) {
        Log(LOG_WARNING, "Failed to build cert signing url");
        free(csrstr);
        return -1;
    }

    Log(LOG_INFO, "Sending certificate signing request to %s", url);

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
    set_curl_ssl_opts(curl);

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
        return -1;
    }

    /* check return code and that data was received */
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    curl_easy_cleanup(curl);

    /* we should get a 202, meaning the server has accepted the CSR */
    if ( code != 202 ) {
        Log(LOG_WARNING, "Error sending CSR, code:%d", code);
        return -1;
    }

    Log(LOG_DEBUG, "CSR was accepted but has yet to be signed");

    return 0;
}



/*
 * Generate the sha256 hash of the given string. Expects the length field to
 * initially describe the length of the string, and will be overwritten with
 * the length of the resulting hash.
 *
 * https://www.openssl.org/docs/crypto/EVP_DigestInit.html
 */
static char *hash(char *str, int *length) {
    EVP_MD_CTX *mdctx;
    char *hashstr = calloc(1, EVP_MAX_MD_SIZE);

    assert(str);
    assert(hashstr);
    assert(length);

    if ( (mdctx = EVP_MD_CTX_create()) == NULL ) {
        free(hashstr);
        *length = 0;
        return NULL;
    }

    if ( EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1 ) {
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
 * https://www.openssl.org/docs/crypto/RSA_sign.html
 */
static char *sign(char *hashstr, int *length) {
    char *signature;
    FILE *privfile;
    RSA *key;
    int siglen;

    assert(hashstr);
    assert(length);

    if ( (privfile = fopen(vars.amqp_ssl.key, "r")) == NULL ) {
        *length = 0;
        return NULL;
    }

    //if ( PEM_read_RSAPrivateKey(privfile, &key, NULL, NULL) == NULL ) {
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
 *
 */
static int fetch_certificate(void) {
    CURL *curl;
    CURLcode res;
    FILE *certfile;
    double size;
    long code;
    char *url, *hashstr, *signature, *urlsig;
    int length;
    int i;
    BIO *bio;

    Log(LOG_DEBUG, "Fetch signed certificate");

    /* hash the data that we are about to sign */
    length = strlen(vars.ampname);
    if ( (hashstr = hash(vars.ampname, &length)) == NULL || length <= 0 ) {
        return -1;
    }

    /*
     * sign the ampname, so the server can confirm we sent the CSR and should
     * have access to the signed certificate
     */
    if ( (signature = sign(hashstr, &length)) == NULL || length <= 0 ) {
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
    BIO_flush(bio);
    length = BIO_get_mem_data(bio, &urlsig);

    /* modify the encoding slightly, as we can't use these chars in a url */
    for ( i = 0; i < length; i++ ) {
        switch ( urlsig[i] ) {
            case '+': urlsig[i] = '-'; break;
            case '/': urlsig[i] = '_'; break;
            default: /* do nothing */ break;
        };
    }

    free(signature);

    if ( (certfile = fopen(vars.amqp_ssl.cert, "w")) == NULL ) {
        BIO_free_all(bio);
        return -1;
    }

    /* we need to use an https url to get curl to use the cert/ssl options */
    if ( asprintf(&url, "https://%s:%d/cert/%s/%.*s", vars.collector,
                AMP_PKI_SSL_PORT, vars.ampname, length, urlsig) < 0 ) {
        Log(LOG_ALERT, "Failed to build cert fetching url");
        fclose(certfile);
        BIO_free_all(bio);
        return -1;
    }

    Log(LOG_INFO, "Checking for signed certificate at %s", url);

    curl = curl_easy_init();
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, PACKAGE_STRING);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, certfile);
    set_curl_ssl_opts(curl);

    res = curl_easy_perform(curl);

    fclose(certfile);
    free(url);
    BIO_free_all(bio);

    if ( res != CURLE_OK ) {
        Log(LOG_WARNING, "Failed to fetch signed certificate: %s",
                curl_easy_strerror(res));
        curl_easy_cleanup(curl);
        return -1;
    }

    /* check return code and that data was received */
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    curl_easy_getinfo(curl, CURLINFO_SIZE_DOWNLOAD, &size);
    curl_easy_cleanup(curl);

    /* if no cert, return failure and we might try again later */
    if ( code != 200 || size <= 0 ) {
        if ( unlink(vars.amqp_ssl.cert) < 0 ) {
            Log(LOG_WARNING, "Failed to remove cert '%s': %s",
                    vars.amqp_ssl.cert, strerror(errno));
        }

        /* certificate has not yet been signed, wait and try again */
        if ( code == 403 ) {
            Log(LOG_DEBUG, "Certificate has not yet been signed");
            return 1;
        }

        Log(LOG_WARNING, "Error fetching signed cert, code:%d, size:%fB",
                code, size);
        return -1;
    }

    Log(LOG_INFO, "Signed certificate stored in %s", vars.amqp_ssl.cert);

    return 0;
}



/*
 * Make sure that the locations of all keys have been set. If they were
 * manually specified then the files need to exist, otherwise we don't
 * care either way, they will get created if they need to be.
 */
static int check_key_locations(void) {

    if ( vars.amqp_ssl.cert == NULL ) {
        if ( asprintf(&vars.amqp_ssl.cert, "%s/%s.cert",
                    vars.keys_dir, vars.collector) < 0 ) {
            Log(LOG_ALERT, "Failed to build custom certfile path");
            return -1;
        }
    } else if ( check_exists(vars.amqp_ssl.cert, 1) < 0 ) {
        return -1;
    }

    if ( vars.amqp_ssl.key == NULL ) {
        if ( asprintf(&vars.amqp_ssl.key, "%s/key.pem", vars.keys_dir) < 0 ) {
            Log(LOG_ALERT, "Failed to build custom keyfile path");
            return -1;
        }
    } else if ( check_exists(vars.amqp_ssl.key, 1) < 0 ) {
        return -1;
    }

    if ( vars.amqp_ssl.cacert == NULL ) {
        if ( asprintf(&vars.amqp_ssl.cacert, "%s/%s.pem", AMP_KEYS_DIR,
                    vars.collector) < 0 ) {
            Log(LOG_ALERT, "Failed to build custom cacert file path");
            return -1;
        }
    }

    /*
     * The cacert should be distributed through some trusted means, it must
     * exist here for us to continue.
     */
    if ( check_exists(vars.amqp_ssl.cacert, 1) < 0 ) {
        Log(LOG_WARNING, "Server certificate %s doesn't exist!",
                vars.amqp_ssl.cacert);
        return -1;
    }

    return 0;
}



/*
 * Make sure that all the SSL variables are pointing to certificates, keys,
 * etc that exist. If they don't exist then we try to create them as best
 * as we can.
 * TODO function needs a better name
 */
int get_certificate(int timeout) {
    X509_REQ *request;
    RSA *key;
    int res;

    /*
     * If anything is unspecified, we're probably going to create files,
     * so make sure that the keys directory exists for this ampname
     */
    /* XXX this comment isn't entirely true, can we move this code?
     * we don't always need to create these directories if they are missing,
     * because the user might have specified all the files we need.
     */
    if ( vars.amqp_ssl.cert == NULL || vars.amqp_ssl.key == NULL ||
            vars.amqp_ssl.cacert == NULL ) {

        struct stat statbuf;
        int stat_result;

        /* make sure top level keys directory exists */
        stat_result = stat(AMP_KEYS_DIR, &statbuf);
        if ( stat_result < 0 && errno == ENOENT) {
            Log(LOG_DEBUG, "Top level key directory doesn't exist, creating %s",
                    AMP_KEYS_DIR);
            /* doesn't exist, try to create it */
            if ( mkdir(AMP_KEYS_DIR, 0700) < 0 ) {
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
        stat_result = stat(vars.keys_dir, &statbuf);
        if ( stat_result < 0 && errno == ENOENT) {
            Log(LOG_DEBUG, "Key directory doesn't exist, creating %s",
                    vars.keys_dir);
            /* doesn't exist, try to create it */
            if ( mkdir(vars.keys_dir, 0700) < 0 ) {
                Log(LOG_WARNING, "Failed to create key directory %s: %s",
                        vars.keys_dir, strerror(errno));
                return -1;
            }
        } else if ( stat_result < 0 ) {
            /* error calling stat, report it and return */
            Log(LOG_WARNING, "Failed to stat key directory %s: %s",
                    vars.keys_dir, strerror(errno));
            return -1;
        }
    }

    /* TODO fix the ordering of this section, it seems like I check for the
     * files existing way too many times
     */
    if ( check_key_locations() < 0 ) {
        return -1;
    }

    /* if the private key and certificate exist then thats all we need */
    if ( check_exists(vars.amqp_ssl.key, 0) == 0 &&
            check_exists(vars.amqp_ssl.cert, 0) == 0 ) {
        Log(LOG_DEBUG, "Private key and certificate both exist");
        return 0;
    }

    /*
     * The certfile doesn't exist and wasn't manually specified, so it needs
     * to be created by generating a certificate signing request and sending it
     * off to be signed.
     */
    if ( (key = get_key_file()) == NULL ) {
        return -1;
    }

    if ( (request = create_new_csr(key)) == NULL ) {
        RSA_free(key);
        return -1;
    }

    RSA_free(key);

    /* send CSR and wait for cert */
    if ( send_csr(request) < 0 ) {
        X509_REQ_free(request);
        return -1;
    }

    /* TODO test the retry loop */
    while ( (res = fetch_certificate()) == 1 && timeout > 0 ) {
        if ( timeout < AMP_PKI_QUERY_INTERVAL ) {
            Log(LOG_DEBUG, "Sleeping for %d seconds before checking for cert",
                    timeout);
            sleep(timeout);
            timeout = 0;
        } else {
            Log(LOG_DEBUG, "Sleeping for %d seconds before checking for cert",
                    AMP_PKI_QUERY_INTERVAL);
            sleep(AMP_PKI_QUERY_INTERVAL);
            timeout -= AMP_PKI_QUERY_INTERVAL;
        }
    }

    X509_REQ_free(request);
    return res;
}


