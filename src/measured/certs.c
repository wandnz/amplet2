#include <config.h>

#include <stdlib.h>
#include <stdio.h>
//#include <assert.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <errno.h>
#include <curl/curl.h>

#include "debug.h"
#include "messaging.h"
#include "global.h"
//#include "ssl.h"
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
static int stat_filesize(char *path) {
    struct stat statbuf;

    if ( stat(path, &statbuf) < 0 ) {
        return -1;
    }

    return statbuf.st_size;
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
    int exists;
    int specified = 1;
    FILE *privfile;
    RSA *keypair;

    Log(LOG_DEBUG, "Get private key");

    /* if key isn't set, then figure out where it should be */
    if ( vars.amqp_ssl.key == NULL ) {

        specified = 0;

        /* set the keyfile to be the default location for this ampname */
        if ( asprintf(&vars.amqp_ssl.key, "%s/key.pem", vars.keys_dir) < 0 ) {
            Log(LOG_ALERT, "Failed to build custom keyfile path");
            return NULL;
        }
    }

    /* check if the keyfile exists */
    exists = check_exists(vars.amqp_ssl.key, specified);

    if ( exists < 0 ) {
        return NULL;
    }

    if ( exists == 0 ) {
        if ( (privfile = fopen(vars.amqp_ssl.key, "r")) == NULL ) {
            return NULL;
        }

        /* open it so we can use it to create a CSR */
        if ( PEM_read_RSAPrivateKey(privfile, &keypair, NULL, NULL) == NULL ) {
            return NULL;
        }

        Log(LOG_DEBUG, "Using existing private key %s", vars.amqp_ssl.key);

        fclose(privfile);
        return keypair;
    }

    /* keyfile wasn't manually specified, try to create it if we can */
    Log(LOG_DEBUG, "Key file doesn't exist, creating %s", vars.amqp_ssl.key);

    if ( (keypair = RSA_generate_key(2048, RSA_F4, NULL, NULL)) == NULL ) {
        Log(LOG_ALERT, "Failed to generate RSA key");
        return NULL;
    }

    /* write the private key to disk */
    if ( (privfile = fopen(vars.amqp_ssl.key, "w")) == NULL ) {
        RSA_free(keypair);
        return NULL;
    }

    if ( PEM_write_RSAPrivateKey(privfile, keypair,
                NULL, NULL, 0, NULL, NULL) != 1 ) {
        RSA_free(keypair);
        fclose(privfile);
        return NULL;
    }

    fclose(privfile);
    return keypair;
}



/*
 * Check if a certificate signing request already exists, and if so return it.
 * If it doesn't exist then try to create one.
 */
static char *get_csr(void) {
    X509_REQ *request;
    EVP_PKEY *pkey;
    X509_NAME *name;
    RSA *keypair;
    FILE *csrfile;
    char *filename;
    int exists;

    Log(LOG_DEBUG, "Get certificate signing request");

    /* TODO check if CSR already exists, and if so open and return it */
    if ( asprintf(&filename, "%s/%s.csr", vars.keys_dir, vars.collector) < 0 ) {
        Log(LOG_ALERT, "Failed to build custom CSR path");
        return NULL;
    }

    exists = check_exists(filename, 0);

    if ( exists < 0 ) {
        free(filename);
        return NULL;
    }

    if ( (request = X509_REQ_new()) == NULL ) {
        free(filename);
        return NULL;
    }

    if ( exists == 0 ) {
        if ( (csrfile = fopen(filename, "r")) == NULL ) {
            free(filename);
            return NULL;
        }

        /* open it so we can use it to create a CSR */
        if ( PEM_read_X509_REQ(csrfile, &request, NULL, NULL) == NULL ) {
            fclose(csrfile);
            free(filename);
            return NULL;
        }

        Log(LOG_DEBUG, "Using existing csr %s", filename);

        fclose(csrfile);
        return filename;
    }

    Log(LOG_DEBUG, "CSR doesn't exist, will create %s", filename);

    /* otherwise, need to create a new CSR, get the private key and do it */
    if ( (keypair = get_key_file()) == NULL ) {
        free(filename);
        return NULL;
    }

    if ( (pkey = EVP_PKEY_new()) == NULL ) {
        free(filename);
        return NULL;
    }

    if ( !EVP_PKEY_assign_RSA(pkey, keypair) ) {
        free(filename);
        return NULL;
    }

    Log(LOG_DEBUG, "Creating new CSR request");

    //XXX do these have error checking?
    X509_REQ_set_pubkey(request, pkey);
    name = X509_REQ_get_subject_name(request);
    X509_NAME_add_entry_by_txt(name,"CN",MBSTRING_ASC, vars.ampname, -1, -1, 0);
    X509_NAME_add_entry_by_txt(name,"O", MBSTRING_ASC, "client", -1, -1, 0);

    /* write CSR to disk */
    if ( (csrfile = fopen(filename, "w") ) == NULL ) {
        free(filename);
        return NULL;
    }

    PEM_write_X509_REQ(csrfile, request);

    fclose(csrfile);

    return filename;
}



/*
 *
 */
static int get_cacert(void) {
    int specified = 1;
    int exists;
    CURL *curl;
    CURLcode res;
    FILE *cacertfile;
    double size;
    long code;
    char *url;

    Log(LOG_DEBUG, "Get CA certificate");

    /* if key isn't set, then figure out where it should be */
    if ( vars.amqp_ssl.cacert == NULL ) {

        specified = 0;

        /* set the cacert to be the default location for this collector */
        if ( asprintf(&vars.amqp_ssl.cacert, "%s/%s.pem", AMP_KEYS_DIR,
                    vars.collector) < 0 ) {
            Log(LOG_ALERT, "Failed to build custom cacert file path");
            return -1;
        }
    }

    /* check if the keyfile exists */
    if ( (exists = check_exists(vars.amqp_ssl.cacert, specified)) != 1 ) {
        return exists;
    }

    if ( (cacertfile = fopen(vars.amqp_ssl.cacert, "w")) == NULL ) {
        return -1;
    }

    if ( asprintf(&url, "http://%s:%d/cacert", vars.collector,
                AMP_PKI_PORT) < 0 ) {
        Log(LOG_ALERT, "Failed to build cacert fetch url");
        fclose(cacertfile);
        return -1;
    }

    Log(LOG_INFO, "Fetching CA certificate from %s", url);

    /* fetch the CA cert from the collector */
    curl = curl_easy_init();
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, PACKAGE_STRING);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, cacertfile);

    res = curl_easy_perform(curl);

    fclose(cacertfile);
    free(url);

    if ( res != CURLE_OK ) {
        Log(LOG_WARNING, "Failed to fetch cacert: %s", curl_easy_strerror(res));
        curl_easy_cleanup(curl);
        return -1;
    }

    /* check return code and that data was received */
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    curl_easy_getinfo(curl, CURLINFO_SIZE_DOWNLOAD, &size);
    curl_easy_cleanup(curl);

    if ( code != 200 || size <= 0 ) {
        Log(LOG_WARNING,
                "Response code %d, file size %sB, deleting invalid CA cert",
                code, size);
        if ( unlink(cacertfile) < 0 ) {
            Log(LOG_WARNING, "Failed to remove CA cert '%s': %s", cacertfile,
                    strerror(errno));
        }
        return -1;
    }

    Log(LOG_INFO, "CA certificate stored in %s", vars.amqp_ssl.cacert);

    return 0;
}



static int send_csr(char *request) {
    CURL *curl;
    CURLcode res;
    FILE *certfile, *csr;
    double size;
    long code;
    char *url;
    int csr_size;

    Log(LOG_DEBUG, "Send CSR");

    if ( (certfile = fopen(vars.amqp_ssl.cert, "w")) == NULL ) {
        return -1;
    }

    if ( (csr_size = stat_filesize(request)) < 0 ) {
        fclose(certfile);
        return -1;
    }

    if ( (csr = fopen(request, "r")) == NULL ) {
        fclose(certfile);
        return -1;
    }

    //XXX should be https to verify cert
    if ( asprintf(&url, "https://%s:%d/sign", vars.collector,
                AMP_PKI_PORT) < 0 ) {
        Log(LOG_ALERT, "Failed to build cert signing url");
        fclose(certfile);
        fclose(csr);
        return -1;
    }

    Log(LOG_INFO, "Sending CSR found in %s to %s", request, url);

    curl = curl_easy_init();
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, PACKAGE_STRING);
    curl_easy_setopt(curl, CURLOPT_POST, 1);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, csr_size);
    curl_easy_setopt(curl, CURLOPT_READDATA, csr);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, certfile);

    //XXX may need to remove Expect header to actually work?
    //XXX what content type do i want?

    curl_easy_setopt(curl, CURLOPT_CAINFO, vars.amqp_ssl.cacert);
    /* Try to verify the server certificate */
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1);
    /* Try to verify the server hostname/commonname */
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2);

    res = curl_easy_perform(curl);

    fclose(certfile);
    fclose(csr);
    free(url);

    if ( res != CURLE_OK ) {
        Log(LOG_WARNING, "Failed to send CSR: %s", curl_easy_strerror(res));
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

        /* CSR was accepted but has not yet been signed, wait and try again */
        if ( code == 202 ) {
            Log(LOG_DEBUG, "CSR was accepted but has not yet been signed");
            return 1;
        }

        Log(LOG_WARNING, "Error fetching signed cert, code:%d, size:%sB",
                code, size);
        return -1;
    }

    Log(LOG_INFO, "Signed certificate stored in %s", vars.amqp_ssl.cert);

    return 0;
}



/*
 * Make sure that all the SSL variables are pointing to certificates, keys,
 * etc that exist. If they don't exist then we try to create them as best
 * as we can.
 * TODO function needs a better name
 */
int get_certificate(int timeout) {
    char *request;
    int exists;
    int specified = 1;
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

    if ( vars.amqp_ssl.cert == NULL ) {

        specified = 0;

        /* set the certfile to be the default location for this ampname */
        if ( asprintf(&vars.amqp_ssl.cert, "%s/%s.cert",
                    vars.keys_dir, vars.collector) < 0 ) {
            Log(LOG_ALERT, "Failed to build custom certfile path");
            return -1;
        }
    }

    /* check if the keyfile exists */
    if ( (exists = check_exists(vars.amqp_ssl.cert, specified)) != 1 ) {
        /* XXX should check that the cert and key and ca all match? */
        /* -1 is error, 0 is a good existing file, neither need any more work */
        return exists;
    }

    /* certfile doesn't exist and wasn't manually specified, need to create */
    if ( (request = get_csr()) == NULL ) {
        return -1;
    }

    /* get the cacert if we don't already have one for this server */
    if ( get_cacert() < 0 ) {
        free(request);
        return -1;
    }

    /* send CSR and wait for cert */
    while( (res = send_csr(request)) == 1 && timeout > 0 ) {
        if ( timeout < AMP_PKI_QUERY_INTERVAL ) {
            Log(LOG_DEBUG, "Sleeping for %d seconds before sending CSR again",
                    timeout);
            sleep(timeout);
            timeout = 0;
        } else {
            Log(LOG_DEBUG, "Sleeping for %d seconds before sending CSR again",
                    AMP_PKI_QUERY_INTERVAL);
            sleep(AMP_PKI_QUERY_INTERVAL);
            timeout -= AMP_PKI_QUERY_INTERVAL;
        }
    }

    free(request);
    return res;
}


