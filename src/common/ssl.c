#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ec.h>
#include <assert.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>

#include "debug.h"
#include "ssl.h"
#include "testlib.h"


/*
 * http://www.cypherpunks.to/~peter/06_random.pdf
 * https://www.cs.auckland.ac.nz/~pgut001/pubs/book.pdf
 */


/*
 * XXX check that this is the right way to get errors, when should we use
 * SSL_get_error vs ERR_get_error
 */
static void log_ssl(char *msg) {
    int code;
    char buffer[SSL_ERROR_BUFFER_LENGTH];

    code = ERR_get_error();

    if ( code > 0 ) {
        ERR_error_string(code, buffer);
    } else {
        sprintf(buffer, "No SSL error");
    }

    Log(LOG_WARNING, "%s:%s", msg, buffer);
}



/*
 * Make sure that the locations of all keys have been set. If they were
 * manually specified then the files need to exist, otherwise we don't
 * care either way, they will get created if they need to be.
 */
static int check_key_locations(amp_ssl_opt_t *sslopts, char *collector) {

    if ( sslopts->cert == NULL ) {
        if ( asprintf(&sslopts->cert, "%s/%s.cert",
                    sslopts->keys_dir, collector) < 0 ) {
            Log(LOG_ALERT, "Failed to build custom certfile path");
            return -1;
        }
    } else if ( check_exists(sslopts->cert, 1) < 0 ) {
        return -1;
    }

    if ( sslopts->key == NULL ) {
        if ( asprintf(&sslopts->key, "%s/key.pem",
                    sslopts->keys_dir) < 0 ) {
            Log(LOG_ALERT, "Failed to build custom keyfile path");
            return -1;
        }
    } else if ( check_exists(sslopts->key, 1) < 0 ) {
        return -1;
    }

    if ( sslopts->cacert == NULL ) {
        if ( asprintf(&sslopts->cacert, "%s/%s.pem", AMP_KEYS_DIR,
                    collector) < 0 ) {
            Log(LOG_ALERT, "Failed to build custom cacert file path");
            return -1;
        }
    }

    /*
     * The cacert should be distributed through some trusted means, it must
     * exist here for us to continue.
     */
    if ( check_exists(sslopts->cacert, 1) < 0 ) {
        Log(LOG_WARNING, "Server certificate %s doesn't exist!",
                sslopts->cacert);
        return -1;
    }

    return 0;
}



/*
 * The openssl random number generator also needs reseeding after a fork.
 * Newer versions of the library do this, but debian hasn't picked those
 * up yet. In the meantime, mix in the time and pid (but not the 2 bytes of
 * random stack data recommended, valgrind really hates that) as based on:
 * http://wiki.openssl.org/index.php/Random_fork-safety
 */
void reseed_openssl_rng(void) {
    long long seed[2];
    seed[0] = (long long)time(NULL);
    seed[1] = (long long)getpid();
    RAND_seed(seed, sizeof(seed));
}



/*
 *
 */
char* get_common_name(const X509 *cert) {
    int common_name_loc;
    X509_NAME_ENTRY *common_name_entry = NULL;
    ASN1_STRING *common_name_asn1 = NULL;
    char *common_name_str = NULL;

    /* Find position of the CN field in the Subject field of the certificate */
    common_name_loc = X509_NAME_get_index_by_NID(X509_get_subject_name(
                (X509*)cert), NID_commonName, -1);
    if (common_name_loc < 0) {
        Log(LOG_WARNING, "Error finding position of Common Name field in cert");
        return NULL;
    }

    /* Extract the CN field */
    common_name_entry = X509_NAME_get_entry(X509_get_subject_name(
                (X509 *)cert), common_name_loc);
    if (common_name_entry == NULL) {
        Log(LOG_WARNING, "Error extracting Common Name from cert");
        return NULL;
    }

    /* Convert the CN field to a C string */
    common_name_asn1 = X509_NAME_ENTRY_get_data(common_name_entry);
    if (common_name_asn1 == NULL) {
        Log(LOG_WARNING, "Error converting Common Name");
        return NULL;
    }
    common_name_str = (char *) ASN1_STRING_data(common_name_asn1);

    /* Make sure there isn't an embedded NUL character in the CN */
    if ((size_t)ASN1_STRING_length(common_name_asn1) !=
            strlen(common_name_str)) {
        Log(LOG_WARNING, "Malformed Common Name in cert");
        return NULL;
    }

    return common_name_str;
}



/*
 * See: https://github.com/iSECPartners/ssl-conservatory/
 *
 * Make sure that the hostname of the machine we are connecting to/from matches
 * the common name in the certificate. We don't want to talk to someone who
 * has a valid cert, but is not issued to them!
 */
int matches_common_name(const char *hostname, const X509 *cert) {
    char *common_name = NULL;

    if ( (common_name = get_common_name(cert)) == NULL ) {
        Log(LOG_WARNING, "Failed to get common name from certificate");
        return -1;
    }

    /* Compare expected hostname with the CN */
    if (strcasecmp(hostname, common_name) == 0) {
        Log(LOG_DEBUG, "Hostname '%s' matches Common Name in cert", hostname);
        return 0;
    }

    Log(LOG_WARNING, "Hostname '%s' does not match Common Name '%s'", hostname,
            common_name);

    return -1;
}



/*
 * See: https://github.com/iSECPartners/ssl-conservatory/
 *
 * Initialise the SSL context and load all the keys that we will be using.
 */
int initialise_ssl(amp_ssl_opt_t *sslopts, char *collector) {
    Log(LOG_DEBUG, "Initialising global SSL options");

    /*
     * "OpenSSL will attempt to seed the random number generator
     * automatically upon instantiation by calling RAND_poll. If the generator
     * is not initialized and RAND_bytes is called, then the generator will
     * also call RAND_poll"
     *
     * Looks like this works fine unless we are running AMP on VxWorks, which
     * sounds unlikely at this stage!
     *
     * http://wiki.openssl.org/index.php/Random_Numbers
     */
    SSL_library_init();
    SSL_load_error_strings();

    /*
     * TODO we might want to loop on this and add more entropy if it fails,
     * but I have yet to see it fail (on either physical and virtual machines).
     */
    if ( RAND_status() != 1 ) {
        Log(LOG_WARNING, "OpenSSL PRNG not seeded with enough data.");
        ssl_cleanup();
        return -1;
    }

    /*
     * Make sure that key locations are valid. This will populate them all
     * with default values if unset, and will make sure they exist if manually
     * set.
     */
    if ( collector ) {
        if ( check_key_locations(sslopts, collector) < 0 ) {
            ssl_cleanup();
            return -1;
        }
    }

    /*
     * OpenSSL 1.0.1-beta1 to 1.0.1e will apparently use RDRAND as the source
     * of all randomness, entropy, etc in an unsafe way. Disabling RDRAND is
     * the recommended approach, which Debian did in version 1.0.1e-2+deb7u1
     * on 23 December 2013.
     *
     * TODO Do we actually need to disable it ourselves in code as well? Do
     * we trust all the distributions that we are running on?
     *
     * http://wiki.openssl.org/index.php/Library_Initialization
     * http://seclists.org/fulldisclosure/2013/Dec/99
     */

    return 0;
}



/*
 *
 */
SSL_CTX* initialise_ssl_context(amp_ssl_opt_t *sslopts) {
    SSL_CTX *ssl_ctx = NULL;
    EC_KEY *ecdh;

    Log(LOG_DEBUG, "Initialising SSL context");

    if ( sslopts->cacert == NULL || sslopts->cert == NULL ||
            sslopts->key == NULL ) {
        Log(LOG_WARNING, "Can't initialise SSL, certs and keys aren't set");
        return NULL;
    }

    /*
     * limit connections to using TLSv1.2 and above, we don't care about
     * backwards compatability with old clients as we control them all
     */
    ssl_ctx = SSL_CTX_new(SSLv23_method());
    SSL_CTX_set_options(ssl_ctx, SSL_OP_MIN_TLSv1_2);

    /* disable compression to mitigate CRIME attack */
    SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_COMPRESSION);

    /* Make sure all clients provide a certificate, and that it is valid */
    SSL_CTX_set_verify(ssl_ctx,
            SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

    Log(LOG_INFO, "Loading certificate from %s", sslopts->cert);
    /* Load our certificate */
    if ( SSL_CTX_use_certificate_chain_file(ssl_ctx,sslopts->cert) != 1 ) {
        Log(LOG_WARNING, "Couldn't load certificate %s", sslopts->cert);
        ssl_cleanup();
        return NULL;
    }

    Log(LOG_INFO, "Loading private key from %s", sslopts->key);
    /* Load our private key */
    if ( SSL_CTX_use_PrivateKey_file(ssl_ctx, sslopts->key,
                SSL_FILETYPE_PEM) != 1 ) {
        Log(LOG_WARNING, "Couldn't load private key %s", sslopts->key);
        ssl_cleanup();
        return NULL;
    }

    /* Check that the certificate and key agree */
    if ( SSL_CTX_check_private_key(ssl_ctx) != 1 ) {
        Log(LOG_WARNING, "Private key does not match certificate");
        ssl_cleanup();
        return NULL;
    }

    Log(LOG_INFO, "Loading CA certificate from %s", sslopts->cacert);
    /* Load our cacert we will validate others against */
    if (SSL_CTX_load_verify_locations(ssl_ctx,sslopts->cacert,NULL) != 1) {
        Log(LOG_WARNING, "Couldn't load certificate trust store",
                sslopts->cacert);
        ssl_cleanup();
        return NULL;
    }

    /* Only support ciphers we believe are secure */
    if (SSL_CTX_set_cipher_list(ssl_ctx, SECURE_CIPHER_LIST) != 1) {
        Log(LOG_WARNING, "Failed to set cipher list");
        ssl_cleanup();
        return NULL;
    }

    /*
     * To use elliptic curve Diffie-Hellman ciphers for PFS, we need to set up
     * the parameters or our cipher choices will forever be silently ignored.
     */
    Log(LOG_DEBUG, "Setting up elliptic curve");

    /* always generate a new key when using ECDH ciphers */
    SSL_CTX_set_options(ssl_ctx, SSL_OP_SINGLE_ECDH_USE);

    if ( (ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1)) == NULL ) {
        Log(LOG_WARNING, "Failed to create elliptic curve");
        ssl_cleanup();
        return NULL;
    }

    if ( SSL_CTX_set_tmp_ecdh(ssl_ctx, ecdh) != 1 ) {
        Log(LOG_WARNING, "Failed to set elliptic curve");
        EC_KEY_free(ecdh);
        ssl_cleanup();
        return NULL;
    }

    EC_KEY_free(ecdh);

    return ssl_ctx;
}



/*
 * Establish a control connection across an existing, connected socket. If
 * there is an SSL context then this will perform the server/client side
 * establishment as directed, otherwise it will just wrap the file descriptor
 * in a BIO with no further action.
 */
BIO* establish_control_socket(SSL_CTX *ssl_ctx, int fd, int client) {
    BIO *socket_bio, *top_bio;

    if ( (socket_bio = BIO_new_socket(fd, BIO_CLOSE)) == NULL ) {
        Log(LOG_WARNING, "Failed to create new socket BIO");
        return NULL;
    }

    if ( ssl_ctx ) {
        BIO *ssl_bio;
        SSL *ssl;

        Log(LOG_DEBUG, "Active SSL context, using SSL BIO");

        /* 0 flags this as a server connection */
        if ( (ssl_bio = BIO_new_ssl(ssl_ctx, client)) == NULL ) {
            log_ssl("Failed to create new SSL BIO");
            BIO_free(socket_bio);
            return NULL;
        }

        top_bio = BIO_push(ssl_bio, socket_bio);

        if ( BIO_do_handshake(top_bio) != 1 ) {
            log_ssl("Failed to complete SSL handshake");
            BIO_free_all(top_bio);
            return NULL;
        }

        BIO_get_ssl(top_bio, &ssl);

        /* Check that the cert presented is valid */
        if ( SSL_get_verify_result(ssl) != X509_V_OK ) {
            log_ssl("Failed to validate client certificate");
            BIO_free_all(top_bio);
            return NULL;
        }
    } else {
        Log(LOG_DEBUG, "No SSL context, using plain socket BIO");
        top_bio = socket_bio;
    }

    Log(LOG_DEBUG, "Successfully established control connection");

    return top_bio;
}



/*
 * Cleanup as much of the memory magically allocated by SSL as we can.
 */
void ssl_cleanup(void) {
    if ( ssl_ctx != NULL ) {
        SSL_CTX_free(ssl_ctx);
    }
    EVP_cleanup();
    ERR_free_strings();
    /*
     * XXX should be able to call SSL_COMP_free_compression_methods() but our
     * libssl doesn't appear to be new enough?
     */
    sk_SSL_COMP_free(SSL_COMP_get_compression_methods());
}
