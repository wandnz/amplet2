#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <assert.h>
#include <sys/types.h>
#include <unistd.h>

#include "global.h"
#include "debug.h"
#include "ssl.h"



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
 * See: https://github.com/iSECPartners/ssl-conservatory/
 *
 * Make sure that the hostname of the machine we are connecting to/from matches
 * the common name in the certificate. We don't want to talk to someone who
 * has a valid cert, but is not issued to them!
 */
int matches_common_name(const char *hostname, const X509 *cert) {
    int common_name_loc = -1;
    X509_NAME_ENTRY *common_name_entry = NULL;
    ASN1_STRING *common_name_asn1 = NULL;
    char *common_name_str = NULL;

    /* Find position of the CN field in the Subject field of the certificate */
    common_name_loc = X509_NAME_get_index_by_NID(X509_get_subject_name(
                (X509*)cert), NID_commonName, -1);
    if (common_name_loc < 0) {
        Log(LOG_WARNING, "Error finding position of Common Name field in cert");
        return -2;
    }

    /* Extract the CN field */
    common_name_entry = X509_NAME_get_entry(X509_get_subject_name(
                (X509 *)cert), common_name_loc);
    if (common_name_entry == NULL) {
        Log(LOG_WARNING, "Error extracting Common Name from cert");
        return -2;
    }

    /* Convert the CN field to a C string */
    common_name_asn1 = X509_NAME_ENTRY_get_data(common_name_entry);
    if (common_name_asn1 == NULL) {
        Log(LOG_WARNING, "Error converting Common Name");
        return -2;
    }
    common_name_str = (char *) ASN1_STRING_data(common_name_asn1);

    /* Make sure there isn't an embedded NUL character in the CN */
    if ((size_t)ASN1_STRING_length(common_name_asn1) !=
            strlen(common_name_str)) {
        Log(LOG_WARNING, "Malformed Common Name in cert");
        return -3;
    }

    /* Compare expected hostname with the CN */
    if (strcasecmp(hostname, common_name_str) == 0) {
        Log(LOG_DEBUG, "Hostname '%s' matches Common Name in cert", hostname);
        return 0;
    }

    Log(LOG_WARNING, "Hostname '%s' does not match Common Name '%s'", hostname,
            common_name_str);

    return -1;
}



/*
 * See: https://github.com/iSECPartners/ssl-conservatory/
 *
 * Initialise the SSL context and load all the keys that we will be using.
 */
int initialise_ssl(void) {
    Log(LOG_DEBUG, "Initialising SSL");

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
    if(RAND_status() != 1) {
        Log(LOG_WARNING, "OpenSSL PRNG not seeded with enough data.");
        ssl_cleanup();
        return -1;
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
SSL_CTX* initialise_ssl_context(void) {
    SSL_CTX *ssl_ctx = NULL;
    EC_KEY *ecdh;
    DH *dh;

    Log(LOG_DEBUG, "Initialising SSL context");

    if ( vars.amqp_ssl.cacert == NULL || vars.amqp_ssl.cert == NULL ||
            vars.amqp_ssl.key == NULL ) {
        Log(LOG_WARNING, "Can't initialise SSL, certs and keys aren't set");
        return NULL;
    }

    /*
     * limit connections to using TLSv1.2 and above, we don't care about
     * backwards compatability with old clients as we control them all
     */
    ssl_ctx = SSL_CTX_new(SSLv23_method());
    SSL_CTX_set_options(ssl_ctx, SSL_OP_MIN_TLSv1_2);

    /* Make sure all clients provide a certificate, and that it is valid */
    SSL_CTX_set_verify(ssl_ctx,
            SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

    /* Load our certificate */
    if ( SSL_CTX_use_certificate_chain_file(ssl_ctx,vars.amqp_ssl.cert) != 1 ) {
        Log(LOG_WARNING, "Couldn't load certificate.\n");
        ssl_cleanup();
        return NULL;
    }

    /* Load our private key */
    if ( SSL_CTX_use_PrivateKey_file(ssl_ctx, vars.amqp_ssl.key,
                SSL_FILETYPE_PEM) != 1 ) {
        Log(LOG_WARNING, "Couldn't load private key.\n");
        ssl_cleanup();
        return NULL;
    }

    /* Check that the certificate and key agree */
    if ( SSL_CTX_check_private_key(ssl_ctx) != 1 ) {
        Log(LOG_WARNING, "Private key does not match certificate.\n");
        ssl_cleanup();
        return NULL;
    }

    /* Load our cacert we will validate others against */
    if (SSL_CTX_load_verify_locations(ssl_ctx,vars.amqp_ssl.cacert,NULL) != 1) {
        Log(LOG_WARNING, "Couldn't load certificate trust store.\n");
        ssl_cleanup();
        return NULL;
    }

    /* Only support ciphers we believe are secure */
    if (SSL_CTX_set_cipher_list(ssl_ctx, SECURE_CIPHER_LIST) != 1) {
        ssl_cleanup();
        return NULL;
    }

    Log(LOG_DEBUG, "Setting up Diffie-Hellman parameters");

    /*
     * Help prevent small subgroup attacks by always creating a new key when
     * using Diffie-Hellman. Has a slight cost during connection negotiation,
     * but improves forward secrecy.
     */
    SSL_CTX_set_options(ssl_ctx, SSL_OP_SINGLE_DH_USE);

    /*
     * To use Diffie-Hellman ciphers for PFS, we need to set up the parameters
     * or our cipher choices will forever be silently ignored.
     * TODO confirm these are good parameters choices
     * TODO this takes ~30 on startup, use the static approach (see dhparam).
     */
    if ( (dh = DH_generate_parameters(1024, 5, NULL, NULL)) == NULL ) {
        log_ssl("Failed to generate Diffie-Hellman parameters");
        ssl_cleanup();
        return NULL;
    }

    if ( SSL_CTX_set_tmp_dh(ssl_ctx, dh) != 1 ) {
        log_ssl("Failed to set Diffie-Hellman keys");
        DH_free(dh);
        ssl_cleanup();
        return NULL;
    }

    DH_free(dh);

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
        EC_KEY_free (ecdh);
        ssl_cleanup();
        return NULL;
    }

    EC_KEY_free (ecdh);

    return ssl_ctx;
}



/*
 * Wait for and accept an incoming SSL session over top of an existing, open
 * socket and perform initial checks on certificate validity.
 */
SSL* ssl_accept(SSL_CTX *ssl_ctx, int fd) {
    SSL *ssl;

    assert(ssl_ctx);

    Log(LOG_DEBUG, "Accepting new SSL connection");

    if ( (ssl = SSL_new(ssl_ctx)) == NULL ) {
        Log(LOG_DEBUG, "Failed to create new SSL connection descriptor");
        return NULL;
    }

    /* Set this fd as the input/output for this ssl */
    if ( SSL_set_fd(ssl, fd) != 1 ) {
        log_ssl("Failed to set SSL connection descriptor");
        return NULL;
    }

    /* Wait for the remote end to initiate handshake */
    if ( SSL_accept(ssl) != 1 ) {
        log_ssl("Failed to accept SSL connection");
        return NULL;
    }

    /* Check that the cert presented is valid */
    if ( SSL_get_verify_result(ssl) != X509_V_OK ) {
        log_ssl("Failed to validate client certificate");
        return NULL;
    }

    return ssl;
}



/*
 * Connect an SSL session over top of an existing, open socket and perform
 * initial checks on certificate validity.
 */
SSL* ssl_connect(SSL_CTX *ssl_ctx, int fd) {
    SSL *ssl;

    assert(ssl_ctx);

    Log(LOG_DEBUG, "Creating new SSL connection");

    if ( (ssl = SSL_new(ssl_ctx)) == NULL ) {
        Log(LOG_DEBUG, "Failed to create new SSL connection descriptor");
        return NULL;
    }

    /* Set this fd as the input/output for this ssl */
    if ( SSL_set_fd(ssl, fd) != 1 ) {
        log_ssl("Failed to set SSL connection descriptor");
        return NULL;
    }

    /* Initiate the handshake */
    if ( SSL_connect(ssl) != 1 ) {
        log_ssl("Failed to complete SSL handshake");
        return NULL;
    }

    /* Check that the cert presented is valid */
    if ( SSL_get_verify_result(ssl) != X509_V_OK ) {
        log_ssl("Failed to validate client certificate");
        return NULL;
    }

    return ssl;
}



/*
 * Shutdown and free an SSL session.
 */
void ssl_shutdown(SSL *ssl) {
    assert(ssl);

    Log(LOG_DEBUG, "Shutting down SSL connection");

#if 0
    /* call shutdown twice to make sure bi-directional shutdown is complete */
    if ( SSL_shutdown(ssl) == 0 ) {
        SSL_shutdown(ssl);
    }
#endif
    /*
     * We can't rely on the other end to play nice and shutdown when we want
     * to, so only call shutdown once and ignore whatever the other end thinks.
     */
    SSL_shutdown(ssl);

    Log(LOG_DEBUG, "Finished shutting down SSL connection");

    SSL_free(ssl);
    ssl = NULL;
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
}
