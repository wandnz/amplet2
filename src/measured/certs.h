#ifndef _MEASURED_CERTS_H
#define _MEASURED_CERTS_H

#define AMP_PKI_SSL_PORT 7655
#define AMP_MIN_PKI_QUERY_INTERVAL 30
#define AMP_MAX_PKI_QUERY_INTERVAL (30 << 7)

int get_certificate(amp_ssl_opt_t *sslopts, char *ampname, char *collector,
        int timeout);

#endif
