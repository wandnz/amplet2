/*
 * Copyright (C) 2012, iSEC Partners.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of  this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * See: https://github.com/iSECPartners/ssl-conservatory/
 *
 */

#include <openssl/ssl.h>
#include <string.h>
#include "debug.h"
#include "ssl.h"



/*
 * Extract the common name from an X509 certificate.
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
