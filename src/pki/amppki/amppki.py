import os
import sys
from time import strftime, gmtime, time
from OpenSSL import crypto
from Crypto.Hash import SHA256,MD5

CA_DIR = "/tmp/brendonj/ampca"
CERT_DIR = "%s/certs" % CA_DIR
KEY_DIR = "%s/private" % CA_DIR
CSR_DIR = "%s/csr" % CA_DIR
INDEX_FILE = "%s/index.txt" % CA_DIR

def usage(progname):
    print "Usage:"
    print "    %s <command> <options>" % progname
    print
    print "Commands:"
    print "    generate"
    print "    list"
    print "    revoke"
    print "    sign"


def load_csr():
    result = {}
    # open each file in the CSR directory - any CSR here has yet to be signed
    for item in os.listdir(CSR_DIR):
        try:
            # make sure it is a CSR
            csrstr = open("%s/%s" % (CSR_DIR, item)).read()
            csr = crypto.load_certificate_request(crypto.FILETYPE_PEM, csrstr)
            #print csr.get_subject().commonName
            #print SHA256.new(csrstr).hexdigest()
            #print
            item = {
                "status": None,
                "expires": None,
                "revoked": None,
                "serial": None,
                "subject": csr.get_subject(),
                "md5": MD5.new(csrstr).hexdigest(),
                "sha256": SHA256.new(csrstr).hexdigest(),
            }
            host = csr.get_subject().commonName
            if host not in result:
                result[host] = []
            result[host].append(item)
        except crypto.Error as e:
            #print e
            pass
    return result


def list_certificates(certs):
    keys = certs.keys()
    keys.sort()

    for host in keys:
        for cert in certs[host]:
            if cert["status"] == "E" or (
                    cert["status"] == "V" and cert["expires"] < time()):
                status = "-"
                when = "expired %s" % strftime("%y-%m-%d",
                        gmtime(cert["expires"]))
            elif cert["status"] == "V":
                status = "+"
                when = "until %s" % strftime("%Y-%m-%d",
                        gmtime(cert["expires"]))
            elif cert["status"] == "R":
                status = "-"
                when = "revoked %s" % strftime("%Y-%m-%d",
                        gmtime(cert["revoked"]))
            else:
                status = " "
                #when = "waiting"
                when = cert["md5"]

            padding = (42 - len(host)) * " "
            print "%s %s %s %s" % (status, host, padding, when)


def revoke_certs():
    pass


def generate_certs():
    pass


# TODO how much should be exposed? serial numbers? notbefore, notafter?
# TODO let openssl do this rather than doing it ourselves?
# openssl ca -config openssl.cnf -in ../$name/req.pem -out \
#            ../$name/cert.pem -notext -batch -extensions amp_ca_extensions
# [ amp_ca_extensions ]
# basicConstraints = CA:false
# keyUsage = digitalSignature, keyEncipherment
# extendedKeyUsage = 1.3.6.1.5.5.7.3.2, 1.3.6.1.5.5.7.3.1
def sign_cert(request):
    serial = 1
    notbefore = 0
    # XXX how long should they be valid for by default?
    notafter = 60 * 60 * 24 * 365 * 10
    #issuer_cert = get our cacert
    #issuer_key = get our key
    digest = "sha256"

    cert = crypto.X509()
    cert.set_serial_number(serial)
    cert.gmtime_adj_notBefore(notbefore)
    cert.gmtime_adj_notAfter(notAfter)
    cert.set_issuer(issuer_cert.get_subject())
    cert.set_subject(request.get_subject())
    cert.set_pubkey(request.get_pubkey())

    cert.sign(issuer_key, digest)
    # TODO delete csr
    return cert


def load_index(filename):
    index = {
        "valid": {},
        "invalid": {}
    }

    for line in open(filename).readlines():
        parts = line.split("\t")
        item = {
            "status": parts[0],
            "expires": int(parts[1][:-3]),
            "revoked": int(parts[2][:-3]) if len(parts[2]) > 0 else 0,
            "serial": parts[3],
            "subject": parts[5]
        }
        # XXX extract CN properly!
        host = item["subject"].split("/")[1][3:]

        if item["status"] == "V":
            if host not in index["valid"]:
                index["valid"][host] = []
            index["valid"][host].append(item)
        elif item["status"] == "R" or item["status"] == "E":
            if host not in index["invalid"]:
                index["invalid"][host] = []
            index["invalid"][host].append(item)
    return index


# merge two certificate stores, merging the lists of certificates per hostname
# rather than clobbering them
def merge(a, b):
    result = a.copy()
    for k,v in b.iteritems():
        if k in result:
            result[k] += v
        else:
            result[k] = v
    return result


if __name__ == '__main__':
    if len(sys.argv) < 2:
        usage(os.path.basename(sys.argv[0]))
        sys.exit(0)

    csr = load_csr()
    index = load_index(INDEX_FILE)

    if sys.argv[1] == "list":
        if len(sys.argv) == 2:
            # default is to just list outstanding requests
            list_certificates(csr)
        elif sys.argv[2] == "signed":
            # show only signed certificates
            list_certificates(index["valid"])
        elif sys.argv[2] == "all":
            # show all certificates
            all_certs = merge(merge(index["valid"], index["invalid"]), csr)
            list_certificates(all_certs)
        else:
            # list just the hosts named
            pass

    if sys.argv[1] == "sign":
        # find CSR
        # load CSR
        # sign CSR
        sign_cert()
