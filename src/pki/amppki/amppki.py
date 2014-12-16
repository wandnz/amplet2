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
    result = []
    # open each file in the CSR directory - any CSR here has yet to be signed
    for item in os.listdir(CSR_DIR):
        try:
            # make sure it is a CSR
            csrstr = open("%s/%s" % (CSR_DIR, item)).read()
            csr = crypto.load_certificate_request(crypto.FILETYPE_PEM, csrstr)
            #print csr.get_subject().commonName
            #print SHA256.new(csrstr).hexdigest()
            #print
            result.append({
                "host": csr.get_subject().commonName,
                "subject": csr.get_subject(),
                "bits": csr.get_pubkey().bits(),
                "md5": MD5.new(csrstr).hexdigest(),
                "sha256": SHA256.new(csrstr).hexdigest(),
            })
        except crypto.Error as e:
            #print e
            pass

    # sort alphabetically by hostname
    result.sort(key=lambda x:x["host"])
    return result


def get_padding(host):
    return (38 - len(host)) * " "


def list_pending(pending):
    for item in pending:
        print "  %s %s %s %s" % (item["host"], get_padding(item["host"]),
                item["bits"], item["md5"])


def list_certificates(certs, which, hosts=None):
    merged = {}
    for item in certs:
        # XXX extract hostname properly?
        host = item["subject"].split("/")[1][3:]

        # only show expired certs if listing "all"
        if which == "all" and item["status"] == "E" or (
                item["status"] == "V" and item["expires"] < time()):
            status = "-"
            when = "expired %s" % strftime("%Y-%m-%d",
                    gmtime(int(item["expires"][:-3])))
        # only show valid signed certs if listing "all" or "signed"
        elif ((which == "all" or which == "signed") and
                item["status"] == "V" and item["expires"] > time()):
            status = "+"
            when = "until %s" % strftime("%Y-%m-%d",
                    gmtime(int(item["expires"][:-3])))
        # only show revoked certs if listing "all"
        elif which == "all" and item["status"] == "R":
            status = "-"
            when = "revoked %s" % strftime("%Y-%m-%d",
                    gmtime(int(item["expires"][:-3])))
        #else if which == "hosts" and host in hosts:
        # otherwise don't display this item
        else:
            continue

        if host not in merged:
            merged[host] = []
        merged[host].append("%s %s %s %s" % (status, host, get_padding(host),
                    when))

    # sort all the output based on hostname, so we ge a nice alphabetical list
    keys = merged.keys()
    keys.sort()
    for host in keys:
        for cert in merged[host]:
            print cert


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
    # TODO update index, serial
    # TODO delete csr
    return cert


def save_index(index, filename):
    #out = open(filename, "w")
    for line in index:
        print "%s\t%s\t%s\t%s\tunknown\t%s" % (line["status"], line["expires"],
                line["revoked"], line["serial"], line["subject"])


def load_index(filename):
    index = []
    for line in open(filename).readlines():
        parts = line.split("\t")
        index.append({
            "status": parts[0],
            "expires": parts[1],
            "revoked": parts[2] if len(parts[2]) > 0 else "",
            "serial": parts[3],
            "subject": parts[5]
        })
    return index


if __name__ == '__main__':
    if len(sys.argv) < 2:
        usage(os.path.basename(sys.argv[0]))
        sys.exit(0)

    pending = load_csr()
    index = load_index(INDEX_FILE)

    if sys.argv[1] == "list":
        if len(sys.argv) == 2:
            # default is to just list outstanding requests
            list_pending(pending)
        elif sys.argv[2] == "signed":
            # show only signed certificates
            list_certificates(index, "signed")
        elif sys.argv[2] == "all":
            # show all certificates
            list_certificates(index, "all")
            list_pending(pending)
        else:
            # list just the hosts named
            #list_certificates(index, "host", sys.argv[2:])
            pass

    if sys.argv[1] == "sign":
        # find CSR
        # load CSR
        # sign CSR
        sign_cert()
