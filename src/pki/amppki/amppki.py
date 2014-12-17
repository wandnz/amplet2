import os
import sys
import fcntl
from time import strftime, gmtime, time
from OpenSSL import crypto
from Crypto.Hash import SHA256,MD5

CA_DIR = "/tmp/brendonj/ampca"
CERT_DIR = "%s/certs" % CA_DIR
#KEY_DIR = "%s/private" % CA_DIR
CSR_DIR = "%s/csr" % CA_DIR
INDEX_FILE = "%s/index.txt" % CA_DIR
SERIAL_FILE = "%s/serial" % CA_DIR
LOCK_FILE = "%s/.lock" % CA_DIR
CACERT = "%s/cacert.pem" % CA_DIR
CAKEY = "%s/private/cakey.pem" % CA_DIR


def usage(progname):
    print "Usage:"
    print "    %s <command> <options>" % progname
    print
    print "Commands:"
    print "    generate"
    print "    list"
    print "    revoke"
    print "    sign"


def rotate_files(which):
    try:
        # move primary one into the old position
        os.rename(which, "%s.old" % which)
        # move new one into the primary position
        os.rename("%s.tmp" % which, which)
    except OSError as e:
        print "Failed to rotate %s" % e
        return None
    return True


def get_and_increment_serial(filename):
    # read the next serial out of the serial file
    serial = read_serial(filename)
    if serial is None:
        return None

    # XXX assuming we pass it as a hex string to the signing function
    # write out the incremented serial to a temporary file
    if write_serial(filename, serial + 1) is False:
        return None

    # rotate the serial files so the new one is in place
    if rotate_files(SERIAL_FILE) is False:
        return None

    return serial


def read_serial(filename):
    try:
        return int(open(filename).read(), 16)
    except (IOError, ValueError) as e:
        print "Failed to read serial from %s: %s" % (SERIAL_FILE, e)
        return None


def write_serial(filename, serial):
    try:
        open("%s.tmp" % SERIAL_FILE, "w").write("%02X\n" % serial)
    except IOError as e:
        print "Failed to write serial to %s: %s" % (SERIAL_FILE, e)
        return False
    return True


def load_csr():
    result = []
    # open each file in the CSR directory - any CSR here has yet to be signed
    for item in os.listdir(CSR_DIR):
        try:
            # make sure it is a CSR
            csrstr = open("%s/%s" % (CSR_DIR, item)).read()
            csr = crypto.load_certificate_request(crypto.FILETYPE_PEM, csrstr)
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
                    gmtime(int(item["revoked"][:-3])))
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
# openssl ca -config openssl.cnf -in ../$name/req.pem -out \
#            ../$name/cert.pem -notext -batch -extensions amp_ca_extensions
# [ amp_ca_extensions ]
# basicConstraints = CA:false
# keyUsage = digitalSignature, keyEncipherment
# extendedKeyUsage = 1.3.6.1.5.5.7.3.2, 1.3.6.1.5.5.7.3.1
def sign_certificates(hosts):
    newcerts = []
    notbefore = 0
    # XXX how long should they be valid for by default?
    notafter = int(time()) + (60 * 60 * 24 * 365 * 10)
    digest = "sha256"

    try:
        issuer_cert = crypto.load_certificate(crypto.FILETYPE_PEM,
                open(CACERT).read())
        issuer_key = crypto.load_privatekey(crypto.FILETYPE_PEM,
                open(CAKEY).read())
    except IOError as e:
        print "Couldn't load CA cert and private key: %s" % e
        return []
    except crypto.Error as e:
        print "Invalid CA cert or key: %s" % e
        return []

    # XXX hostnames or sha256?
    for host in hosts:
        try:
            request = crypto.load_certificate_request(crypto.FILETYPE_PEM,
                open("%s/%s" % (CSR_DIR, host)).read())
        except IOError as e:
            print "Couldn't find CSR for %s: %s" % (host, e)
            continue
        except crypto.Error as e:
            print "Invalid CSR for %s: %s" % (host, e)
            continue

        # make sure we don't already have a certificate for this host
        if os.path.exists("%s/%s.pem" % (
                    CERT_DIR, request.get_subject().commonName)):
            print "Cert %s already exists, skipping" % (
                    request.get_subject().commonName)
            continue

        cert = crypto.X509()
        cert.gmtime_adj_notBefore(notbefore)
        cert.gmtime_adj_notAfter(notafter)
        cert.set_issuer(issuer_cert.get_subject())
        cert.set_subject(request.get_subject())
        cert.set_pubkey(request.get_pubkey())

        # XXX should all the extensions be marked as critical?
        cert.add_extensions([
            # this certificate is not a CA
            crypto.X509Extension(
                "basicConstraints",
                True,
                "CA:false"
            ),
            # this certificate can be used for signatures and encryption
            crypto.X509Extension(
                "keyUsage",
                True,
                "digitalSignature, keyEncipherment"
            ),
            # this certificate can be used for server auth and client auth
            crypto.X509Extension(
                "extendedKeyUsage",
                True,
                "1.3.6.1.5.5.7.3.1, 1.3.6.1.5.5.7.3.2",
            ),
        ])

        serial = get_and_increment_serial(SERIAL_FILE)

        if serial is None:
            print "Can't get serial number, aborting"
            # it's possible we've already signed some certificates, and so
            # should probably return them (though this is not a good state)!
            return newcerts

        cert.set_serial_number(serial)
        cert.sign(issuer_key, digest)

        # write the cert out to a file
        try:
            open("%s/%s.pem" % (
                        CERT_DIR, request.get_subject().commonName), "w").write(
                    crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        except IOError as e:
            print "Failed to write certificate %s: %s" % (host, e)
            return newcerts

        newcerts.append({
            "status": "V",
            "expires": "%s00Z" % notafter,
            "revoked": "",
            "serial": "%02X" % cert.get_serial_number(),
            "subject": "/CN=%s/O=%s" % (cert.get_subject().commonName,
                cert.get_subject().organizationName),
        })

        # TODO delete csr
    return newcerts


def save_index(index, filename):
    out = open(filename, "w")
    for line in index:
        print >> out, "%s\t%s\t%s\t%s\tunknown\t%s" % (line["status"],
                line["expires"], line["revoked"], line["serial"],
                line["subject"])
    out.close()

    if rotate_files(INDEX_FILE) is False:
        return None


def load_index(filename):
    index = []
    for line in open(filename).readlines():
        parts = line.split("\t")
        index.append({
            "status": parts[0],
            "expires": parts[1],
            "revoked": parts[2] if len(parts[2]) > 0 else "",
            "serial": parts[3],
            "subject": parts[5].strip()
        })
    return index


if __name__ == '__main__':
    if len(sys.argv) < 2:
        usage(os.path.basename(sys.argv[0]))
        sys.exit(0)

    # TODO use getopt or argparse
    lock = None
    action = sys.argv[1]

    # lock the whole CA dir for any actions that will modify it
    if action in ["sign", "revoke"]:
        try:
            lock = open(LOCK_FILE, "w")
            fcntl.lockf(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except IOError as e:
            print "Failed to lock %s: %s" % (LOCK_FILE, e)
            sys.exit(1)

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

    elif sys.argv[1] == "sign":
        newcerts = sign_certificates(sys.argv[2:])
        if len(newcerts) > 0:
            save_index(index + newcerts, "%s.tmp" % INDEX_FILE)

    elif sys.argv[1] == "revoke":
        # check certificate exists
        # revoke it
        # update index
        #save_index(index, "%s.tmp" % INDEX_FILE)
        pass

    # unlock now that the action is complete, and delete the lock file
    if lock is not None:
        fcntl.lockf(lock.fileno(), fcntl.LOCK_UN)
        lock.close()
        os.unlink(LOCK_FILE)
