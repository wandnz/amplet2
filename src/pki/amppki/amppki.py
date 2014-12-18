import os
import sys
import fcntl
import argparse
from time import strftime, gmtime, time
from OpenSSL import crypto
from Crypto.Hash import SHA256, MD5

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


def is_expired(item):
    if int(item["expires"][:-3]) < time():
        return True
    return False


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


def get_amplet_extension_list():
    # XXX should all the extensions be marked as critical?
    return [
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
    ]

def get_and_increment_serial(filename):
    # read the next serial out of the serial file
    serial = read_serial(filename)
    if serial is None:
        return None

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
            filename = "%s/%s" % (CSR_DIR, item)
            csrstr = open(filename).read()
            csr = crypto.load_certificate_request(crypto.FILETYPE_PEM, csrstr)
            result.append({
                "host": csr.get_subject().commonName,
                "filename": filename,
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


def list_pending(pending, hosts):
    for item in pending:
        if len(hosts) > 0 and item["host"] not in hosts:
            continue
        print "  %s %s %s\t%s" % (item["host"], get_padding(item["host"]),
                item["bits"], item["md5"])


def list_certificates(certs, hosts):
    merged = {}
    for item in certs:
        host = item["host"]
        if len(hosts) > 0 and host not in hosts:
            continue

        # only show expired certs if listing "all"
        if item["status"] == "E" or (
                item["status"] == "V" and is_expired(item)):
            status = "-"
            when = "expired %s" % strftime("%Y-%m-%d",
                    gmtime(int(item["expires"][:-3])))
        # only show valid signed certs if listing "all" or "signed"
        elif item["status"] == "V" and not is_expired(item):
            status = "+"
            when = "until %s" % strftime("%Y-%m-%d",
                    gmtime(int(item["expires"][:-3])))
        # only show revoked certs if listing "all"
        elif item["status"] == "R":
            status = "-"
            when = "revoked %s" % strftime("%Y-%m-%d",
                    gmtime(int(item["revoked"][:-3])))
        # otherwise don't display this item
        else:
            continue

        if host not in merged:
            merged[host] = []
        merged[host].append("%s %s %s 0x%s\t%s" % (status, host,
                    get_padding(host), item["serial"], when))

    # sort all the output based on hostname, so we ge a nice alphabetical list
    keys = merged.keys()
    keys.sort()
    for host in keys:
        for cert in merged[host]:
            print cert


def revoke_certificates(index, hosts):
    count = 0
    for cert in index:
        # Loop over the cert list rather than the host list so we can be
        # guaranteed to do it in a single pass. We can revoke on hostnames
        # or serial numbers (hex, must be prefixed with "0x")
        if cert["host"] in hosts or ("0x%s" % cert["serial"]) in hosts:
            # set the status to [R]evoked and the time that it happened
            cert["status"] = "R"
            cert["revoked"] = "%dZ" % (time() * 100)
            count += 1
    if count > 0:
        save_index(index, "%s.tmp" % INDEX_FILE)
    print "Revoked %d certificate(s)" % count


def generate_certs():
    pass


# TODO how much should be exposed? notbefore, notafter?
def sign_certificates(index, pending, hosts, force):
    notbefore = 0
    # XXX how long should they be valid for by default?
    notafter = int(time()) + (60 * 60 * 24 * 365 * 10)
    digest = "sha256"
    count = 0

    # get the CSR items that correspond to the hosts in the host list to sign
    tosign = []
    for host in hosts:
        matches = [item for item in pending if item["host"] == host]
        existing = [item for item in index
                    if item["host"] == host and
                       item["status"] == "V" and
                       not is_expired(item)]
        # by default don't sign anything where there are duplicate hostnames
        if len(matches) > 1 and force is False:
            print "Duplicate requests for %s, specify hash or --force" % host
        # make sure we don't already have a certificate for this host, unless
        # the user explicitly forces another one to be signed
        elif len(existing) > 0 and force is False:
            print "Cert already exists for %s, specify --force to sign" % host
        else:
            tosign += matches

    # load the CA cert and key that we need to sign certificates
    try:
        issuer_cert = crypto.load_certificate(crypto.FILETYPE_PEM,
                open(CACERT).read())
        issuer_key = crypto.load_privatekey(crypto.FILETYPE_PEM,
                open(CAKEY).read())
    except IOError as e:
        print "Couldn't load CA cert and private key: %s" % e
        return
    except crypto.Error as e:
        print "Invalid CA cert or key: %s" % e
        return

    # sign all the CSRs that passed the filter
    for item in tosign:
        try:
            request = crypto.load_certificate_request(crypto.FILETYPE_PEM,
                open(item["filename"]).read())
        except IOError as e:
            print "Couldn't find CSR for %s: %s" % (item["host"], e)
            continue
        except crypto.Error as e:
            print "Invalid CSR for %s: %s" % (item["host"], e)
            continue

        cert = crypto.X509()
        cert.gmtime_adj_notBefore(notbefore)
        cert.gmtime_adj_notAfter(notafter)
        cert.set_issuer(issuer_cert.get_subject())
        cert.set_subject(request.get_subject())
        cert.set_pubkey(request.get_pubkey())
        cert.add_extensions(get_amplet_extension_list())

        serial = get_and_increment_serial(SERIAL_FILE)

        if serial is None:
            print "Can't get serial number, aborting"
            # it's possible we've already signed some certificates, and so
            # should probably return them (though this is not a good state)!
            # TODO what should we do here?
            break

        cert.set_serial_number(serial)
        cert.sign(issuer_key, digest)

        # write the cert out to a file
        try:
            open("%s/%s.%s.pem" % (CERT_DIR,
                        request.get_subject().commonName, serial), "w").write(
                    crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        except IOError as e:
            # TODO what should we do here?
            print "Failed to write certificate %s: %s" % (host, e)
            break

        index.append({
            "status": "V",
            "expires": "%s00Z" % notafter,
            "revoked": "",
            "serial": "%02X" % cert.get_serial_number(),
            "subject": "/CN=%s/O=%s" % (cert.get_subject().commonName,
                cert.get_subject().organizationName),
        })
        count += 1

    # TODO delete csr
    if count > 0:
        save_index(index, "%s.tmp" % INDEX_FILE)
    print "Signed %d certificate(s)" % count


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
            "subject": parts[5].strip(),
            # XXX extract hostname properly?
            "host": parts[5].strip().split("/")[1][3:]
        })
    return index


if __name__ == '__main__':
    if len(sys.argv) < 2:
        usage(os.path.basename(sys.argv[0]))
        sys.exit(0)

    lock = None

    parser = argparse.ArgumentParser()
    parser.add_argument("action",
            choices=["generate", "list", "revoke", "sign"])
    parser.add_argument("-a", "--all", action="store_true")
    parser.add_argument("-f", "--force", action="store_true")
    parser.add_argument("hosts", nargs="*")

    args = parser.parse_args()

    if len(args.hosts) > 0 and args.all:
        print "Conflicting arguments: both --all and a host list are used"
        sys.exit(2)

    # lock the whole CA dir for any actions that will modify it
    if args.action in ["sign", "revoke"]:
        try:
            lock = open(LOCK_FILE, "w")
            fcntl.lockf(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except IOError as e:
            print "Failed to lock %s: %s" % (LOCK_FILE, e)
            sys.exit(1)

    pending = load_csr()
    index = load_index(INDEX_FILE)

    if args.action == "list":
        if args.all:
            # show all certificates (valid, expired, revoked)
            list_certificates(index, args.hosts)
        # list outstanding requests
        list_pending(pending, args.hosts)

    elif args.action == "sign":
        if args.all:
            # sign all outstanding requests
            sign_certificates(index, pending, [x["host"] for x in pending],
                    args.force)
        else:
            # sign only the listed requests
            sign_certificates(index, pending, args.hosts, args.force)

    elif args.action == "revoke":
        # revoke only the listed certificates
        revoke_certificates(index, args.hosts)

    # unlock now that the action is complete, and delete the lock file
    if lock is not None:
        fcntl.lockf(lock.fileno(), fcntl.LOCK_UN)
        lock.close()
        os.unlink(LOCK_FILE)
