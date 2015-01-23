from pyramid.view import view_config
from pyramid.renderers import get_renderer
from pyramid.httpexceptions import *
from Crypto.PublicKey import RSA
from Crypto.Util.asn1 import DerSequence
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5
from ssl import PEM_cert_to_DER_cert
from OpenSSL import crypto
from base64 import urlsafe_b64decode
from os.path import isfile, basename
from glob import glob
from amppki.config import CA_DIR, CERT_DIR, CSR_DIR
from pyasn1.type import univ
from pyasn1.codec.der import decoder
from pyasn1.error import SubstrateUnderrunError, PyAsn1Error

@view_config(route_name="default", renderer="string")
def default(request):
    print "unknown request,", request.method, request.url
    print request.matchdict
    return


# XXX merge this with /cert and do different things on POST vs GET?
@view_config(route_name="sign", renderer="string")
def sign(request):
    # TODO can we make sure this is done over SSL? don't accept this otherwise
    print "accepting cert signing request"

    if len(request.body) <= 0:
        print "no csr in message"
        #return HTTPBadRequest()
        return Response(status_code=400)

    # this is already url decoded for us, so use it as is
    csr = request.body

    try:
        # make sure this is a valid request before we do anything with it
        crypto.load_certificate_request(crypto.FILETYPE_PEM, csr)
    except crypto.Error as e:
        print "invalid csr"
        return Response(status_code=400)

    shahash = SHA256.new(csr).hexdigest()
    print shahash

    if not isfile(shahash):
        # if there isn't one we've prepared earlier, check if we can auto-sign
        # this one right now (maybe it matches a known host config).
        # otherwise we add it to the queue and wait for a human to check it and
        # decide if it should be signed or not
        print "saving csr"
        # XXX are CSRs being deleted once dealt with? could this cause a race?
        try:
            open("%s/%s" % (CSR_DIR, shahash), "w").write(csr)
        except IOError:
            # XXX is this giving away any useful information?
            print "error saving csr"
            return Response(status_code=500)

    #return HTTPAccepted()
    return Response(status_code=202)


def is_der_key(asn1):
    try:
        decoded = decoder.decode(asn1)
        index = decoded[0]
    except (SubstrateUnderrunError, PyAsn1Error) as e:
        return False

    # look for a sequence tag with the RSA key object inside it
    if index.isSameTypeWith(univ.Sequence()):
        # if it is another sequence, look deeper
        if index[0].isSameTypeWith(univ.Sequence()):
            return is_der_key
        # if it has the right object tag, we've probably found it
        if index[0].isSameTypeWith(univ.ObjectIdentifier()):
            if index[0].asTuple() == (1,2,840,113549,1,1,1):
                return True
    return False


@view_config(route_name="cert", renderer="string")
def cert(request):
    # TODO can we make sure this is done over SSL? don't accept this otherwise
    # check that the named cert exists
    print request.matchdict

    # XXX how much validation of the ampname do we need? Coming through the
    # pyramid route it already can't contain slashes, which basename (perhaps
    # redundantly) confirms. Also, to get sent a file, the file will have to
    # look like a certificate containing the public key that will verify the
    # signature.
    ampname = basename(request.matchdict["ampname"])
    try:
        signature = urlsafe_b64decode(str(request.matchdict["signature"]))
    except TypeError as e:
        # in this case we'll give the user a slightly more useful response
        # code - they messed up their signature, nothing of ours is exposed
        print "failed to base64 decode, invalid data"
        return Response(status_code=400)

    print "got request for cert", ampname

    # check that the certificate exists on disk
    try:
        # TODO do we just want to check the newest one?
        # TODO can we accidentally expose other files by doing it this way?
        # look at the matching certificate with the latest serial number
        matches = sorted(glob("%s/%s.*.pem" % (CERT_DIR, ampname)))
        certstr = open("%s" % matches[-1]).read()
    except (IOError, IndexError) as e:
        # the user doesn't need to know what went wrong, just tell them that
        # they can't get whatever cert they asked for
        print "failed to open certificate:", e
        #return HTTPForbidden()
        return Response(status_code=403)

    # Crypto.RSA.importKey() doesn't like X509 certificates, so we have to
    # extract the public key from the certificate before we can use it
    # http://stackoverflow.com/questions/12911373/
    der = PEM_cert_to_DER_cert(certstr)
    cert = DerSequence()
    cert.decode(der)
    tbsCertificate = DerSequence()
    tbsCertificate.decode(cert[0])

    # we have to look through the certificate to find the right part that
    # corresponds to the key - it can move around depending on how many other
    # attributes there are
    try:
        key = None
        for item in tbsCertificate:
            if is_der_key(item):
                key = RSA.importKey(item)
                break
    except (ValueError, IndexError, TypeError) as e:
        print "importing key failed:", e
        #return HTTPForbidden()
        return Response(status_code=403)

    if key is None:
        print "key is none"
        #return HTTPForbidden()
        return Response(status_code=403)

    print key.exportKey()

    # verify the signature using the public key in the cert
    # https://www.dlitz.net/software/pycrypto/api/2.6/Crypto.PublicKey.RSA._RSAobj-class.html#verify
    shahash = SHA256.new(ampname)
    print shahash.hexdigest()
    verifier = PKCS1_v1_5.new(key)
    if not verifier.verify(shahash, signature):
        print "verification failed"
        #return HTTPForbidden()
        return Response(status_code=403)

    # return the signed cert
    print "all ok"
    return certstr
