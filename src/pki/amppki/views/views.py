from pyramid.view import view_config
from pyramid.renderers import get_renderer
from pyramid.httpexceptions import *
from Crypto.PublicKey import RSA
from Crypto.Util.asn1 import DerSequence
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5
from ssl import PEM_cert_to_DER_cert

@view_config(route_name="default", renderer="string")
def default(request):
    print "unknown request,", request.method, request.url
    print request.matchdict
    return


@view_config(route_name="cacert", renderer="string")
def cacert(request):
    # load the cacert from disk and send it to the user, it's public info
    print "this is a cacert"
    return open("cacert.pem").read()


@view_config(route_name="sign", renderer="string")
def sign(request):
    # TODO can we make sure this is done over SSL? don't accept this otherwise
    print "signing a cert"
    print request.POST
    print request.body
    # first check if we have already signed this one, and send it if so (maybe
    # the client went away before it was signed).
    csr = request.POST.keys()[0]

    # if there isn't one we've prepared earlier, check if we can auto-sign
    # this one right now (maybe it matches a known host config).

    # otherwise we add it to the queue and wait for a human to check it and
    # decide if it should be signed or not
    open("test.csr", "w").write(csr)
    return HTTPAccepted()


# TODO PKCS1_PSS vs PKCS1_v1_5
@view_config(route_name="cert", renderer="string")
def cert(request):
    # TODO can we make sure this is done over SSL? don't accept this otherwise
    # check that the named cert exists
    print request.matchdict
    certname = request.matchdict["certname"]
    certname = "cert.pem" # XXX
    print "got request for cert", certname

    print "headers:", request.headers
    print "environ:", request.environ
    print "body:", request.body

    # TODO sanitise certname so that they can't load arbitrary files

    # check that the certificate exists on disk
    try:
        certstr = open(certname).read()
    except IOError as e:
        # the user doesn't need to know what went wrong, just tell them that
        # they can't get whatever cert they asked for
        print "failed to open certificate:", e
        return HTTPForbidden()

    print certstr

    # Crypto.RSA.importKey() doesn't like X509 certificates, so we have to
    # extract the public key from the certificate before we can use it
    # http://stackoverflow.com/questions/12911373/
    der = PEM_cert_to_DER_cert(certstr)
    cert = DerSequence()
    cert.decode(der)
    tbsCertificate = DerSequence()
    tbsCertificate.decode(cert[0])
    subjectPublicKeyInfo = tbsCertificate[6]

    try:
        key = RSA.importKey(subjectPublicKeyInfo)
    except (ValueError, IndexError, TypeError) as e:
        print "importing key failed:", e
        return HTTPForbidden()

    if key is None:
        print "key is none"
        return HTTPForbidden()

    # read the signature and verify it against the public key in the cert
    # https://www.dlitz.net/software/pycrypto/api/2.6/Crypto.PublicKey.RSA._RSAobj-class.html#verify
    signature = (1234567890, None) # TODO get from body
    shahash = SHA256.new(certname)
    verifier = PKCS1_v1_5.new(key)
    if not verifier.verify(shahash, signature):
        print "verification failed"
        return HTTPForbidden()

    # return the signed cert
    print "all ok"
    return open(certname).read()
