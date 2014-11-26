from pyramid.view import view_config
from pyramid.renderers import get_renderer
from pyramid.httpexceptions import *
from Crypto.PublicKey import RSA
from Crypto.Util.asn1 import DerSequence
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5
from ssl import PEM_cert_to_DER_cert
from base64 import urlsafe_b64decode
from os.path import isfile

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

    if len(request.POST.keys()) != 1:
        print "no csr in message"
        #return HTTPBadRequest()
        return Response(status_code=400)

    # this is already url decoded for us, so use it as is
    csr = request.POST.keys()[0]

    # first check if we have already signed this one, and send it if so (maybe
    # the client went away before it was signed).
    # TODO verify this is actually a CSR
    print csr
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
            open(shahash, "w").write(csr)
        except IOError:
            # XXX is this giving away any useful information?
            print "error saving csr"
            return Response(status_code=500)

    #return HTTPAccepted()
    return Response(status_code=202)


@view_config(route_name="cert", renderer="string")
def cert(request):
    # TODO can we make sure this is done over SSL? don't accept this otherwise
    # check that the named cert exists
    print request.matchdict
    ampname = request.matchdict["ampname"]
    certname = "%s.cert" % ampname
    signature = (urlsafe_b64decode(str(request.matchdict["signature"])), None)
    print "got request for cert", certname

    open("test.sig", "w").write(signature[0])

    # TODO sanitise certname so that they can't load arbitrary files

    # check that the certificate exists on disk
    try:
        certstr = open(certname).read()
    except IOError as e:
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
    subjectPublicKeyInfo = tbsCertificate[6]

    try:
        key = RSA.importKey(subjectPublicKeyInfo)
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
    if not verifier.verify(shahash, signature[0]):
        print "verification failed"
        #return HTTPForbidden()
        return Response(status_code=403)

    # return the signed cert
    print "all ok"
    return open(certname).read()
