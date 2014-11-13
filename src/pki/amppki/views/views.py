from pyramid.view import view_config
from pyramid.renderers import get_renderer
from pyramid.httpexceptions import *


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
    print "signing a cert"
    print request.POST
    print request.body
    # first check if we have already signed this one, and send it if so (maybe
    # the client went away before it was signed).

    # if there isn't one we've prepared earlier, check if we can auto-sign
    # this one right now (maybe it matches a known host config).

    # otherwise we add it to the queue and wait for a human to check it and
    # decide if it should be signed or not
    return HTTPAccepted()
