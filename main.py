#!/usr/bin/env python
#
# Create an Atom API to Yahoo! Mail.
#
# NOTE: Do we really always need to redirect to http://www.yttrium.ws? If
#       the problem is that the bounce-back hostname is configured w/ the
#       key, we can just create a key pointing to localhost.yttrium.ws.
#
# NOTE: Need to figure out how to expunge keys from git history if making
#       this open source. Or change keys and de-activate the old one.
#
# TODO:
#
#   - Generating request / response pairs using AJAX direct to the Cascade
#     endpoint is impossible without building an OAuth implemetnation that
#     can run entirely in JavaScript. We need to proxy through our web
#     service.
#
#       - Because of this, our request is not going to be exactly as sent
#         to the Cascade endpoint. If we want to get at this (do we?), we
#         will need to send it back from the web service. Maybe use MXHR
#         to get both request and response back using a single response.
#
#   - Use Django directly so that porting off of GAE is easier.

import os
import sys

# Add the lib/ directory to our path so that we don't have to keep all
# 3rd party libraries in the root of our application
sys.path.insert(
    0,
    os.path.join(os.path.abspath(os.path.dirname(__file__)), 'lib')
)

from google.appengine.ext import webapp
from google.appengine.ext.webapp import template
from google.appengine.ext.webapp.util import run_wsgi_app

import cgi
import logging
import oauth
import os
import pprint
import simplejson
import urllib
import urllib2

REQUEST_TOKEN_COOKIE_NAME = 'rt'
ACCESS_TOKEN_COOKIE_NAME = 'at'

###
# XXX: Make this a class annotation, as we're just using this to get to
#      'self' anyway. Does Python 2.5.x support class decorators?
def oauth_consumer(f):
    '''A decorator function for RequestHandler methods; populates the handler
       with instance variables _oaSig and _oaConsumer for working with OAuth.'''

    def wrapper(wr_self, *wr_args, **wr_kwargs):
        wr_self._oaConsumer = oauth.OAuthConsumer(
            u'dj0yJmk9eUtKYWFMSGdvS29NJmQ9WVdrOVkzcEtNR3QwTXpnbWNHbzlOakkxTXprd05qZzEmcz1jb25zdW1lcnNlY3JldCZ4PTE5',
            u'eb8c96f8afc7c0eb3ccbe4ebaeb09e2d4a1248f3'
        )
        wr_self._oaSig = oauth.OAuthSignatureMethod_HMAC_SHA1()

        return f(wr_self, *wr_args, **wr_kwargs)

    return wrapper

class oauth_token:
    '''A decorator class for RequestHandler methods; ensures that a valid
       OAuth access token cookie exists and stores it in self._oaToken. Can
       issue a 302 over to /oauth/init to retrieve one if not.
    
       - The 'redirect' keyword argument specifies a boolean indicating
         whether or not to 302 on failure. The default is a 403.'''

    def __init__(self, cookieName, redirect = False):
        self._cookieName = cookieName
        self._redirect = redirect

    def __call__(self, f):
        def wrapper(wr_self, *wr_args, **wr_kwargs):
            # If our cookie doesn't exist, react as specified by our caller
            if not self._cookieName in wr_self.request.cookies:
                logging.warning('No access token found in request')

                if self._redirect:
                    wr_self.redirect(
                        'http://www.yttrium.ws/auth/oauth/init?' + \
                        urllib.urlencode(
                            [(u'url', wr_self.request.url)]
                        )
                    )
                else:
                    wr_self.response.set_status(403)

                return

            # Parse bits from the cookie into an OAuth token object
            tokenDict = dict(
                cgi.parse_qsl(
                    urllib.unquote_plus(
                        wr_self.request.cookies[self._cookieName]
                    )
                )
            )

            if not u'oauth_token' in tokenDict:
                logging.warning('No "%s" key in the "%s" cookie.' % ('oauth_token', self._cookieName))
                wr_self.response.set_status(403)
                return

            if not u'oauth_token_secret' in tokenDict:
                logging.warning('No "%s" key in the "%s" cookie.' % ('oauth_token_secret', self._cookieName))
                wr_self.response.set_status(403)
                return

            # We've got a valid token; create it and invoke the function
            # being wrapped
            wr_self._oaToken = oauth.OAuthToken(
                tokenDict['oauth_token'],
                tokenDict['oauth_token_secret']
            )

            return f(wr_self, *wr_args, **wr_kwargs)

        return wrapper

class MainHandler(webapp.RequestHandler):
    '''Other stuff should go here.'''

    def get(self):
        self.response.headers[u'Content-Type'] = u'text/plain'
        self.response.out.write(u'Hello, world!')

class OAuthInitHandler(webapp.RequestHandler):
    '''Initialize the OAuth token acquisition process. Acquires a request
       token and asks for it to be validated by the user. Stashes away the
       secret for the request token in a cookie.'''

    @oauth_consumer
    def get(self):
        url = self.request.get('url')

        oaReq = oauth.OAuthRequest(
            http_method = u'GET',
            http_url = u'https://api.login.yahoo.com/oauth/v2/get_request_token',
            parameters = {
                u'oauth_nonce' : oauth.generate_nonce(),
                u'oauth_timestamp' : oauth.generate_timestamp(),
                u'oauth_consumer_key' : self._oaConsumer.key,
                u'oauth_version' : u'1.0',
                u'xoauth_lang_pref' : u'en-us',
                u'oauth_callback' : u'http://www.yttrium.ws/auth/oauth/finish?' +
                    urllib.urlencode([(u'url', url)]),
            }
        )

        oaReq.sign_request(self._oaSig, self._oaConsumer, None)
        logging.debug('Requet token request URL: "%s"', oaReq.to_url())

        reqTokenResp = urllib2.urlopen(oaReq.to_url())
        reqTokenRespContent = ''.join(reqTokenResp.readlines())

        if reqTokenResp.code != 200:
            logging.warning('Failed to get OAuth request token: "%s"', reqTokenRespContent)
            self.response.set_status(403)
            return

        logging.info('Got request token: ' + reqTokenRespContent)
        oaReqToken = oauth.OAuthToken.from_string(reqTokenRespContent)

        self.response.headers.add_header(
            u'Set-Cookie',
            u'%s=%s; domain=.yttrium.ws; path=/' % \
                (
                    REQUEST_TOKEN_COOKIE_NAME,
                    urllib.quote_plus(
                        u'oauth_token=%s&oauth_token_secret=%s' % \
                            (oaReqToken.key, oaReqToken.secret)
                    )
                )
        )
        self.response.headers.add_header(
            u'Set-Cookie',
            u'%s=; domain=.yttrium.ws; path=/; max-age=0' % (ACCESS_TOKEN_COOKIE_NAME)
        )
        self.redirect(
            u'https://api.login.yahoo.com/oauth/v2/request_auth?' +
                urllib.urlencode([(u'oauth_token', oaReqToken.key)])
        )
        return

class OAuthFinishHandler(webapp.RequestHandler):
    '''Complete the OAuth token acquisition process. Acquires a validated
       request token and exchanges it for an access token. Stashes away the
       secret for the access token in a cookie.'''

    @oauth_consumer
    @oauth_token(REQUEST_TOKEN_COOKIE_NAME)
    def get(self):
        url = self.request.get('url')

        self._oaToken.set_verifier(self.request.get('oauth_verifier'))

        # Make sure the token from our callback matches the one from
        # our cookie
        if self._oaToken.key != self.request.get('oauth_token'):
            logging.warning('Cookie and URL disagree about request token name')
            self.response.set_status(403)
            return

        oaReq = oauth.OAuthRequest(
            http_method = u'GET',
            http_url = u'https://api.login.yahoo.com/oauth/v2/get_token',
            parameters = {
                u'oauth_nonce' : oauth.generate_nonce(),
                u'oauth_timestamp' : oauth.generate_timestamp(),
                u'oauth_consumer_key' : self._oaConsumer.key,
                u'oauth_verifier' : self._oaToken.verifier,
                u'oauth_token' : self._oaToken.key,
                u'oauth_version' : u'1.0',
            }
        )

        oaReq.sign_request(self._oaSig, self._oaConsumer, self._oaToken)
        logging.debug('Access token request URL: "%s"', oaReq.to_url())

        accTokenResp = urllib2.urlopen(oaReq.to_url())
        accTokenRespContent = ''.join(accTokenResp.readlines())

        if accTokenResp.code != 200:
            logging.warning('Failed to get OAuth access token: "%s"', accTokenRespContent)
            self.response.set_status(403)
            return

        logging.info('Got access token: ' + accTokenRespContent)
        oaAccToken = oauth.OAuthToken.from_string(accTokenRespContent)
       
        self.response.headers.add_header(
            u'Set-Cookie',
            u'%s=; domain=.yttrium.ws; path=/; max-age=0' % (REQUEST_TOKEN_COOKIE_NAME)
        )
        self.response.headers.add_header(
            u'Set-Cookie',
            u'%s=%s; domain=.yttrium.ws; path=/' % \
                (
                    ACCESS_TOKEN_COOKIE_NAME,
                    urllib.quote_plus(
                        u'oauth_token=%s&oauth_token_secret=%s' % \
                            (oaAccToken.key, oaAccToken.secret)
                    )
                )
        )

        if url:
            self.redirect(url)
            return

        self.response.headers['Content-Type'] = 'text/plain'
        self.response.out.write('Access token: set')

class CascadeAPIHandler(webapp.RequestHandler):
    '''The Cascade API handler. Requires an authenticated session and
       does not redirect to get one.'''

    JSON_ENDPOINT_URL = u'http://mail.yahooapis.com/ws/mail/v1.1/jsonrpc'

    @oauth_consumer
    @oauth_token(ACCESS_TOKEN_COOKIE_NAME)
    def post(self):
        # Construct a signed URL. We can do this regardless of the POST
        # data provided to us by the client.
        oaReq = oauth.OAuthRequest(
            http_method = u'POST',
            http_url = self.JSON_ENDPOINT_URL,
            parameters = {
                u'oauth_nonce' : oauth.generate_nonce(),
                u'oauth_timestamp' : oauth.generate_timestamp(),
                u'oauth_consumer_key' : self._oaConsumer.key,
                u'oauth_token' : self._oaToken.key,
                u'oauth_version' : u'1.0'
            }
        )
        oaReq.sign_request(self._oaSig, self._oaConsumer, self._oaToken)
        headers = { 'Content-Type' : 'application/json' }
        headers.update(oaReq.to_header())

        try:
            cascadeReq = urllib2.Request(
                url = self.JSON_ENDPOINT_URL,
                data = self.request.body,
                headers = headers
            )
            cascadeResp = urllib2.urlopen(cascadeReq)
        except urllib2.HTTPError, e:
            logging.debug(pprint.pformat(e))
            cascadeResp = e

        # Collect and pretty-print JSON content, as it's easier to do so
        # here than in the browser.
        cascadeRespContent = ''.join(cascadeResp.readlines())
        cascadeRespContent = simplejson.dumps(simplejson.loads(cascadeRespContent), indent=4)

        rc = cascadeResp.code
        if rc > 900:
            rc = 500
        self.response.set_status(rc)
        self.response.out.write(cascadeRespContent)
        for hn, hv in cascadeResp.headers.items():
            self.response.headers.add_header(hn, hv)

class ExplorerHandler(webapp.RequestHandler):
    '''Explore the Cascade API.'''

    @oauth_consumer
    @oauth_token(ACCESS_TOKEN_COOKIE_NAME, True)
    def get(self):
        gtemplPath = os.path.join(
            os.path.dirname(__file__),
            'gtmpl',
            'explorer.gtmpl'
        )

        self.response.out.write(webapp.template.render(gtemplPath, {}))

def main():
    # Configure log levels
    logging.getLogger().setLevel(logging.DEBUG)

    app = webapp.WSGIApplication(
        [
            ('/auth/oauth/init', OAuthInitHandler),
            ('/auth/oauth/finish', OAuthFinishHandler),
            ('/api/cascade', CascadeAPIHandler),
            ('/explorer', ExplorerHandler),
            ('/', MainHandler)
        ],
        debug = True
    )

    run_wsgi_app(app)

if __name__ == '__main__':
  main()

# vim:tabstop=4 shiftwidth=4 expandtab
