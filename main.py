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
#   - Replace lame explicit checks for cookies / auth with decorators.
#     We probably need 2 varieties: one redirecting, one not.
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

class MainHandler(webapp.RequestHandler):
    '''Other stuff should go here.'''

    def get(self):
        self.response.headers[u'Content-Type'] = u'text/plain'
        self.response.out.write(u'Hello, world!')

class OAuthHandler(webapp.RequestHandler):
    '''Superclass for OAuth-related handlers.'''

    _oaConsumer = oauth.OAuthConsumer(
        u'dj0yJmk9eTVoMnNFbHBlbVQ0JmQ9WVdrOVkzcEtNR3QwTXpnbWNHbzlOakkxTXprd05qZzEmcz1jb25zdW1lcnNlY3JldCZ4PWQ1',
        u'4dc5bf318e068d8d518676d2eb8b1d6376bf4fb3'
    )
    _oaSig = oauth.OAuthSignatureMethod_HMAC_SHA1()

class OAuthInitHandler(OAuthHandler):
    '''Initialize the OAuth token acquisition process. Acquires a request
       token and asks for it to be validated by the user. Stashes away the
       secret for the request token in a cookie.'''

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
        reqTokenRespContent = '\n'.join(reqTokenResp.readlines())

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
            u'%s=; domain=.yttrium.ws; path=/' % (ACCESS_TOKEN_COOKIE_NAME)
        )
        self.redirect(
            u'https://api.login.yahoo.com/oauth/v2/request_auth?' +
                urllib.urlencode([(u'oauth_token', oaReqToken.key)])
        )
        return

class OAuthFinishHandler(OAuthHandler):
    '''Complete the OAuth token acquisition process. Acquires a validated
       request token and exchanges it for an access token. Stashes away the
       secret for the access token in a cookie.'''

    def get(self):
        url = self.request.get('url')

        if not REQUEST_TOKEN_COOKIE_NAME in self.request.cookies:
            logging.warning('No "%s" cookie present' % (REQUEST_TOKEN_COOKIE_NAME))
            self.response.set_status(403)
            return

        reqTokenDict = dict(cgi.parse_qsl(urllib.unquote_plus(self.request.cookies[REQUEST_TOKEN_COOKIE_NAME])))
        logging.debug('reqTokenDict: ' + pprint.pformat(reqTokenDict))

        if not u'oauth_token' in reqTokenDict:
            logging.warning('No "%s" key in the "%s" cookie.' % ('oauth_token', REQUEST_TOKEN_COOKIE_NAME))
            self.response.set_status(403)
            return

        if reqTokenDict[u'oauth_token'] != self.request.get('oauth_token'):
            logging.warning('Cookie and URL disagree about request token name')
            self.response.set_status(403)
            return

        if not u'oauth_token_secret' in reqTokenDict:
            logging.warning('No "%s" key in the "%s" cookie.' % ('oauth_token_secret', REQUEST_TOKEN_COOKIE_NAME))
            self.response.set_status(403)
            return

        oaReqToken = oauth.OAuthToken(
            self.request.get('oauth_token'),
            reqTokenDict[u'oauth_token_secret']
        )
        oaReqToken.set_verifier(self.request.get('oauth_verifier'))
        oaReq = oauth.OAuthRequest(
            http_method = u'GET',
            http_url = u'https://api.login.yahoo.com/oauth/v2/get_token',
            parameters = {
                u'oauth_nonce' : oauth.generate_nonce(),
                u'oauth_timestamp' : oauth.generate_timestamp(),
                u'oauth_consumer_key' : self._oaConsumer.key,
                u'oauth_verifier' : oaReqToken.verifier,
                u'oauth_token' : oaReqToken.key,
                u'oauth_version' : u'1.0',
            }
        )

        oaReq.sign_request(self._oaSig, self._oaConsumer, oaReqToken)
        logging.debug('Access token request URL: "%s"', oaReq.to_url())

        accTokenResp = urllib2.urlopen(oaReq.to_url())
        accTokenRespContent = '\n'.join(accTokenResp.readlines())

        if accTokenResp.code != 200:
            logging.warning('Failed to get OAuth access token: "%s"', accTokenRespContent)
            self.response.set_status(403)
            return

        logging.info('Got access token: ' + accTokenRespContent)
        oaAccToken = oauth.OAuthToken.from_string(accTokenRespContent)
       
        self.response.headers.add_header(
            u'Set-Cookie',
            u'%s=; domain=.yttrium.ws; path=/' % (REQUEST_TOKEN_COOKIE_NAME)
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

class CascadeAPIHandler(OAuthHandler):
    '''The Cascade API handler. Requires an authenticated session and
       does not redirect to get one.'''

    JSON_ENDPOINT_URL = u'http://mail.yahooapis.com/ws/mail/v1.1/jsonrpc'

    def post(self):
        if not ACCESS_TOKEN_COOKIE_NAME in self.request.cookies:
            logging.warning('No access token found in request')
            self.response.set_status(403)
            return

        # Construct a signed URL. We can do this regardless of the POST
        # data provided to us by the client.
        accTokenDict = dict(cgi.parse_qsl(urllib.unquote_plus(self.request.cookies[ACCESS_TOKEN_COOKIE_NAME])))
        logging.debug('accTokenDict: ' + pprint.pformat(accTokenDict))

        if not u'oauth_token' in accTokenDict:
            logging.warning('No "%s" key in the "%s" cookie.' % ('oauth_token', ACCESS_TOKEN_COOKIE_NAME))
            self.response.set_status(403)
            return

        if not u'oauth_token_secret' in accTokenDict:
            logging.warning('No "%s" key in the "%s" cookie.' % ('oauth_token_secret', ACCESS_TOKEN_COOKIE_NAME))
            self.response.set_status(403)
            return

        oaAccToken = oauth.OAuthToken(
            accTokenDict['oauth_token'],
            accTokenDict['oauth_token_secret']
        )
        oaReq = oauth.OAuthRequest(
            http_method = u'POST',
            http_url = self.JSON_ENDPOINT_URL,
            parameters = {
                u'oauth_nonce' : oauth.generate_nonce(),
                u'oauth_timestamp' : oauth.generate_timestamp(),
                u'oauth_consumer_key' : self._oaConsumer.key,
                u'oauth_token' : oaAccToken.key,
                u'oauth_version' : u'1.0'
            }
        )
        oaReq.sign_request(self._oaSig, self._oaConsumer, oaAccToken)
        logging.debug('Cascade JSON request URL: "%s"', oaReq.to_url())

        try:
            cascadeReq = urllib2.Request(
                url = oaReq.to_url(),
                data = self.request.body,
                headers = { 'Content-Type' : 'application/json' }
            )
            cascadeResp = urllib2.urlopen(cascadeReq)
        except urllib2.HTTPError, e:
            logging.debug(pprint.pformat(e))
            cascadeResp = e

        cascadeRespContent = '\n'.join(cascadeResp.readlines())

        self.response.set_status(cascadeResp.code)
        self.response.out.write(cascadeRespContent)
        for hn, hv in cascadeResp.headers.items():
            self.response.headers.add_header(hn, hv)

class ExplorerHandler(webapp.RequestHandler):
    '''Explore the Cascade API.'''

    def get(self):
        if not ACCESS_TOKEN_COOKIE_NAME in self.request.cookies:
            self.redirect(
                'http://www.yttrium.ws/auth/oauth/init?' + \
                urllib.urlencode(
                    [(u'url', self.request.url)]
                )
            )
            return

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
