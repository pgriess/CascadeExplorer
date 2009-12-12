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

from google.appengine.api.urlfetch import fetch 
from google.appengine.ext import webapp
from google.appengine.ext.webapp.util import run_wsgi_app

import cgi
import logging
import oauth
import pprint
import simplejson
import urllib

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
        reqTokenResp = fetch(oaReq.to_url())

        if reqTokenResp.status_code != 200:
            logging.warning('Failed to get OAuth request token: "%s"', reqTokenResp.content)
            self.response.set_status(403)
            return

        logging.info('Got request token: ' + reqTokenResp.content)
        oaReqToken = oauth.OAuthToken.from_string(reqTokenResp.content)

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
        if not u'oauth_token' in reqTokenDict:
            logging.warning('No "%s" key in the "%s" cookie.' % ('oauth_token', REQUEST_TOKEN_COOKIE_NAME))
            self.response.set_status(403)
            return

        logging.debug('reqTokenDict: ' + pprint.pformat(reqTokenDict))

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
        logging.debug('Access token request URL: %s', oaReq.to_url())
        accTokenResp = fetch(oaReq.to_url())

        if accTokenResp.status_code != 200:
            logging.warning('Failed to get OAuth access token: "%s"', accTokenResp.content)
            self.response.set_status(403)
            return

        logging.info('Got access token: ' + accTokenResp.content)
        oaAccToken = oauth.OAuthToken.from_string(accTokenResp.content)
       
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

class APIHandler(webapp.RequestHandler):
    '''The meat of the API goes here. Bounces through the OAuth token
       acquisition dance if no credentials are found.'''

    def get(self):
        if not ACCESS_TOKEN_COOKIE_NAME in self.request.cookies:
            self.redirect(
                'http://www.yttrium.ws/auth/oauth/init?' + \
                urllib.urlencode(
                    [(u'url', self.request.url)]
                )
            )
            return

        self.response.headers['Content-Type'] = 'text/plain'
        self.response.out.write('Access token: ok')

class ExplorerHandler(webapp.RequestHandler):
    '''Explore the Cascade API.'''

    JSON_ENDPOINT_URL = 'http://mail.yahooapis.com/ws/mail/v1.1/jsonrpc'

    def get(self):
        if not ACCESS_TOKEN_COOKIE_NAME in self.request.cookies:
            self.redirect(
                'http://www.yttrium.ws/auth/oauth/init?' + \
                urllib.urlencode(
                    [(u'url', self.request.url)]
                )
            )
            return

        self.response.headers['Content-Type'] = 'text/plain'
        self.response.out.write('Access token: ok')

def main():
    app = webapp.WSGIApplication(
        [
            ('/auth/oauth/init', OAuthInitHandler),
            ('/auth/oauth/finish', OAuthFinishHandler),
            ('/api', APIHandler),
            ('/explorer', ExplorerHandler),
            ('/', MainHandler)
        ],
        debug = True
    )

    run_wsgi_app(app)

if __name__ == '__main__':
  main()
