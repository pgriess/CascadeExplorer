#!/usr/bin/env python
#
# Create an Atom API to Yahoo! Mail.
#
# NOTE: Do we really always need to redirect to http://www.yttrium.ws? If
#       the problem is that the bounce-back hostname is configured w/ the
#       key, we can just create a key pointing to localhost.yttrium.ws.
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
#
#   - Render HTML responses from Cascade. These occur when a 999 error comes
#     back and it'd be nice to show this graphically.
#
#   - Add atom:generator element to indicate software name and version # for
#     debugging.

from google.appengine.ext import webapp
from google.appengine.ext.webapp import template
from google.appengine.ext.webapp.util import run_wsgi_app
from google.appengine.api.urlfetch import DownloadError

import cascade
import cgi
import elementtree.ElementTree as ET
import logging
import oauth
import os
import pprint
import simplejson
import time
import urllib
import urllib2
from yttrium_settings import OAUTH_CONSUMER_KEY, OAUTH_CONSUMER_SECRET
from StringIO import StringIO

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
            OAUTH_CONSUMER_KEY,
            OAUTH_CONSUMER_SECRET
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
                        '/auth/oauth/init?' + \
                        urllib.urlencode(
                            [(u'url', wr_self.request.url)]
                        )
                    )
                else:
                    wr_self.response.set_status(403)

                return

            wr_self._oaToken = cascade.oauth_token_from_query_string(
                wr_self.request.cookies[self._cookieName]
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
        try:
            tok, url = cascade.oauth_get_request_token(
                self._oaConsumer,
                'http://www.yttrium.ws/auth/oauth/finish?' +
                    urllib.urlencode([(u'url', self.request.get('url'))])
            )
        except cascade.CascadeError:
            self.response.set_status(403)
            return

        self.response.headers.add_header(
            u'Set-Cookie',
            u'%s=%s; domain=.yttrium.ws; path=/' % (
                REQUEST_TOKEN_COOKIE_NAME,
                cascade.oauth_token_to_query_string(tok)
            )
        )
        self.response.headers.add_header(
            u'Set-Cookie',
            u'%s=; domain=.yttrium.ws; path=/; max-age=0' % (
                ACCESS_TOKEN_COOKIE_NAME
            )
        )
        self.redirect(url)


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

        try:
            tok = cascade.oauth_get_access_token(
                self._oaConsumer,
                self._oaToken
            )
        except CascadeError:
            self.response.set_status(403)
            return

        self.response.headers.add_header(
            u'Set-Cookie',
            u'%s=; domain=.yttrium.ws; path=/; max-age=0' % (
                REQUEST_TOKEN_COOKIE_NAME
            )
        )
        self.response.headers.add_header(
            u'Set-Cookie',
            u'%s=%s; domain=.yttrium.ws; path=/' % (
                ACCESS_TOKEN_COOKIE_NAME,
                cascade.oauth_token_to_query_string(tok)
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

    @oauth_consumer
    @oauth_token(ACCESS_TOKEN_COOKIE_NAME)
    def post(self):

        # Loop around Cascade call to allow for retrying if we need to
        # refresh our OAuth access token.
        cascadeResp = None
        oaTokStr = self._oaToken.to_string()
        for attemptNo in range(0, 2):
            # We do our own Cascade request / response handling here, as the
            # API doesn't provide access to the underlying HTTP objects, which
            # we want to expose to our callers.
            oaReq = oauth.OAuthRequest(
                http_method = u'POST',
                http_url = cascade.JSON11_ENDPOINT_URL,
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
            url = oaReq.to_url();

            try:
                cascadeReq = urllib2.Request(
                    url = url,
                    data = self.request.body,
                    headers = headers
                )
                cascadeResp = urllib2.urlopen(cascadeReq)

                # We've gotten a 200 response, we're done
                break
            except urllib2.HTTPError, e:
                # Only attempt access token refresh if we haven't already done
                # so, and think that it might work.
                #
                # XXX: Note that there appears to be some bug in the Yahoo!
                #      OAuth implementation that causes really stale tokens to
                #      be rejected with 999 rather than 401.
                if attemptNo > 0 or (e.code != 401 and e.code != 999):
                    cascadeResp = e
                    break

                self._oaToken = cascade.oauth_refresh_access_token(
                    self._oaConsumer,
                    self._oaToken
                )
            except DownloadError, e:
                # We see this if we're getting throttled, wherein Yahoo!  will
                # return an HTTP status code 999 and leave the TCP connection
                # open, timing out the request.
                #
                # XXX: Because of the stale OAuth token bug mentioned above, we
                #      consider this a situation where we should refresh our
                #      OAuth token.
                if attemptNo > 0:
                    raise e

                self._oaToken = cascade.oauth_refresh_access_token(
                    self._oaConsumer,
                    self._oaToken
                )
            finally:
                if cascadeResp:
                    cascadeRespContent = ''.join(cascadeResp.readlines())
                    cascadeResp.close()

        # If we succeeded and we ended up refreshing the access token, update the
        # client with the new value
        if cascadeResp.code == 200 and \
           oaTokStr != self._oaToken.to_string():
            self.response.headers.add_header(
                u'Set-Cookie',
                u'%s=%s; domain=.yttrium.ws; path=/' % (
                    ACCESS_TOKEN_COOKIE_NAME,
                    cascade.oauth_token_to_query_string(self._oaToken)
                )
            )

        # Return some types of content pretty-printed, so that we don't have
        # to deal with doing this in the browser in JavaScript.
        if 'Content-Type' in cascadeResp.headers and \
           cascadeResp.headers['Content-Type'].startswith('application/json'):
            cascadeRespContent = simplejson.dumps(simplejson.loads(cascadeRespContent), indent=4)

        rc = cascadeResp.code
        if rc > 900:
            cascadeResp.headers['X-Yttrium-HTTP-Status'] = rc
            rc = 500

        self.response.set_status(rc)

        for hn, hv in cascadeResp.headers.items():
            self.response.headers[hn] = hv

        self.response.out.write(cascadeRespContent)

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

class AtomFoldersHandler(webapp.RequestHandler):
    '''Generate Atom content for a Yahoo! Mail account.'''
    
    @oauth_consumer
    @oauth_token(ACCESS_TOKEN_COOKIE_NAME, True)
    def get(self):
        self.response.headers[u'Content-Type'] = u'application/atom+xml'

        feed = ET.Element('feed')
        feed.set('xmlns', 'http://www.w3.org/2005/Atom')
        ET.SubElement(feed, 'title').text = 'Folder list'
        ET.SubElement(feed, 'updated').text = time.strftime('%Y-%m-%d')
        ET.SubElement(feed, 'id').text = \
            'yttrium://%s/folders' % (urllib.quote(self._oaToken.key, ''))

        self.response.out.write(ET.tostring(feed, u'UTF-8'))

def main():
    # Configure log levels
    logging.getLogger().setLevel(logging.DEBUG)

    app = webapp.WSGIApplication(
        [
            ('/auth/oauth/init', OAuthInitHandler),
            ('/auth/oauth/finish', OAuthFinishHandler),
            ('/api/cascade', CascadeAPIHandler),
            ('/explorer', ExplorerHandler),
            ('/atom/folders', AtomFoldersHandler),
            ('/', MainHandler)
        ],
        debug = True
    )

    run_wsgi_app(app)

if __name__ == '__main__':
  main()

# vim:tabstop=4 shiftwidth=4 expandtab
