"""
Nigel Fernandes
HCDE 310
12/12/2019

   This AppEngine application uses the Spotify API to allow users to log in to their Spotify accounts,
   see their top artists, and gets personalized recommendations on less-popular artists that match their
   listening history. The webpage allows users to follow suggested artists directly from the webpage and
   click a link to view their Spotify profile and sample their music.

"""

from secrets import CLIENT_ID, CLIENT_SECRET
GRANT_TYPE = 'authorization_code'

import webapp2, urllib2, os, urllib, json, jinja2, logging, sys, time
import base64, Cookie, hashlib, hmac, email
from google.appengine.ext import db
from google.appengine.api import urlfetch

JINJA_ENVIRONMENT = jinja2.Environment(loader=jinja2.FileSystemLoader(os.path.dirname(__file__)),
    extensions=['jinja2.ext.autoescape'],
    autoescape=True)

### this is our user database model. We will use it to store the access_token
class User(db.Model):
    uid = db.StringProperty(required=True)
    displayname = db.StringProperty(required=False)
    img = db.StringProperty(required=False)   
    access_token = db.StringProperty(required=True)
    refresh_token = db.StringProperty(required=False)
    profile_url=db.StringProperty(required=False)
    api_url=db.StringProperty(required=False) 

### helper functions 

### We have some cookie functions here. This lets us be careful 
### to make sure that a  malicious user can't spoof your user ID in
### their cookie and then use our site to do things on your behalf
def set_cookie(response, name, value, domain=None, path="/", expires=None):
    """Generates and signs a cookie for the give name/value"""
    timestamp = str(int(time.time()))
    value = base64.b64encode(value)
    signature = cookie_signature(value, timestamp)
    cookie = Cookie.BaseCookie()
    cookie[name] = "|".join([value, timestamp, signature])
    cookie[name]["path"] = path
    if domain: cookie[name]["domain"] = domain
    if expires:
        cookie[name]["expires"] = email.utils.formatdate(
            expires, localtime=False, usegmt=True)
    response.headers.add("Set-Cookie", cookie.output()[12:])


def parse_cookie(value):
    """Parses and verifies a cookie value from set_cookie"""
    if not value: return None
    parts = value.split("|")
    if len(parts) != 3: return None
    if cookie_signature(parts[0], parts[1]) != parts[2]:
        logging.warning("Invalid cookie signature %r", value)
        return None
    timestamp = int(parts[1])
    if timestamp < time.time() - 30 * 86400:
        logging.warning("Expired cookie %r", value)
        return None
    try:
        return base64.b64decode(parts[0]).strip()
    except:
        return None

def cookie_signature(*parts):
    chash = hmac.new(CLIENT_SECRET, digestmod=hashlib.sha1)
    for part in parts: chash.update(part)
    return chash.hexdigest()
    
    
### this adds a header with the user's access_token to Spotify requests
def spotifyurlfetch(url,access_token,params=None):
    headers = {'Authorization': 'Bearer '+access_token}
    response = urlfetch.fetch(url,method=urlfetch.GET, payload=params, headers=headers)
    return response.content

### handlers

### this handler will be our Base Handler -- it checks for the current user. 
### creating this class allows our other classes to inherit from it
### so they all "know about" the user
class BaseHandler(webapp2.RequestHandler):
    # @property followed by def current_user makes so that if x is an instance
    # of BaseHandler, x.current_user can be referred to, which has the effect of
    # invoking x.current_user()
    @property
    def current_user(self):
        """Returns the logged in Spotify user, or None if unconnected."""
        if not hasattr(self, "_current_user"):
            self._current_user = None
            # find the user_id in a cookie
            user_id = parse_cookie(self.request.cookies.get("spotify_user"))
            if user_id:
                self._current_user = User.get_by_key_name(user_id)
        return self._current_user

### this will handle our home page
class HomeHandler(BaseHandler):
    def get(self):
        template = JINJA_ENVIRONMENT.get_template('oauth.html')
        # check if they are logged in
        user = self.current_user
        tvals = {'current_user':user}
        
        if user != None:
            # info based on user's 3 top artists
            # Call 1: get user's top artists, Call 2: get A1 Related Artists,
            # Call 3: get A2 Related Artists, Call 4: get A3 Related Artists
            url = 'https://api.spotify.com/v1/me/top/artists'
            response = json.loads(spotifyurlfetch(url, user.access_token))
            logging.info(response)
            tvals["artists"] = response["items"]
            artist1id = response["items"][0]["id"]
            relartsURL = "https://api.spotify.com/v1/artists/%s/related-artists" % artist1id
            relartsResponse = json.loads(spotifyurlfetch(relartsURL, user.access_token))
            tvals["relatedArtists"] = relartsResponse["artists"]
        self.response.write(template.render(tvals))

        '''
            #start of multi artist  
            RELATED_ARTISTS = []
            url = 'https://api.spotify.com/v1/me/top/artists'
            response = json.loads(spotifyurlfetch(url, user.access_token))
            logging.info(response)
            tvals["artists"] = response["items"]

            #first top artist
            artist1id = response["items"][0]["id"]
            relartsURL1 = "https://api.spotify.com/v1/artists/%s/related-artists" % artist1id
            relartsResponse1 = json.loads(spotifyurlfetch(relartsURL1, user.access_token))
            RELATED_ARTISTS.append(relartsResponse1["artists"])

            #second top artist
            artist2id = response["items"][1]["id"]
            relartsURL2 = "https://api.spotify.com/v1/artists/%s/related-artists" % artist2id
            relartsResponse2 = json.loads(spotifyurlfetch(relartsURL2, user.access_token))
            RELATED_ARTISTS.append(relartsResponse2["artists"])        
        
            #third top artist
            artist3id = response["items"][2]["id"]
            relartsURL3 = "https://api.spotify.com/v1/artists/%s/related-artists" % artist3id
            relartsResponse3 = json.loads(spotifyurlfetch(relartsURL3, user.access_token))
            RELATED_ARTISTS.append(relartsResponse3["artists"])
        
            #tvals["relatedArtists"] = RELATED_ARTISTS
            #end of multi artist
            '''

### this handler will handle our authorization requests 
class LoginHandler(BaseHandler):
    def get(self):
        # after  login; redirected here      
        # did we get a successful login back?
        args = {}
        args['client_id']= CLIENT_ID
        
        verification_code = self.request.get("code")
        if verification_code:
            # if so, we will use code to get the access_token from Spotify
            # This corresponds to STEP 4 in https://developer.spotify.com/web-api/authorization-guide/
                
            args["client_secret"] = CLIENT_SECRET
            args["grant_type"] = GRANT_TYPE
            args["code"] = verification_code                # the code we got back from Spotify
            args['redirect_uri']=self.request.path_url      # the current page
            
            # We need to make a post request, according to the documentation 
            
            #headers = {'content-type': 'application/x-www-form-urlencoded'}
            url = "https://accounts.spotify.com/api/token"
            response = urlfetch.fetch(url, method=urlfetch.POST, payload=urllib.urlencode(args))
            response_dict = json.loads(response.content)
            logging.info(response_dict["access_token"])
            access_token = response_dict["access_token"]
            refresh_token = response_dict["refresh_token"]

            # Download the user profile. Save profile and access_token
            # in Datastore; we'll need the access_token later
            
            ## the user profile is at https://api.spotify.com/v1/me
            profile = json.loads(spotifyurlfetch('https://api.spotify.com/v1/me',access_token))
            logging.info(profile)
           
            user = User(key_name=str(profile["id"]), uid=str(profile["id"]),
                        displayname=str(profile["display_name"]), access_token=access_token,
                        profile_url=profile["external_urls"]["spotify"], api_url=profile["href"], refresh_token=refresh_token)
            if profile.get('images') is not None:
                if len(profile['images']) > 0:
                    user.img = profile["images"][0]["url"]
            user.put()
            
            ## set a cookie so we can find the user later
            set_cookie(self.response, "spotify_user", str(user.uid), expires=time.time() + 30 * 86400)
            
            ## okay, all done, send them back to the App's home page
            self.redirect("/")
        else:
            # not logged in yet-- send the user to Spotify to do that
            # This corresponds to STEP 1 in https://developer.spotify.com/web-api/authorization-guide/
            
            args['redirect_uri']=self.request.path_url
            args['response_type']="code"
            #ask for the necessary permissions - see details at https://developer.spotify.com/web-api/using-scopes/
            args['scope'] = "user-top-read user-library-modify playlist-modify-private playlist-modify-public playlist-read-collaborative"
            url = "https://accounts.spotify.com/authorize?" + urllib.urlencode(args)
            logging.info(url)
            self.redirect(url)


## this handler logs the user out by making the cookie expire
class LogoutHandler(BaseHandler):
    def get(self):
        set_cookie(self.response, "spotify_user", "", expires=time.time() - 86400)
        self.redirect("/")


application = webapp2.WSGIApplication([\
    ("/", HomeHandler),
    ("/auth/login", LoginHandler),
    ("/auth/logout", LogoutHandler)
], debug=True)

#http://localhost:8080/
#PS C:\Users\nigel> cd ClassCode\s17\spotify-example
#PS C:\Users\nigel\ClassCode\s17\spotify-example> gcloud app deploy app.yaml
