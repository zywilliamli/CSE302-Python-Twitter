import cherrypy
import urllib.request
import json
import base64
import urllib.request
import json
import base64
import nacl.encoding
import nacl.signing

startHTML = "<html><head><title>CS302 example</title><link rel='stylesheet' href='/static/example.css' /></head><body>"


class MainApp(object):
    # CherryPy Configuration
    _cp_config = {'tools.encode.on': True,
                  'tools.encode.encoding': 'utf-8',
                  'tools.sessions.on': 'True',
                  }

    # If they try somewhere we don't know, catch it here and send them to the right place.
    @cherrypy.expose
    def default(self, *args, **kwargs):
        """The default page, given when we don't recognise where the request is for."""
        Page = startHTML + "I don't know where you're trying to go, so have a 404 Error."
        cherrypy.response.status = 404
        return Page

    # PAGES (which return HTML that can be viewed in browser)
    @cherrypy.expose
    def index(self):
        Page = startHTML + "Welcome! This is a test website for COMPSYS302!<br/>"

        try:
            Page += "Hello " + cherrypy.session['username'] + "!<br/>"
            # Page += "Here is some bonus text because you've logged in! <a href='/signout'>Sign out</a>"
        except KeyError:  # There is no username

            Page += "Click here to <a href='login'>login</a>."
        return Page

    @cherrypy.expose
    def login(self, bad_attempt=0):
        Page = startHTML
        if bad_attempt != 0:
            Page += "<font color='red'>Invalid username/password!</font>"

        Page += '<form action="/signin" method="post" enctype="multipart/form-data">'
        Page += 'Username: <input type="text" name="username"/><br/>'
        Page += 'Password: <input type="text" name="password"/>'
        Page += '<input type="submit" value="Login"/></form>'
        return Page

    @cherrypy.expose
    def sum(self, a=0, b=0):  # All inputs are strings by default
        output = int(a) + int(b)
        return str(output)

    # LOGGING IN AND OUT
    @cherrypy.expose
    def signin(self, username=None, password=None):
        """Check their name and password and send them either to the main page, or back to the main login screen."""
        error = authoriseUserLogin(username, password)
        if error == 0:
            cherrypy.session['username'] = username
            raise cherrypy.HTTPRedirect('/')
        else:
            raise cherrypy.HTTPRedirect('/login?bad_attempt=1')

    @cherrypy.expose
    def signout(self):
        """Logs the current user out, expires their session"""
        username = cherrypy.session.get('username')
        if username is None:
            pass
        else:
            cherrypy.lib.sessions.expire()
        raise cherrypy.HTTPRedirect('/')


###
### Functions only after here
###

def authoriseUserLogin(username, password):
    LISTEN_IP = "0.0.0.0"
    LISTEN_PORT = 1234
    credentials = ('%s:%s' % (username, password))
    b64_credentials = base64.b64encode(credentials.encode('ascii'))
    headers = {
        'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
        'Content-Type': 'application/json; charset=utf-8',
    }

    private_key = nacl.signing.SigningKey.generate()

    public_key = private_key.verify_key
    public_key_hex = public_key.encode(encoder=nacl.encoding.HexEncoder)

    ap_signature = private_key.sign(bytes(public_key_hex.decode('utf-8') + username, encoding='utf-8'), encoder=nacl.encoding.HexEncoder)
    ping_signature = private_key.sign(bytes(public_key_hex.decode('utf-8'), encoding='utf-8'), encoder=nacl.encoding.HexEncoder)

    payload = {
        'add_pubkey':
            {'pubkey': public_key_hex.decode('utf-8'),
             'username': username,
             'signature': ap_signature.signature.decode('utf-8')},
        'ping':
            {'pubkey': public_key_hex.decode('utf-8'),
             'signature': ping_signature.signature.decode('utf-8')},
        'report':
            {'connection_address': LISTEN_IP + ':' + str(LISTEN_PORT),
             'connection_location': 0,
             'incoming_pubkey': public_key_hex.decode('utf-8'),
             'status': 'online'}
    }


def report():
    pass


def add_pubkey(payload, headers):
    url = "http://cs302.kiwi.land/api/add_pubkey"

    payload_data = json.dumps(payload).encode('utf-8')

    try:
        req = urllib.request.Request(url, data=payload_data, headers=headers)
        response = urllib.request.urlopen(req)
        data = response.read()  # read the received bytes
        encoding = response.info().get_content_charset('utf-8')  # load encoding if possible (default to utf-8)
        response.close()
    except urllib.error.HTTPError as error:
        print(error.read())
        exit()

    JSON_object = json.loads(data.decode(encoding))
    print(JSON_object)


def ping():
    pass


def load_new_api_key(headers):
    url = "http://cs302.kiwi.land/api/load_new_apikey"

    try:
        req = urllib.request.Request(url, headers=headers)
        response = urllib.request.urlopen(req)
        data = response.read()  # read the received bytes
        encoding = response.info().get_content_charset('utf-8')  # load encoding if possible (default to utf-8)
        response.close()
    except urllib.error.HTTPError as error:
        print(error.read())
        exit()

    JSON_object = json.loads(data.decode(encoding))
    print(JSON_object)
