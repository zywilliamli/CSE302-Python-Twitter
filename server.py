import socket
import time
import os
import cherrypy
import urllib.request
import json
import base64
import nacl.encoding
import nacl.signing
from database import Database

# load the html page as global variable
page = open(os.getcwd() + '/page.html', 'r').read()

listen_ip = "0.0.0.0"
listen_port = 10000

# word filter for swear words
word_filter = {'fuck': 'f**k', 'shit': 's**t', 'cunt': 'c**t'}
connection = {'lab': '0', 'wifi': '1', 'world': '2'}
status = ['online', 'away', 'busy', 'offline']
urls = {
    'load_new_apikey': "http://cs302.kiwi.land/api/load_new_apikey",
    'add_pubkey': "http://cs302.kiwi.land/api/add_pubkey",
    'ping': "http://cs302.kiwi.land/api/ping",
    'report': "http://cs302.kiwi.land/api/report",
    'list_users': "http://cs302.kiwi.land/api/list_users",
}

db = Database()
db.connect_db()
db.create_tables()


# listening apis, for when other clients call this client's endpoints
class API(object):

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    def rx_privatemessage(self):
        message = cherrypy.request.json
        error = Data.store_message(message)
        if error is '0':
            return {'response': 'ok'}
        else:
            return {'error': 'error'}

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    def rx_broadcast(self):
        broadcast = cherrypy.request.json
        error = Data.store_broadcast(broadcast)
        if error is '0':
            return {'response': 'ok'}
        else:
            return {'error': 'error'}

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    def ping_check(self):
        return {'response': 'ok', 'my_time': str(time.time())}


# the class main.py and javascript interacts with
class MainApp(object):
    # CherryPy Configuration
    _cp_config = {'tools.encode.on': True,
                  'tools.encode.encoding': 'utf-8',
                  'tools.sessions.on': 'True',
                  }

    # If they try somewhere we don't know, catch it here and send them to the right place.
    @cherrypy.expose
    def default(self, *args, **kwargs):
        # """The default page, given when we don't recognise where the request is for."""
        cherrypy.response.status = 404
        return page

    @cherrypy.expose
    def index(self):
        return page

    @cherrypy.expose
    def sum(self, a=0, b=0):  # All inputs are strings by default
        output = int(a) + int(b)
        return str(output)

    # LOGGING IN AND OUT
    @cherrypy.expose
    def signin(self, username=None, password=None, location=None):

        """Check their name and password and send them either to the main page, or back to the main login screen."""
        error = Data.authorise_user_login(username, password, location)
        if error == 0:
            cherrypy.session['username'] = username
            return "0"
        else:
            return "1"

    @cherrypy.expose
    def signout(self):
        """Logs the current user out, expires their session"""
        error = Data.user_logout()
        return error

    @cherrypy.expose
    def update_users(self):
        try:
            Data.get_user_list()
            upi_list = []
            for user in cherrypy.session['user_list']['users']:
                upi_list.append(user['username'])
            return json.dumps(upi_list)
        except:
            return '1'

    @cherrypy.expose
    def update_broadcast(self):

        broadcasts = db.get_broadcast()
        broadcast_list = []
        for broadcast in broadcasts:
            broadcast_list.append(broadcast['username'] + ' (' + broadcast['sender_created_at'] + ') -' + Data.filter_words(broadcast['message']))
        return json.dumps(broadcast_list)

    @cherrypy.expose
    def update_message(self):
        try:
            unsealed_box = nacl.public.SealedBox(cherrypy.session['private_key'].to_curve25519_private_key())
        except:
            pass
        messages = db.get_message()
        message_list = []
        for message in messages:
            try:
                disp_msg = message['sender_username']
                disp_msg += ' -> '
                disp_msg += message['target_username']
                disp_msg += ' ('
                disp_msg += message['sender_created_at']
                disp_msg += ') -'
                try:
                    disp_msg += Data.filter_words(
                        unsealed_box.decrypt(message['message'].encode('utf-8'), encoder=nacl.encoding.HexEncoder).decode('utf-8'))
                    message_list.append(disp_msg)
                except:
                    try:
                        disp_msg += Data.filter_words(message['message'].decode('utf-8'))
                        message_list.append(disp_msg)
                    except:
                        pass
            except:
                pass
        return json.dumps(message_list)

    @cherrypy.expose
    def broadcast(self, data):
        Data.rx_broadcast(data)
        return '0'

    @cherrypy.expose
    def sendMessage(self, data, name):
        Data.pm(data, name)
        return '0'

    @cherrypy.expose
    def report(self):
        payload = {'connection_address': cherrypy.session['ip'] + ':' + str(listen_port),
                   'connection_location': cherrypy.session['location'],
                   'incoming_pubkey': cherrypy.session['public_key_hex'].decode('utf-8'),
                   'status': status[0]}
        report_response = Data.post(urls['report'], cherrypy.session['headers'], payload, 5)
        print(report_response)
        if report_response['response'] == 'ok':
            return '0'
        else:
            return '1'

    @cherrypy.expose
    def ping_check(self):
        ping_payload = {'my_time': str(time.time()), 'connection_address': cherrypy.session['ip'] + ':' + str(listen_port),
                        'connection_location': cherrypy.session['location']}

        for user in cherrypy.session['user_list']['users']:
            try:
                ping_response = Data.post('http://' + user['connection_address'] + '/api/ping_check', cherrypy.session['headers'], ping_payload, 0.2)
            except:
                pass


# data class for interacting with databases, login server, and posting/getting methods
class Data(object):

    @staticmethod
    def filter_words(message):
        for key in word_filter:
            message = message.replace(key, word_filter[key])
        return message

    @staticmethod
    def pm(orig_message, user_name):
        admin = next(item for item in cherrypy.session['user_list']['users'] if item['username'] == user_name)
        message1 = orig_message.encode('utf-8')

        verifykey = nacl.signing.VerifyKey(admin['incoming_pubkey'], encoder=nacl.encoding.HexEncoder)
        publickey = verifykey.to_curve25519_public_key()
        sealed_box = nacl.public.SealedBox(publickey)
        encrypted = sealed_box.encrypt(message1, encoder=nacl.encoding.HexEncoder)
        message = encrypted.decode('utf-8')

        pm_signature = cherrypy.session['private_key'].sign(
            bytes(
                cherrypy.session['pubkey_response']['loginserver_record'] + admin['incoming_pubkey'] + admin['username'] + message + str(time.time()),
                encoding='utf-8'),
            encoder=nacl.encoding.HexEncoder)

        pm_payload = {
            'loginserver_record': cherrypy.session['pubkey_response']['loginserver_record'],
            'target_pubkey': admin['incoming_pubkey'],
            'target_username': admin['username'],
            'encrypted_message': message,
            'sender_created_at': str(time.time()),
            'signature': pm_signature.signature.decode('utf-8')
        }
        pm_response = Data.post('http://' + admin['connection_address'] + '/api/rx_privatemessage', cherrypy.session['headers'], pm_payload, 5)
        pm_payload['encrypted_message'] = message1
        Data.store_message(pm_payload)
        print(pm_response)

    @staticmethod
    def get_user_list():
        cherrypy.session['user_list'] = Data.get(urls['list_users'], cherrypy.session['headers'], 5)

    @staticmethod
    def rx_broadcast(message):
        broadcast_signature = cherrypy.session['private_key'].sign(
            bytes(cherrypy.session['pubkey_response']['loginserver_record'] + message + str(time.time()), encoding='utf-8'),
            encoder=nacl.encoding.HexEncoder)

        broadcast_payload = {'loginserver_record': cherrypy.session['pubkey_response']['loginserver_record'],
                             'message': message,
                             'sender_created_at': str(time.time()),
                             'signature': broadcast_signature.signature.decode('utf-8')}

        for user in cherrypy.session['user_list']['users']:
            print(user['username'])
            try:
                broadcast_response = Data.post('http://' + user['connection_address'] + '/api/rx_broadcast', cherrypy.session['headers'],
                                               broadcast_payload, 1)
                print(broadcast_response)
            except:
                print('excepted')
                pass

    @staticmethod
    def user_logout():
        payload = {'connection_address': cherrypy.session['ip'] + ':' + str(listen_port),
                   'connection_location': cherrypy.session['location'],
                   'incoming_pubkey': cherrypy.session['public_key_hex'].decode('utf-8'),
                   'status': status[3]}

        report_response = Data.post(urls['report'], cherrypy.session['headers'], payload, 5)

        if report_response['response'] == 'ok':
            return '0'
        else:
            return '1'

    @staticmethod
    def create_headers(username, password):
        credentials = ('%s:%s' % (username, password))
        b64_credentials = base64.b64encode(credentials.encode('ascii'))
        cherrypy.session['headers'] = {
            'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
            'Content-Type': 'application/json; charset=utf-8',
        }

    @staticmethod
    def create_api_headers(username, api_key):
        cherrypy.session['headers'] = {
            'X-username': username,
            'X-apikey': api_key,
            'Content-Type': 'application/json; charset=utf-8'
        }

    # Functions only after here
    @staticmethod
    def authorise_user_login(username, password, location):
        cherrypy.session['ip'] = socket.gethostbyname(socket.gethostname())
        cherrypy.session['private_key'] = nacl.signing.SigningKey.generate()
        cherrypy.session['public_key'] = cherrypy.session['private_key'].verify_key
        cherrypy.session['public_key_hex'] = cherrypy.session['public_key'].encode(encoder=nacl.encoding.HexEncoder)
        cherrypy.session['location'] = location
        Data.create_headers(username, password)

        ap_signature = cherrypy.session['private_key'].sign(bytes(cherrypy.session['public_key_hex'].decode('utf-8') + username, encoding='utf-8'),
                                                            encoder=nacl.encoding.HexEncoder)
        ping_signature = cherrypy.session['private_key'].sign(bytes(cherrypy.session['public_key_hex'].decode('utf-8'), encoding='utf-8'),
                                                              encoder=nacl.encoding.HexEncoder)

        payload = {
            'add_pubkey':
                {'pubkey': cherrypy.session['public_key_hex'].decode('utf-8'),
                 'username': username,
                 'signature': ap_signature.signature.decode('utf-8')},
            'ping':
                {'pubkey': cherrypy.session['public_key_hex'].decode('utf-8'),
                 'signature': ping_signature.signature.decode('utf-8')},
            'report':
                {'connection_address': cherrypy.session['ip'] + ':' + str(listen_port),
                 'connection_location': cherrypy.session['location'],
                 'incoming_pubkey': cherrypy.session['public_key_hex'].decode('utf-8'),
                 'status': status[0]}
        }

        apikey_response = Data.get(urls['load_new_apikey'], cherrypy.session['headers'], 5)

        Data.create_api_headers(username, apikey_response['api_key'])

        cherrypy.session['pubkey_response'] = Data.post(urls['add_pubkey'], cherrypy.session['headers'], payload['add_pubkey'], 5)
        ping_response = Data.post(urls['ping'], cherrypy.session['headers'], payload['ping'], 5)
        report_response = Data.post(urls['report'], cherrypy.session['headers'], payload['report'], 5)

        if report_response['response'] == 'ok':
            return 0
        else:
            return 1

    @staticmethod
    def post(url, headers, payload, timeout):
        payload_data = json.dumps(payload).encode('utf-8')

        try:
            req = urllib.request.Request(url, data=payload_data, headers=headers)
            response = urllib.request.urlopen(req, timeout=timeout)
            data = response.read()  # read the received bytes
            encoding = response.info().get_content_charset('utf-8')  # load encoding if possible (default to utf-8)
            response.close()
        except urllib.error.HTTPError as error:
            print(error.read())
            exit()

        json_object = json.loads(data.decode(encoding))
        return json_object

    @staticmethod
    def get(url, headers, timeout):
        try:
            req = urllib.request.Request(url, headers=headers)
            response = urllib.request.urlopen(req, timeout=timeout)
            data = response.read()  # read the received bytes
            encoding = response.info().get_content_charset('utf-8')  # load encoding if possible (default to utf-8)
            response.close()
        except urllib.error.HTTPError as error:
            print(error.read())
            exit()

        json_object = json.loads(data.decode(encoding))
        return json_object

    @staticmethod
    def store_message(message):
        try:
            message_tuple = (message['loginserver_record'], message['target_pubkey'], message['target_username'], message['encrypted_message'],
                             message['sender_created_at'], message['signature'])
            db.insert_message(message_tuple)
            return '0'
        except:
            return '1'

    @staticmethod
    def store_broadcast(broadcast):
        try:
            broadcast_tuple = (broadcast['loginserver_record'], broadcast['message'], broadcast['sender_created_at'], broadcast['signature'])
            db.insert_broadcast(broadcast_tuple)
            return '0'
        except:
            return '1'
