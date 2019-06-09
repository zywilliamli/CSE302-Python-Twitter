import socket
import time

import cherrypy
import urllib.request
import urllib.request
import json
import base64
import nacl.encoding
import nacl.signing
from database import Database
from jinja2 import Environment, FileSystemLoader

file_loader = FileSystemLoader('template')
env = Environment(loader=file_loader)

page = open('page.html', 'r').read()

listen_ip = "0.0.0.0"
listen_port = 1233

private_key = nacl.signing.SigningKey.generate()

user_list = {}
pubkey_response = {}

public_key = private_key.verify_key
public_key_hex = public_key.encode(encoder=nacl.encoding.HexEncoder)

ip = socket.gethostbyname(socket.gethostname())
connection = {'lab': '0', 'wifi': '1', 'world': '2'}
word_filter = {'fuck': '****', 'shit': '****', 'cunt': '****'}

status = ['online', 'away', 'busy', 'offline']
headers = {}
urls = {
    'load_new_apikey': "http://cs302.kiwi.land/api/load_new_apikey",
    'add_pubkey': "http://cs302.kiwi.land/api/add_pubkey",
    'ping': "http://cs302.kiwi.land/api/ping",
    'report': "http://cs302.kiwi.land/api/report",
    'list_users': "http://cs302.kiwi.land/api/list_users",
    'rx_privatemessage': "http://cs302.kiwi.land/api/rx_privatemessage"
}

db = Database()
db.openConnection()
db.createTables()


class API(object):

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    def rx_privatemessage(self):
        message = cherrypy.request.json
        Data.receive_message(message)
        return {'response': 'ok'}

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    def rx_broadcast(self):
        broadcast = cherrypy.request.json
        Data.receive_broadcast(broadcast)
        return {'response': 'ok'}

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    def ping_check(self):
        return {'response': 'ok', 'my_time': str(time.time())}
    #
    # @cherrypy.expose
    # @cherrypy.tools.json_in()
    # def checkmessage(self):
    #     dict = cherrypy.request.json
    #
    # @cherrypy.expose
    # @cherrypy.tools.json_in()
    # def rx_groupmessage(self):
    #     dict = cherrypy.request.json
    #
    # @cherrypy.expose
    # @cherrypy.tools.json_in()
    # def rx_groupinvite(self):
    #     dict = cherrypy.request.json
    #
    # @cherrypy.expose
    # @cherrypy.tools.json_in()
    # def ping_check(self):
    #     dict = cherrypy.request.json
    #


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
        template = env.get_template('page.html')

        broadcasts = db.getAllBroadcasts()
        messages = db.getMessageHistory()

        print(broadcasts)

        return template.render(broadcasts=broadcasts, messages=messages)

    @cherrypy.expose
    def index(self):
        template = env.get_template('page.html')

        broadcasts = db.getAllBroadcasts()
        messages = db.getMessageHistory()

        return template.render(broadcasts=broadcasts, messages=messages)

    @cherrypy.expose
    def refreshBroadcast(self):
        template = env.get_template('page.html')

        broadcasts = db.getAllBroadcasts()
        messages = db.getMessageHistory()

        return template.render(broadcasts=broadcasts, messages=messages)

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
        print('logging out')
        error = Data.user_logout()
        return error

    @cherrypy.expose
    def getUsers(self):
        try:
            user_list = Data.get_user_list()
            print(user_list)
            upi_list = []
            for user in user_list['users']:
                upi_list.append(user['username'])
            return json.dumps(upi_list)
        except:
            return '1'

    @cherrypy.expose
    def broadcast(self, data):
        Data.rx_broadcast(data)
        return '0'

    @cherrypy.expose
    def sendMessage(self, data, name):
        Data.pm(data, name)
        return '0'

    @cherrypy.expose
    def getMessage(self):
        # pass
        print(db.getMessageHistory())
        return db.getMessageHistory()[0]['message']

    @cherrypy.expose
    def ping_check(self):
        ping_payload = {'my_time': str(time.time()), 'connection_address': ip + ':' + str(listen_port), 'connection_location': connection['wifi']}
        for user in user_list['users']:
            print(user)
            try:
                ping_response = Data.post('http://' + user['connection_address'] + '/api/rx_broadcast', headers, ping_payload)
                print(ping_response)
            except:
                print('excepted')
                pass


class Data(object):

    @staticmethod
    def pm(message, user_name):
        # admin = next(item for item in user_list['users'] if item['username'] == user_name)
        admin = user_list['users'][int(user_name)]
        message1 = message.encode('utf-8')

        verifykey = nacl.signing.VerifyKey(admin['incoming_pubkey'], encoder=nacl.encoding.HexEncoder)
        publickey = verifykey.to_curve25519_public_key()
        sealed_box = nacl.public.SealedBox(publickey)
        encrypted = sealed_box.encrypt(message1, encoder=nacl.encoding.HexEncoder)
        message = encrypted.decode('utf-8')

        pm_signature = private_key.sign(
            bytes(pubkey_response['loginserver_record'] + admin['incoming_pubkey'] + admin['username'] + message + str(time.time()),
                  encoding='utf-8'),
            encoder=nacl.encoding.HexEncoder)

        pm_payload = {
            'loginserver_record': pubkey_response['loginserver_record'],
            'target_pubkey': admin['incoming_pubkey'],
            'target_username': admin['username'],
            'encrypted_message': message,
            'sender_created_at': str(time.time()),
            'signature': pm_signature.signature.decode('utf-8')
        }
        pm_response = Data.post('http://' + admin['connection_address'] + '/api/rx_privatemessage', headers, pm_payload)
        print(pm_response)

    @staticmethod
    def get_user_list():
        global user_list
        user_list = Data.get(urls['list_users'], headers)
        return user_list

    @staticmethod
    def rx_broadcast(message):
        broadcast_signature = private_key.sign(bytes(pubkey_response['loginserver_record'] + message + str(time.time()), encoding='utf-8'),
                                               encoder=nacl.encoding.HexEncoder)

        broadcast_payload = {'loginserver_record': pubkey_response['loginserver_record'],
                             'message': message,
                             'sender_created_at': str(time.time()),
                             'signature': broadcast_signature.signature.decode('utf-8')}

        for user in user_list['users']:
            print(user['username'])
            try:
                broadcast_response = Data.post('http://' + user['connection_address'] + '/api/rx_broadcast', headers, broadcast_payload)
                print(broadcast_response)
            except:
                print('excepted')
                pass

    @staticmethod
    def user_logout():
        payload = {'connection_address': ip + ':' + str(listen_port),
                   'connection_location': connection['lab'],
                   'incoming_pubkey': public_key_hex.decode('utf-8'),
                   'status': status[3]}

        report_response = Data.post(urls['report'], headers, payload)

        if report_response['response'] == 'ok':
            return '0'
        else:
            return '1'

    @staticmethod
    def create_headers(username, password):
        credentials = ('%s:%s' % (username, password))
        b64_credentials = base64.b64encode(credentials.encode('ascii'))

        headers['Authorization'] = 'Basic %s' % b64_credentials.decode('ascii')
        headers['Content-Type'] = 'application/json; charset=utf-8'

    @staticmethod
    def create_api_headers(username, api_key):
        global headers
        headers = {
            'X-username': username,
            'X-apikey': api_key,
            'Content-Type': 'application/json; charset=utf-8'
        }

    # Functions only after here
    @staticmethod
    def authorise_user_login(username, password, location):
        Data.create_headers(username, password)

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
                {'connection_address': ip + ':' + str(listen_port),
                 'connection_location': connection['wifi'],
                 'incoming_pubkey': public_key_hex.decode('utf-8'),
                 'status': status[0]}
        }

        global pubkey_response
        apikey_response = Data.get(urls['load_new_apikey'], headers)

        Data.create_api_headers(username, apikey_response['api_key'])

        pubkey_response = Data.post(urls['add_pubkey'], headers, payload['add_pubkey'])
        ping_response = Data.post(urls['ping'], headers, payload['ping'])
        report_response = Data.post(urls['report'], headers, payload['report'])
        print("----------------------------------------------------------------")
        print("apikey_response")
        print(apikey_response)
        print("pubkey_response")
        print(pubkey_response)
        print("ping_response")
        print(ping_response)
        print("report_response")
        print(report_response)
        print("----------------------------------------------------------------")

        if report_response['response'] == 'ok':
            return 0
        else:
            return 1

    @staticmethod
    def post(url, headers, payload):
        payload_data = json.dumps(payload).encode('utf-8')

        try:
            req = urllib.request.Request(url, data=payload_data, headers=headers)
            response = urllib.request.urlopen(req, timeout=1)
            data = response.read()  # read the received bytes
            encoding = response.info().get_content_charset('utf-8')  # load encoding if possible (default to utf-8)
            response.close()
        except urllib.error.HTTPError as error:
            print(error.read())
            exit()

        json_object = json.loads(data.decode(encoding))
        return json_object

    @staticmethod
    def get(url, headers):
        try:
            req = urllib.request.Request(url, headers=headers)
            response = urllib.request.urlopen(req, timeout=1)
            data = response.read()  # read the received bytes
            encoding = response.info().get_content_charset('utf-8')  # load encoding if possible (default to utf-8)
            response.close()
        except urllib.error.HTTPError as error:
            print(error.read())
            exit()

        json_object = json.loads(data.decode(encoding))
        return json_object

    @staticmethod
    def receive_message(message):
        unsealed_box = nacl.public.SealedBox(private_key.to_curve25519_private_key())
        decoded_message = unsealed_box.decrypt(message['encrypted_message'].encode('utf-8'), encoder=nacl.encoding.HexEncoder).decode('utf-8')
        message_tuple = (message['loginserver_record'], message['target_pubkey'], message['target_username'], decoded_message,
                         message['sender_created_at'], message['signature'])
        db.insertMessage(message_tuple)

    @staticmethod
    def receive_broadcast(broadcast):
        broadcast_tuple = (broadcast['loginserver_record'], broadcast['message'], broadcast['sender_created_at'], broadcast['signature'])
        db.insertBroadcast(broadcast_tuple)
