import urllib.request
import json
import base64
import nacl.encoding
import nacl.signing


def post(url, headers, payload):
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


def get(url, headers):
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


username = "zli667"
password = "TwelveHertz_916720181"

LISTEN_IP = "0.0.0.0"
LISTEN_PORT = 1234
credentials = ('%s:%s' % (username, password))
b64_credentials = base64.b64encode(credentials.encode('ascii'))

private_key = nacl.signing.SigningKey.generate()

public_key = private_key.verify_key
public_key_hex = public_key.encode(encoder=nacl.encoding.HexEncoder)

ap_signature = private_key.sign(bytes(public_key_hex.decode('utf-8') + username, encoding='utf-8'), encoder=nacl.encoding.HexEncoder)
ping_signature = private_key.sign(bytes(public_key_hex.decode('utf-8'), encoding='utf-8'), encoder=nacl.encoding.HexEncoder)

headers = {
    'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
    'Content-Type': 'application/json; charset=utf-8',
}

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

urls = {
    'load_new_apikey': "http://cs302.kiwi.land/api/load_new_apikey",
    'add_pubkey': "http://cs302.kiwi.land/api/add_pubkey",
    'ping': "http://cs302.kiwi.land/api/ping",
    'report': "http://cs302.kiwi.land/api/report"
}

get(urls['load_new_apikey'], headers)
post(urls['add_pubkey'], headers, payload['add_pubkey'])
post(urls['ping'], headers, payload['ping'])
post(urls['report'], headers, payload['report'])
