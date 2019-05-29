import urllib.request
import json
import base64
import nacl.encoding
import nacl.signing

url = "http://cs302.kiwi.land/api/add_pubkey"

# STUDENT TO UPDATE THESE...
username = "zli667"
password = "TwelveHertz_916720181"

# create HTTP BASIC authorization header
credentials = ('%s:%s' % (username, password))
b64_credentials = base64.b64encode(credentials.encode('ascii'))
headers = {
    'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
    'Content-Type': 'application/json; charset=utf-8',
}

# Generate a new random signing key
private_key = nacl.signing.SigningKey.generate()

# Obtain the verify key for a given signing key
public_key = private_key.verify_key

# Serialize the verify key to send it to a third party
public_key_hex = public_key.encode(encoder=nacl.encoding.HexEncoder)

message = bytes(public_key_hex.decode('utf-8') + username, encoding='utf-8')

# Signature of the username
signature = private_key.sign(message, encoder=nacl.encoding.HexEncoder)

payload = {
    'pubkey': public_key_hex.decode('utf-8'),
    'username': username,
    'signature': signature.signature.decode('utf-8'),
}

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