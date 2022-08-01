import http.client
<<<<<<< HEAD
import socket, json                                         #
import hashlib
=======
import json
>>>>>>> e4766f40da41b6078081595b4837b5c88e1748aa

print('\nConnection: ')
connection = http.client.HTTPConnection("localhost", 8000)
print(connection)
print('\n')
headers = {'Forwarded': 'uri=/', 'Content-type': 'application/json'}

# For GET
connection.request("GET", "/", {}, headers)

response = connection.getresponse()
print("Status: {} and reason: {}".format(response.status, response.reason))
print(response.read().decode())

#For POST
#foo = {'text': 'Hello world github/linguist#1 **cool**, and #1!'}
# json_foo = json.dumps(foo)
# connection.request("POST", "/", json_foo, headers)
# response = connection.getresponse()
# print("Status: {} and reason: {}".format(response.status, response.reason))
# print(response.read().decode())

<<<<<<< HEAD

# ==============================================================================================|
serverdict = {'c_csuites': '_', 'c_curves': '_', 's_proto': '_', 's_session': '_', 'c_port': '_',
            's_ip': '_', 'tcp_rtt': '_'}
print("Original svr dict: " + str(serverdict))      # '_' py placeholders
print('\n')
result = list(serverdict.values())
print("result = " + str(result))


# hashedSecret = hashlib.sha224(b"314159265358979323846").hexdigest()         # o # compiles but...
hashedSecret = hashlib.sha224(bytes('314159265358979323846'.encode()))    # compiles but...

print('\nhashedSecret: ')
print(hashedSecret)
print('\n')

connection.send(hashedSecret)
# connection.send(hashedSecret)  #TypeError:bytes-like obj required not 'str' nor '_hashlib.HASH'

# =============================================================================================|


print('\n')
connection.close()
=======
connection.close()
>>>>>>> e4766f40da41b6078081595b4837b5c88e1748aa
