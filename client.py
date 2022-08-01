import http.client
import socket, json                                         #
import hashlib
import json
import socket

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

# ==============================================================================================|
serverdict = {'c_csuites': '_', 'c_curves': '_', 's_proto': '_', 's_session': '_', 'c_port': '_',
            's_ip': '_', 'tcp_rtt': '_'}
print("Original svr dict: " + str(serverdict))      # '_' py placeholders
print('\n')
result = list(serverdict.values())
print("result = " + str(result))
# hashedSecret = hashlib.sha224(b"314159265358979323846").hexdigest()     # o # compiles but...
# hashedSecret = hashlib.sha224(bytes('314159265358979323846'.encode()))    # compiles but...
                                        # or
# hashedSecret = hashlib.md5()
# update_bytes = b'314159265358979323846'
# hashedSecret.update(update_bytes)
# print('\nhashedSecret: ')
# print(hashedSecret)
print('\n')
# connection.send(hashedSecret)
# connection.send(hashedSecret)  #TypeError:bytes-like obj required not 'str' nor '_hashlib.HASH'
# =============================================================================================|




print("Massage to pass: ")
msg = input("314159265358979323846")
msg_utf = str.encode(msg)
hashedSecret = hashlib.sha256(msg_utf)
print('\nHash object: ')
print(hashedSecret)
#hex_dig = hashedSecret.hexdigest()
# message_to_send = "{" + msg + ";" + hashedSecret + "}"
message_to_send = "{" + msg + " + ";"}"
# val_bytes = bytearray(hashedSecret.digest())
# connection.send(val_bytes)
# data = connection.recv(1024).decode()
# print(data)
#msg = input()
print('\n')
connection.close()

