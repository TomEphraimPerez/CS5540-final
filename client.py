import http.client
import json

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

connection.close()