# ClIENT:

# $ ssh root@allesrebel.com   # $ exit -> Connection to allesrebel.com closed.
# $ cd 5540-final
# $ python3 server.py	-> About to listen on http://localhost:8000
# [blinking cursor]

from ipaddress import IPv6Interface, ip_address, ip_interface, ip_network #
import ipaddress										#
import os, sys											# 
import hashlib
from telnetlib import IP
import requests											# 
import socket
BUFFER_SIZE = 1024
 	
# url = '127.0.0.1:443'		# lcl host test only, or 127.0.0.0/8 or 8.8.8.8 
print('\nsecret (fromTempLiteral):')										
hashedSecret = hashlib.sha224(b"314159265358979323846").hexdigest()		# test
print(hashedSecret)										# test

host = "localhost"										# o
port = 8000
# s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # o
s = socket.socket() 									# Either "s =..." , same results"
print ("\nSocket successfully created\n")
s.bind((host, port))									# OK											
# host = socket.gethostname()
# s.connect((host, port))			# -> ConnectionRefusedError: [Errno 61] Connection refused
s.listen(5000)  
print("\nsocket is listening\n")
print('s.bind((host, port: OK')

'''
while True: 
# Establish connection with client.
  c, addr = s.accept()    
  print ('Got connection from', host) 
  # send a thank you message to the client. encoding to send byte type.
  c.send('Thank you for connecting'.encode())
  # Close the connection with the client
  # c.close()   
  # Breaking once connection closed
  break
'''

# s.bind((host, port))
# s.close()

print("\n\nCONNECTION FROM: \n", host)
print("CONNECTION FROM: \n", port)
print('\n')

# Extract elements/features  of the server-side (from a dictionary).  
	# eg.,from root@localhost:~# cd 5540-final / server.py / [listening on localhost:8000]/[my IP]: 		
		# 		c_csuites (cipher)
		# 		c_curves (characteristic math algo)
		# 		s_proto
		# 		s_session (a hex str ~ 60 chars), 	  
		# 		c_port (client) 		
		# 		s_ip
		# 		tcp_rtt
serverdict = {'c_csuites' :  '_' , 	 'c_curves' :  '_' ,	 's_proto' :	 '_' ,	  's_session' :  '_' ,	 'c_port' :  '_' ,	 's_ip' :  '_'  ,	 'tcp_rtt' : '_'}	

print("Original svr dict: " + str(serverdict))			#  test

# https://pythonguides.com/get-all-values-from-a-dictionary-python/
result = list(serverdict.values())						# Extract values w/ py built-in values().
print("result = " +  str(result))						# test
print('\n')

# https://docs.python.org/3/library/hashlib.html
m = hashlib.sha224()									# †
m.update(b"\n\n\t\tIs anyone $HOME ?\n")
m.digest()
print(m)		# -> <sha224 _hashlib.HASH object @ 0x102858350>

# hashlib.sha224(result).hexdigest()					# Non-op. But uneccessary since †
digestSZ = m.digest_size
print('digest size: ', digestSZ)
blockSZ = m.block_size
print('block size: ', blockSZ)
print('\n')


# SEND HASHED_SECRET -------------|
s.sendall(hashedSecret.encode())   						# -> OSError: Socket is not connected
# --------------------------------|
s.close()


# SEND RESULT ====================|

# ================================|

# NOTES ->>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
# host = root@allesrebel.com	-  45.79.84.107 ping OK.						   
	# (Only the server needs to worry about using a free port, & clients need to know what the port is 
		# OW they'll not be able to connect to  svr.
# host = "45.79.84.107"										# S-ip
# (TCP sockets are bi-directional. After connection there's no diff bt svr & client, you only have 2 
	# ends of a stream)
# (My full path:  /Users/thomasperez/5540Smr22Team/GroupProject1/phoca/SendHashToSvr.txt)
# <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   END NOTES  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<

