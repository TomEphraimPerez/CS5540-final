# ClIENT:

import os, sys												# 
import hashlib
import requests												# 
import socket
BUFFER_SIZE = 1024
 	
# url = '127.0.0.1:443'		# lcl host test only, or 127.0.0.0/8 or 8.8.8.8 
print('\nsecret (fromTempLiteral):')										
hashedSecret = hashlib.sha224(b"314159265358979323846").hexdigest()		# test
print(hashedSecret)											# test
														
host = "localhost"
port = 8000			

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 		#  
s.bind((host, port))

print("\n\nCONNECTION FROM (inThisCase):", str('45.79.84.107'))

# Extract elements/features  of the server-side (from a dictionary).  
	#  eg., from root@localhost:~# cd 5540-final / server.py / [listening on localhost:8000] / [my IP]: 		
		# 		c_csuites (cipher)
		# 		c_curves (characteristic math algo)
		# 		s_proto
		# 		s_session (a hex str ~ 60 chars), 	  
		# 		c_port (client) 		
		# 		s_ip
		# 		tcp_rtt
print('\n')
serverdict = {'c_csuites' :  '_' , 	 'c_curves' :  '_' ,	 's_proto' :	 '_' ,	  's_session' :  '_' ,	 'c_port' :  '_' ,	 's_ip' :  '_'  ,	 'tcp_rtt' : '_'}	

print("Original svr dict: " + str(serverdict))			#  test

# https://pythonguides.com/get-all-values-from-a-dictionary-python/
result = list(serverdict.values())							# Extract values using py built-in values().
print("Result : " +  str(result))							# test
print('\n')

# https://docs.python.org/3/library/hashlib.html
m = hashlib.sha224()										# 
m.update(b"\n\n\t\tIs anyone $HOME ?\n")
m.digest()
# hashlib.sha224(result).hexdigest()							# Non-op. 
# m = hashlib.sha224()										# 
# m.block_size												# 


# NOTES ->>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
# host = root@allesrebel.com	-  45.79.84.107 			# 							   
	# ( server needs to worry about using a free port, and the clients need to know what this port is, 
		# OW they'll not be able to connect to  svr. **
# host = "45.79.84.107"										# S-ip
# TCP sockets are bi-directional. After connection there's no difference bt svr & client, you only have 2 
	# ends of a stream:
# ((My full path:  /Users/thomasperez/5540Smr22Team/GroupProject1/phoca/SendHashToSvr.txt))
# <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   END NOTES  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<

