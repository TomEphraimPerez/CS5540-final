# 										Send a hash to the server

'''
The sequence diagram has a couple minor changes, there is flexibility with options etc. 
This code simply will inject a hash into the server's website.db. In directories, 
Rebel (/root/5540-final) has one as I do (/Users/thomasperez/5540Smr22Team/GroupProject1/phoca).
2FA preceeds this module.
'''
# ((My full path:  /Users/thomasperez/5540Smr22Team/GroupProject1/phoca/SendHashToSvr.txt))
import os, sys												# TBA
import hashlib
import requests												# TBA
import socket
		
# CREATE the secret 	
# url = '127.0.0.1:443'		# lcl host test only, or 127.0.0.0/8 or 8.8.8.8 
# print(url)															# test only
hashedSecret = hashlib.sha224(b"314159265358979323846").hexdigest()		# testonly
print(hashedSecret)														# testonly

# SAVE/cache secret "hashedSecret"

# EXCHANGE secret over secure link
# TCP sockets are bi-directional. After connection there's no difference bt svr & client, you only have 2 ends of a stream:

														
# Take the server name and port.
# host = "localhost"										# ?
# host = root@allesrebel.com	-  45.79.84.107 			# or	
#host = socket.gethostname()							 
		# ( server needs to worry about using a free port, and the clients need to know what this port 	is, 
			# OW they'll not be able to connect to  svr. **

# s = socket.socket() 										>>>
# s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 	# Server ((of both?))
s = socket.socket() 										# Client (c_port 55651)
# host = "45.79.84.107"										# S-ip
host = "localhost"
port = 8000			

s.connect((host, port))										# Send and rec on secured ch	
# s.sendall(hashedSecret.encode())
print("CONNECTION FROM:", str(addr))



# Extract elements/features  of the server-side (from a dictionary).  
	#  eg., from root@localhost:~# cd 5540-final / server.py / [listening on localhost:8000] / [my IP]: 		
		# 		c_csuites (cipher)
		# 		c_curves (characteristic math algo)
		# 		s_proto
		# 		s_session (a hex str ~ 60 chars), 	  
		# 		c_port (client) 		
		# 		s_ip
		# 		tcp_rtt
serverdict = {'c_csuites' :  '_' , 	 'c_curves' :  '_' ,	 's_proto' :	 '_' ,	  's_session' :  '_' ,	 'c_port' :  '_' ,	 's_ip' :  '_'  ,	 'tcp_rtt' : '_'	}		
print("\n\nOriginal svr dict: " + str(serverdict))			#  test


# https://pythonguides.com/get-all-values-from-a-dictionary-python/
result = list(serverdict.values())							# Extract values using py built-in values().
print(" \n\nResult : " +  str(result))						# test


# https://docs.python.org/3/library/hashlib.html
# hashlib.sha224(result).hexdigest()						# Non-op. 
# m = hashlib.sha224()										# ?
# m.block_size												# ?
