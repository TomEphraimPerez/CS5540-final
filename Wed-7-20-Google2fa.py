''' ***** SYNYOPSIS: ***(using this as a template)******************
Establiosh a secure tunnel
Hail (Hello) eg., allesrebel.com 
GOTO appropriate dir
execute server.py
Extract common, (all, in this case) features
.
.
.
.
Send/share secret
Confirm
 ******************************************************************
'''

# Wed-7-20-Google2fa
# * Information from :     https://docs.python.org/3/library/secrets.html
# * * Information fr:      https://docs.python.org/3/library/hashlib.html

# My full path: /Users/thomasperez/5540Smr22Team/GroupProject1/phoca/Wed-7-20-Google2fa.py
# python Wed-7-20-Google2fa.py


# AFTER 3-WAY >>> LISTENING ON local:8000  >>>>>  DO >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
import string										#*
import secrets										#*
import hashlib										# **
import sys, os

os.getcwd()
'/Users/thomasperez/.ssh'							# ok
print (os.getcwd())									# non-op
os.system('ssh root@allesrebel.com')				# ok - in ' root@localhost:~# ' 
os.chdir("root/5540-final")							# non-op
print (os.getcwd())									# non-op

os.system('python3 server.py')	#@ OK. Results in: "Welcome to Ubuntu 22.04 LTS (GNU/Linux 5.15.0-41-generic x86_64)  . . ."
													# BUT ONLY is visible after  user does ^D in console, manually.s

# RESULTS@  eg:
#About to listen on http://localhost:8000
'''
{'for': '67.150.3.111', 'c_csuites': 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM -SHA256:ECDHE-ECDSA-AES256-SHA38 		etc etc etc
'''

print("\n\nProcessing fingerprinting of client app comms over TLS")	# os.system usage?

# Extract elements/features  of the server-side (from a dict).  
	#  from eg., root@localhost:~# cd 5540-final / server.py / [listening localhost:1000] / [my IP]
	# 	filter or not : 		
		# 		c_csuites (cipher)
		# 		c_curves (characteristic math algo)
		# 		s_proto
		# 		s_session (a hex str ~ 60 chars), 	  
		# 		c_port (client) 		
		# 		s_ip
		# 		tcp_rtt
		
# ** Condensed-usage:		
serverdict = {'c_csuites' :  '_' , 	 'c_curves' :  '_' ,	 's_proto' :	 '_' ,	  's_session' :  '_' ,	 'c_port' :  '_' ,	 's_ip' :  '_'  ,	 'tcp_rtt' : '_'	 }		# init
print("\n\nOriginal svr dict: " + str(serverdict))					#  test

# https://pythonguides.com/get-all-values-from-a-dictionary-python/
result = list(serverdict.values())									# Extract values using py BI values().
print(" \n\nResult : " +  str(result))								# test

# hash :
# https://docs.python.org/3/library/hashlib.html
# hashlib.sha224(result).hexdigest()								# Non-op. 
# m = hashlib.sha224()												# ?
# m.block_size														# ?


# Share hash ------->	 

os.system('exit')


