# 7-8-22 2FA, based on; credit:
#       https://blog.jothin.tech/2fa-with-python
# and hopefully easily reversable.
# test10
# pip install onetimepass
# authenticator app = Google authenticatoror Microsoft authenticator or etc.

# lcl Dir >>>
# /Users/thomasperez/5540smr22Team/GroupProject1/phoca 



# |******************           EXECUTE        ******************************************|
'''
Execute:	python 2FA_1_7-9-22BAK.py 	( not $ ./2FA_1_7-9-22BAK.py , O/W get script errors)
									A <TOTP>
'''
# |**************************************************************************************|



# |********* HOW TO GET YOUR One-Time secret Passcode given by Microsoft; eg 373030 ******|
# USE the GITHUB URL to enter into the Microsoft Authenticator app, eg:
# 		https://github.com/TomEphraimPerez/CS5540-final/tree/master
#  Include the generated 16 alphanumeric secret given when running this script; eg: 
#		4RPQ75PDZCZJJ2E5

# Now - the MS authenticator, for a few seconds, issues you a  		
#       One-Time secret Passcode given by Microsoft;  eg: 373030
# Enter this 6-digit code into the CLI since it's expecting it.
# |******************           Vio'la          ******************************************|



# |*****      JSON and CSV formats supported for output of raw feature data:     *********|
'''
R-> client looking out
sudo python phoca --raw-data --output-format json www.google.com | jq
{
  "www.google.com": {
    "classification": "Non-Phishing",
    "data": {
      "site": "www.google.com",
      "tcpSYNTiming": 5.626678466796875e-05,
      "tlsClientHelloTiming": 0.0029659271240234375,
      "tlsClientHelloErrorTiming": 0.003025054931640625,
      "tlsHandshakeTiming": 0.012071371078491211,
      ...

'''
# |***************************************************************************************|



from onetimepass import  valid_totp
from secrets import choice
# for HTOP
from onetimepass import  valid_hotp

#Function to rtn a rand str w/ len=16
def generate_secret():
	secret = ''
	while len(secret) < 16:
		secret += choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567')
		
	return secret
		
secret = generate_secret()
print('\n\n\t\tEnter the secret passcode you see here, into your Microsoft authenticator app :  ', secret)
print("""
	>>> OPTIONAL for GOOGLE Authenticator | Saving the Google secret:
	> Open the app
	> Click on the "+" icon
	> Click "Enter"
	> Enter an email account, then the  secret code
	> Click "Add"
""")

print('\n\n')
while True:
	otp = int (input ('Enter the One-Time secret Passcode given by Microsoft :  '))
	authenticated = valid_totp(otp, secret)
   
	if authenticated:
		print('Valid OTP,  Authenticated  :)  ')
	elif not authenticated:
		print('Invalid OTP,   : /   Try again.')

		
#												A n<HOTP>
'''
def generate_secret():
	secret = ''
	while len(secret) < 16:
		secret += choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567')
		
	return secret
	
secret = generate_secret()
print('\n\n\t\tEnter the secret passcode you see here, into your Microsoft authenticator app :  ', secret)
print("""
    >>> OPTIONAL for GOOGLE Authenticator | Saving the Google secret:
	> Open the app
	> Click on the "+" icon
	> Click "Enter"
	> Enter an email account, then the  secret code
	> Click "Add"
""")
'''

"""
print('\n\n')
while True:
	counter = 0
	opt = int (input ('Enter the One-Time secret Passcode given by Microsoft :  '))
	authenticated = valid_hotp(otp, secret)
   
	if authenticated:
		print('Valid OTP,  Authenticated  : ) ') 
		count += 1
	elif not authenticated:
		print('Invalid OTP,  : / Try again.')	
"""








