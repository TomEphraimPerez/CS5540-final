# THIS** IS 
# • server.py (from /Users/thomasperez/5540Smr22Team/GroupProject1/phoca/probes/tls_prober/pytls/server.py) 
#   (on my  *main branch),        + (plus)

# • open src code:<Generate JA3 fingerprints from PCAPs using Python> 	from :
#	https://github.com/salesforce/ja3/blob/master/python/ja3.py
#	( py path	#!/usr/bin/env python)


# It's**  a salesforce/ja3er processed  MD5  hash for the TCP details of the client end (as seen by the server).
# ((My REPO:
#   thomasperez$ 00~/Users/thomasperez/5540Smr22Team/GroupProject1/phoca/probes/tls_prober/pytls/server.py 01~     [*MAIN BRANCH] ))

#!/usr/bin/python


'''
HASH THIS:
{'for': '128.199.236.104', 'c_csuites': 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:0xc011:0xc007:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:0x0005:AES128-SHA:AES256-SHA:0xc012:0x000a', 'c_curves': 'prime256v1:secp384r1:secp521r1', 's_proto': 'TLSv1.2', 's_session': '058cadf1d29579131b5acb241a46f8e1c226da08edf855a76ab26d0577dad737', 'c_port': '52456', 's_ip': '45.79.84.107', 'tcp_rtt': '193451', 'uri': '/'}
'''


#|SERVER.PY fr /Users/thomasperez/5540Smr22Team/GroupProject1/phoca/probes/tls_prober/pytls/server.py •••••••••|
import sys 
import os
import socket
import select
import logging
from optparse import OptionParser

from tls import *

def dump_hello(record):
    print('Record Version:', record.tls_versions[record.version()])

    messages = record.handshake_messages()
    for message in messages:
        logging.debug('handshake:%s|', message.message_types[message.message_type()])

        print('Handshake Version:', record.tls_versions[message.version()])
        if message.message_type() == message.ClientHello:
            print('Session ID Length:', message.session_id_length())
            print('Cipher Suites Length (bytes):', message.cipher_suites_length())
            print('Cipher Suites:')
            for suite in message.cipher_suites():
                print('0x%04x' % suite, cipher_suites.get(suite, 'UNKNOWN'))

def read_hello(f):
    record = read_tls_record(f)
    if record.content_type() == TLSRecord.Handshake:
        dump_hello(record)
    else:
        raise Exception('Unexpected message type %s', message.message_types[message.message_type()])
#|END SERVER.PY [/Users/thomasperez/5540Smr22Team/GroupProject1/phoca/probes/tls_prober/pytls/server.py] •••••••|




# |/////////////   https://github.com/salesforce/ja3/blob/master/python/ja3.py   //////////////////////////////|
class generateJA3fpFromPCAPs(object):
	#!/usr/bin/env python
	"""Generate JA3 fingerprints from PCAPs using Python."""

	import argparse
	import dpkt
	import json
	import socket
	import binascii
	import struct
	import os
	from hashlib import md5

	# CREDIT (inc Salesforce):
	__author__ = "Tommy Stallings"
	__copyright__ = "Copyright (c) 2017, salesforce.com, inc."
	__credits__ = ["John B. Althouse", "Jeff Atkinson", "Josh Atkins"]
	__license__ = "BSD 3-Clause License"
	__version__ = "1.0.0"
	__maintainer__ = "Tommy Stallings, Brandon Dixon"
	__email__ = "tommy.stallings2@gmail.com"

	# Google uses this as a mechanism to prevent extensibility failures in the TLS ecosystem. 
	GREASE_TABLE = {0x0a0a: True, 0x1a1a: True, 0x2a2a: True, 0x3a3a: True,
                	0x4a4a: True, 0x5a5a: True, 0x6a6a: True, 0x7a7a: True,
                	0x8a8a: True, 0x9a9a: True, 0xaaaa: True, 0xbaba: True,
                	0xcaca: True, 0xdada: True, 0xeaea: True, 0xfafa: True}
	# GREASE_TABLE Ref: https://tools.ietf.org/html/draft-davidben-tls-grease-00
	SSL_PORT = 443
	TLS_HANDSHAKE = 22

def convert_ip(value):
    """Convert an IP address from binary to text.

    	:param value: Raw binary data to convert
    	:type value: str
    	:returns: str
    """
    try:
        return socket.inet_ntop(socket.AF_INET, value)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, value)

def parse_variable_array(buf, byte_len):
    '''Unpack data from buffer of specific length.

    :param buf: Buffer to operate on
    :type buf: bytes
    :param byte_len: Length to process
    :type byte_len: int
    :returns: bytes, int
    '''
    _SIZE_FORMATS = ['!B', '!H', '!I', '!I']
    assert byte_len <= 4
    size_format = _SIZE_FORMATS[byte_len - 1]
    padding = b'\x00' if byte_len == 3 else b''
    size = struct.unpack(size_format, padding + buf[:byte_len])[0]
    data = buf[byte_len:byte_len + size]
    
    return data, size + byte_len


def ntoh(buf):
    """Convert to network order.

    :param buf: Bytes to convert
    :type buf: bytearray
    :returns: int
    """
    if len(buf) == 1:
        return buf[0]
    elif len(buf) == 2:
        return struct.unpack('!H', buf)[0]
    elif len(buf) == 4:
        return struct.unpack('!I', buf)[0]
    else:
        raise ValueError('Invalid input buffer size for NTOH')


def convert_to_ja3_segment(data, element_width):
    """Convert a packed array of elements to a JA3 segment.

    :param data: Current PCAP buffer item
    :type: str
    :param element_width: Byte count to process at a time
    :type element_width: int
    :returns: str
    """
    int_vals = list()
    data = bytearray(data)
    if len(data) % element_width:
        message = '{count} is not a multiple of {width}'
        message = message.format(count=len(data), width=element_width)
        raise ValueError(message)

    for i in range(0, len(data), element_width):
        element = ntoh(data[i: i + element_width])
        if element not in GREASE_TABLE:
            int_vals.append(element)
    	
    return "-".join(str(x) for x in int_vals)


def process_extensions(client_handshake):
    """Process any extra extensions and convert to a JA3 segment.

    :param client_handshake: Handshake data from the packet
    :type client_handshake: dpkt.ssl.TLSClientHello
    :returns: list
    """
    if not hasattr(client_handshake, "extensions"):
        # Needed to preserve commas on the join
        return ["", "", ""]

    exts = list()
    elliptic_curve = ""
    elliptic_curve_point_format = ""
    for ext_val, ext_data in client_handshake.extensions:
        if not GREASE_TABLE.get(ext_val):
            exts.append(ext_val)
        if ext_val == 0x0a:
            a, b = parse_variable_array(ext_data, 2)
            # Elliptic curve points (16 bit values)
            elliptic_curve = convert_to_ja3_segment(a, 2)
        elif ext_val == 0x0b:
            a, b = parse_variable_array(ext_data, 1)
            # Elliptic curve point formats (8 bit values)
            elliptic_curve_point_format = convert_to_ja3_segment(a, 1)
        else:
            continue

    results = list()
    results.append("-".join([str(x) for x in exts]))
    results.append(elliptic_curve)
    results.append(elliptic_curve_point_format)
    
    return results


def process_pcap(pcap, any_port=False):
    """Process packets within the PCAP.

    :param pcap: Opened PCAP file to be processed
    :type pcap: dpkt.pcap.Reader
    :param any_port: Whether or not to search for non-SSL ports
    :type any_port: bool
    """
    decoder = dpkt.ethernet.Ethernet
    linktype = pcap.datalink()
    if linktype == dpkt.pcap.DLT_LINUX_SLL:
        decoder = dpkt.sll.SLL
    elif linktype == dpkt.pcap.DLT_NULL or linktype == dpkt.pcap.DLT_LOOP:
        decoder = dpkt.loopback.Loopback

    results = list()
    for timestamp, buf in pcap:
        try:
            eth = decoder(buf)
        except Exception:
            continue

        if not isinstance(eth.data, (dpkt.ip.IP, dpkt.ip6.IP6)):
            # We want an IP packet
            continue
        if not isinstance(eth.data.data, dpkt.tcp.TCP):
            # TCP only
            continue

        ip = eth.data
        tcp = ip.data

        if not (tcp.dport == SSL_PORT or tcp.sport == SSL_PORT or any_port):
            # Doesn't match SSL port or we are picky
            continue
        if len(tcp.data) <= 0:
            continue

        tls_handshake = bytearray(tcp.data)
        if tls_handshake[0] != TLS_HANDSHAKE:
            continue

        records = list()

        try:
            records, bytes_used = dpkt.ssl.tls_multi_factory(tcp.data)
        except dpkt.ssl.SSL3Exception:
            continue
        except dpkt.dpkt.NeedData:
            continue

        if len(records) <= 0:
            continue

        for record in records:
            if record.type != TLS_HANDSHAKE:
                continue
            if len(record.data) == 0:
                continue
            client_hello = bytearray(record.data)
            if client_hello[0] != 1:
                # We only want client HELLO
                continue
            try:
                handshake = dpkt.ssl.TLSHandshake(record.data)
            except dpkt.dpkt.NeedData:
                # Looking for a handshake here
                continue
            if not isinstance(handshake.data, dpkt.ssl.TLSClientHello):
                # Still not the HELLO
                continue

            client_handshake = handshake.data
            buf, ptr = parse_variable_array(client_handshake.data, 1)
            buf, ptr = parse_variable_array(client_handshake.data[ptr:], 2)
            ja3 = [str(client_handshake.version)]

            # Cipher Suites (16 bit values)
            ja3.append(convert_to_ja3_segment(buf, 2))
            ja3 += process_extensions(client_handshake)
            ja3 = ",".join(ja3)

            record = {"source_ip": convert_ip(ip.src),
                    "destination_ip": convert_ip(ip.dst),
                    "source_port": tcp.sport,
                    "destination_port": tcp.dport,
                    "ja3": ja3,
                    "ja3_digest": md5(ja3.encode()).hexdigest(),
                    "timestamp": timestamp,
                    "client_hello_pkt": binascii.hexlify(tcp.data).decode('utf-8')}
            results.append(record)

        return results #o

def load():
	return generateJA3fpFromPCAPs()

# |========================Calls to generateJA3fpFromPCAPs()===========================|
# def main()                    # o
    """Intake arguments from the user and print out JA3 output."""
desc = "A python script for extracting JA3 fingerprints from PCAP files"
parser = argparse.ArgumentParser(description=(desc))
parser.add_argument("pcap", help="The pcap file to process")
help_text = "Look for client hellos on any port instead of just 443"
parser.add_argument("-a", "--any_port", required=False,
                    action="store_true", default=False,
                    help=help_text)
help_text = "Print out as JSON records for downstream parsing"
parser.add_argument("-j", "--json", required=False, action="store_true",
                    default=False, help=help_text)
help_text = "Print packet related data for research (json only)"
parser.add_argument("-r", "--research", required=False, action="store_true",
                    default=False, help=help_text)
args = parser.parse_args()

# Use an iterator to process each line of the file
output = None
with open(args.pcap, 'rb') as fp:
    try:
        capture = dpkt.pcap.Reader(fp)
    except ValueError as e_pcap:
        try:
            fp.seek(0, os.SEEK_SET)
            capture = dpkt.pcapng.Reader(fp)
        except ValueError as e_pcapng:
            raise Exception(
                    "File doesn't appear to be a PCAP or PCAPng: %s, %s" %
                    (e_pcap, e_pcapng))
        output = process_pcap(capture, any_port=args.any_port)

if args.json:
    if not args.research:
        def remove_items(x):
            del x['client_hello_pkt']
        list(map(remove_items,output))
    output = json.dumps(output, indent=4, sort_keys=True)
    print(output)
else:
    for record in output:
        tmp = '[{dest}:{port}] JA3: {segment} --> {digest}'
        tmp = tmp.format(dest=record['destination_ip'],
            port=record['destination_port'],
            segment=record['ja3'],
            digest=record['ja3_digest'])
        print(tmp)

# if __name__ == "__main__":            #o
#        main()                         #o

    def load():
	    return generateJA3fpsFromPCAPs()

# |==========END CALLS to Generate JA3 fingerprints from PCAPs using Python===========|

# |////////////// END   https://github.com/salesforce/ja3/blob/master/python/ja3.py ////////////////////////////|	




#                                       MAIN() FROM:
# /Users/thomasperez/5540Smr22Team/GroupProject1/phoca/probes/tls_prober/pytls/server.py
def main():
    options = OptionParser(usage='%prog server [options]',
                            description='Test for Python SSL')
    options.add_option('-p', '--port',
                        type='int', default=4433,
                        help='TCP port to listen on (default: 4433)')
    options.add_option('-d', '--debug', action='store_true', dest='debug',
                        default=False,
                         help='Print debugging messages')

    opts, args = options.parse_args()

    if opts.debug:
        logging.basicConfig(level=logging.DEBUG)
 
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    print('Binding...')
    s.bind(('0.0.0.0', opts.port))

    s.listen(1)
    while True:
        conn, addr = s.accept()
        print('Connection from', addr)
        f = conn.makefile('rw', 0)
        f = LoggedFile(f)
        read_hello(f)

if __name__ == '__main__':
    main()



#=============================| QUICK NOTES    |
'''
ja3 -> https://github.com/salesforce/ja3/blob/master/README.md ->
  decimal values of the bytes for the following fields in the Client Hello packet; SSL Version, Accepted Ciphers, List of Extensions, 
  Elliptic Curves, and Elliptic Curve Formats. It then concatenates those values together in order, using a "," to delimit each field and a "-" to 
  delimit each value in each field.
  
  SSLVersion,Cipher,SSLExtension,EllipticCurve,EllipticCurvePointFormat
  EG//
  769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0 --> ada70206e40642a3e4461f35503241d5
769,4-5-10-9-100-98-3-6-19-18-99,,, --> de350869b8c85de67a350c8d186f11e6
    
((( Fields in the Client Hello packet can alternatively be for us; (at least) :
c_csuites
c_curves
s_ip
tcp_rtt 
...
)))

GREASE is :
Generate Random Extensions And Sustain Extensibility). Google uses this as a mechanism to prevent extensibility failures in the TLS ecosystem. 
JA3 ignores these values completely to ensure that programs utilizing GREASE can still be identified with a single JA3 hash.
'''
#=============================| END QUICK NOTES|





