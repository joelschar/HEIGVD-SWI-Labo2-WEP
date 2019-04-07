#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Manually decrypt a wep message given the WEP key"""

__author__      = "Abraham Rubinstein"
__copyright__   = "Copyright 2017, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "abraham.rubinstein@heig-vd.ch"
__status__ 		= "Prototype"

from scapy.all import *
import binascii
import rc4
#Cle wep AA:AA:AA:AA:AA
key='\xaa\xaa\xaa\xaa\xaa'

arp = rdpcap('arp.cap')[0]
# rc4 seed est composé de IV+clé
seed = arp.iv+key
#message with 36 chars
message = "A new message ! A new message ! A nr"

# create the ICV
icv = struct.pack('<l', binascii.crc32(message))
# concat message and icv
plaintext = message + icv

print(plaintext)

# encrypt the plaintext
message_crypted=rc4.rc4crypt(plaintext, seed)

# set the data
arp.wepdata =message_crypted[:-4]
# set the icv
icv = struct.unpack('!L', message_crypted[-4:])[0]
arp.icv = icv

arp.show()
# store new request
wrpcap("encrypt.cap", arp)
