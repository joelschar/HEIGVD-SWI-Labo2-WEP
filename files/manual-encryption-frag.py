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
import math

defmorefrag = 0x004
undefmorefrag = 0xfffb

#Cle wep AA:AA:AA:AA:AA
key='\xaa\xaa\xaa\xaa\xaa'

arp = rdpcap('arp.cap')[0]

# creaate longue message
message = "A new message ! A new message ! A nrA new message ! A new message ! A nrA new message ! A new message ! A nr"

# get the length of message
messagelen= len(message)

# calcul number of fragment for this message
nbrFrag = int(math.ceil(messagelen / float(36)))

# for each fragment
for i in xrange(0,nbrFrag):

	# get a copy of initial arp request
	arpcur = arp

	# get the fragments
	messagefrag = message[i*36:36+(i*36)]

	# if fragment need padding we create one with '§'
	if len(messagefrag) < 36:
		messagefrag = messagefrag + '§'*(36-len(messagefrag))
	
	# specify more fragment bit
	if i != nbrFrag-1:
		arpcur.FCfield |= defmorefrag
	# last fragment so no more fragment
	else :
		arpcur.FCfield &= undefmorefrag

	# set counter of fragments
	arpcur.SC = i
	# rc4 seed est composé de IV+clé
	seed = arpcur.iv+key

	# create the icv
	icv = struct.pack('<l', binascii.crc32(messagefrag))
	
	# plaintext = message and icv
	plaintext = messagefrag + icv
	print(plaintext)
	# encrypt plaintext
	message_crypted=rc4.rc4crypt(plaintext, seed)

	# set data
	arpcur.wepdata = message_crypted[:-4]
	# set icv
	icv = struct.unpack('!L', message_crypted[-4:])[0]
	arpcur.icv = icv

	arpcur.show()
	print arpcur.FCfield

	# store all the fragments
	wrpcap("encrypt-frag.cap", arpcur, append=True)
