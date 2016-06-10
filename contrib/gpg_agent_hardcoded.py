#!/usr/bin/env python
from __future__ import print_function
import os
import signal
import socket
import sys


class Timeout(object):
    def __init__(self, seconds):
        self.seconds = seconds

    def handler(self, signum, frame):
        pass

    def __enter__(self):
        signal.signal(signal.SIGALRM, self.handler)
        signal.alarm(self.seconds)

    def __exit__(self, *args, **kwargs):
        signal.alarm(0)


def handle(conn):
    conn.send('OK\n')
    while True:
        data = conn.recv(4096)
        if data.startswith('BYE'):
            break
        elif data.startswith('GET_PASSPHRASE '):
            sys.stderr.write('DEBUG: %r\n' % (data,))
            conn.send('OK 6861726D32\n')
        else:
            conn.send('OK\n')


sockpath = sys.argv[1]
try:
    os.unlink(sockpath)
except OSError:
    pass
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.bind(sockpath)
sock.listen(100)

while True:
    sys.stderr.write('DEBUG: waiting for new conn\n')
    conn, peeraddr = sock.accept()
    sys.stderr.write('DEBUG: accepted conn\n')

    try:
        with Timeout(1):
            handle(conn)
    except Exception as e:
        sys.stderr.write('ERR: conn failure: %s\n' % (e,))
    try:
        conn.close()
    except Exception as e:
        sys.stderr.write('ERR: close failure: %s\n' % (e,))
