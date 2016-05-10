#!/usr/bin/env python

import configparser
import os
import re
import signal
import socket
import subprocess
import sys
import threading

from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from time import sleep

config = configparser.ConfigParser()

# Escape codes
red   = '\033[1;31m'
blue  = '\033[1;34m'
green = '\033[1;32m'
nc    = '\033[1;m'
begin = '\033[80D'


class httpRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type','text/html')
        self.end_headers()

        message = execute(self.path, 'HTTP', self.client_address[0])
        if not message:
            return
        self.wfile.write(message)
        return

    def log_request(handler, code):
        return

    def log_message(handler, fmt, code, error):
        print('  [ %sHTTP%s ] %sERROR %s%s: %s' % (blue, nc, red, int(code), nc, error))
        return


def serve_udp():
    print('Starting %sUDP%s  server on %s:%s ... ' % (green, nc, config['host']['bind'], config['ports']['udp']), end="")
    # Create UDP socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        #s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((config['host']['bind'], int(config['ports']['udp'])))
    except socket.error:
        print ('Failed to create UDP socket')
        sys.exit(1)
    print('Ready!')

    while True:
        #(cs, addr) = s.accept()
        #data = cs.recv(1024).decode()
        data, addr = s.recvfrom(1024)
        message = execute(data.decode('utf-8'), 'UDP', addr[0])
        if not message:
            continue
        #print(dir(s))
        #print(dir(s.send))
        #print(addr)
        #print(type(addr[0]))
        #s.send(message, int(addr[0]))
        s.sendto(message, addr)
        #print(message)


def serve_http():
    print('Starting %sHTTP%s server on %s:%s ... ' % (blue, nc, config['host']['bind'], config['ports']['http']), end="")
    httpd = HTTPServer((config['host']['bind'], int(config['ports']['http'])), httpRequestHandler)
    print('Ready!')
    httpd.serve_forever()


def parse_cmd(path, split_char='/', split_shift=0):
    ps=path.split(split_char)

    function = check_function(ps[split_shift])
    if not function:
        return False

    return ps[split_shift:]


def check_function(function):
    if len(function) <= 0:
        return False

    pattern = re.compile("^[a-z][a-z0-9_-]*$")
    if not pattern.match(function):
        return False
    return function


def signal_handler(signal, frame):
    # Need to move cursor to beginning to omit '^C'
    print('%sStopping program...' % begin)
    #sys.exit(0)
    os._exit(0)


def execute(cmd, proto, addr):
    # TODO Check cmd
    #print(list(config['commands'].items()))
    #for i in config['commands'].items():
    #    print(i)

    if proto == "UDP":
        protoc = green
        pcmd = parse_cmd(cmd, split_char=';')
    else:
        protoc = blue
        pcmd = parse_cmd(cmd, split_shift=1)

    if not pcmd:
        return False

    pret = ''
    for p in pcmd[1:]:
        pret += "\"%s\"" % p
        if p != pcmd[-1]:
            pret += ", "
    lcmd = "%s(%s)" % (pcmd[0], pret)

    if not cmd:
        print('  [ %s%4s%s ] %sERROR%s: Request malformed: %s' % (protoc, proto, nc, red, nc, lcmd))
    else:
        print('  [ %s%4s%s ] %13s %s' % (protoc, proto, nc, addr, lcmd))

    ret = "ERROR"
    error = None
    subret = None
    try:
        subret = subprocess.run(pcmd, stdout=subprocess.PIPE, check=True)
    except subprocess.CalledProcessError as e:
        error = 'Command %s exited with return code %s:\n           STDOUT: %s\n           STDERR: %s' % (lcmd, e.returncode, e.stdout, e.stderr)
    except FileNotFoundError as e:
        error = 'Command "%s" not found' % pcmd[0]

    if error is not None:
        print('  [ %s%4s%s ] %sERROR%s: %s' % (protoc, proto, nc, red, nc, error))

    if subret is not None:
        return subret.stdout
    else:
        return False


def main():
    if len(sys.argv) > 1:
        config_file = sys.argv[1]
    else:
        config_file = '~/.config/network-slave/config'

    if not os.path.exists(config_file):
        sys.exit('%sERROR%s: Config file not found "%s"' % (red, nc, config_file))

    config.read(config_file)

    thread_http = threading.Thread(target=serve_http)
    thread_http.start()
    sleep(.1)

    thread_udp = threading.Thread(target=serve_udp)
    thread_udp.start()
    sleep(.1)

    # Catch Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)
    print('Press Ctrl+C to end\n')
    signal.pause()


if __name__ == "__main__":
    main()
