#!/usr/bin/env python
from twisted.web import http
from twisted.internet import protocol
from twisted.internet import reactor, threads
import urllib
import pprint
import socket
from nx_parser import signature_parser
import MySQLConnector
import MySQLdb
import getopt
import sys

quiet=False

class InterceptHandler(http.Request):
    def process(self):
        if self.getHeader('Orig_args'):
            args = {'GET' : self.getHeader('Orig_args')}
            method = 'GET'
        elif self.args:
            args = {'POST': self.args}
            method = 'POST'
        else:
            method = 'GET'
            args = {}
        args['Cookie'] = self.getHeader('Cookie')
        args['Referer'] = self.getHeader('Referer')
        sig = self.getHeader("naxsi_sig")
        if sig is None:
            print "no naxsi_sig header."
            return
        url = sig.split('&uri=')[1].split('&')[0]
        fullstr = method + ' ' + url + ' ' + ','.join([x + ' : ' + str(args.get(x, 'No Value !')) for x in args.keys()])
        threads.deferToThread(self.background, fullstr, sig)
        self.finish()
        return
    def background(self, fullstr, sig):
        self.db = MySQLConnector.MySQLConnector().connect()
        if self.db is None:
            raise ValueError("Cannot connect to db.")
        self.cursor = self.db.cursor()
        if self.cursor is None:
            raise ValueError("Cannot connect to db.")
        parser = signature_parser(self.cursor)
        parser.sig_to_db(fullstr, sig)
        self.db.close()

class InterceptProtocol(http.HTTPChannel):
    requestFactory = InterceptHandler

class InterceptFactory(http.HTTPFactory):
    protocol = InterceptProtocol

def usage():
    print 'Usage: python nx_intercept [-h,--help] [-p,--port portnumber] [-a,--add-monitoring ip:1.2.3.4|md5:af794f5e532d7a4fa59c49845af7947e]'

def add_monitoring(arg):
    l = arg.split('|')
    ip = None
    md5 = None
    for i in l:
        if i.startswith('ip:'):
            ip = i[3:]
        elif i.startswith('md5:'):
            md5 = i[4:]
    if md5 is not None and len(md5) != 32:
        print 'md5 is not valid ! Nothing will be inserted in db !'
        return
    if ip is not None:
        try:
            socket.inet_aton(ip)
        except socket.error:
            print 'ip is not valid ! Nothing will be inserted in db !'
            return
    db = MySQLConnector.MySQLConnector().connect()
    cursor = db.cursor()
    if md5 is not None and ip is not None:
        cursor.execute("INSERT INTO http_monitor (peer_ip, md5) VALUES (%s, %s)", (ip, md5))
        return
    if md5 is not None:
        cursor.execute("INSERT INTO http_monitor (md5) VALUES (%s)", (md5))
        return
    if ip is not None:
        cursor.execute("INSERT INTO http_monitor (peer_ip) VALUES (%s)", (ip))
        return

def fill_db(filename):
    fd = open(filename, 'r')
    db = MySQLConnector.MySQLConnector().connect()
    sig = ''

    if db is None:
        raise ValueError('Cannot connect to db')
    cursor = db.cursor()
    if cursor is None:
        raise ValueError('Cannot connect to db')
    for line in fd:
        fullstr = ''
        if 'NAXSI_FMT' in line:
            l = line.split(", ")
            date = ' '.join(l[0].split()[:2])
            sig = l[0].split('NAXSI_FMT:')[1][1:]
            l = l[1:]
            request_args = {}
            for i in l:
                s = i.split(':')
                request_args[s[0]] = urllib.unquote(''.join(s[1:]))
#            print 'args are ', request_args
            if request_args:
                fullstr = request_args['request'][2:-1] + ' Referer : ' + request_args.get('referrer', ' "None"')[2:-1].strip('"\n') + ',Cookie : ' + request_args.get('cookie', ' "None"')[2:-1]
        if sig != ''  and fullstr != '':
#            print "adding %s (%s) " % (sig, fullstr)
            parser = signature_parser(cursor)
            parser.sig_to_db(fullstr, sig, date=date)
    db.close()


if __name__ == '__main__':
#    global quiet
    port = 8000
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'qhp:a:l:', ['quiet','help', 'port', 'add-monitoring', 'log-file', ])
    except getopt.GetoptError, err:
        print str(err)
        usage()
        sys.exit(42)

    for o, a in opts:
        if o in ('-h', '--help'):
            usage()
            sys.exit(0)
        if o in ('-p', '--port'):
            port = int(a)
        if o in ('-q', '--quiet'):
            quiet = True
        if o in ('-a', '--add-monitoring'):
            add_monitoring(a)
            exit(42)
        if o in ('-l', '--log-file'):
            fill_db(a)
            exit(42)

    reactor.listenTCP(port, InterceptFactory())
    reactor.run()
