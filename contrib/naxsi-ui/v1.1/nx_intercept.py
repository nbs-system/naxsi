#!/usr/bin/env python
from twisted.web import http
from twisted.internet import protocol
from twisted.internet import reactor
import pprint
import socket
from nx_parser import signature_parser
import MySQLConnector
import MySQLdb
import getopt
import sys

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
        self.db = MySQLConnector.MySQLConnector().connect()
        if self.db is None:
            raise ValueError("Cannot connect to db.")
        self.cursor = self.db.cursor()
        if self.cursor is None:
            raise ValueError("Cannot connect to db.")
        sig = self.getHeader("naxsi_sig")
        if sig is None:
            print "no naxsi_sig header."
            self.finish()
            return
        parser = signature_parser(self.cursor)
        args['Cookie'] = self.getHeader('Cookie')
        args['Referer'] = self.getHeader('Referer')
        url = sig.split('&uri=')[1].split('&')[0]
        parser.sig_to_db(method + ' ' + url + ' ' + ','.join([x + ' : ' + str(args.get(x, 'No Value !')) for x in args.keys()]), sig)
        self.db.close()
        self.finish()

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
        cursor.execute("INSERT INTO http_monitor (peer_ip, md5) VALUES ('%s', '%s')" % (ip, md5))
        return
    if md5 is not None:
        cursor.execute("INSERT INTO http_monitor (md5) VALUES ('%s')" % (md5))
        return
    if ip is not None:
        cursor.execute("INSERT INTO http_monitor (peer_ip) VALUES ('%s')" % (ip))
        return

if __name__ == '__main__':
    port = 8000
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'hp:a:', ['help', 'port', 'add-monitoring'])
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
        if o in ('-a', '--add-monitoring'):
            add_monitoring(a)
            exit(42)

    reactor.listenTCP(port, InterceptFactory())
    reactor.run()
