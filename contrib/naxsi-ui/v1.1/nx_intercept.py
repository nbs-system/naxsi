#!/usr/bin/env python
from twisted.web import http
from twisted.internet import protocol
from twisted.internet import reactor
import pprint
from nx_parser import signature_parser
import MySQLConnector
import MySQLdb
import getopt
import sys

class InterceptHandler(http.Request):
    def process(self):
        print '----------------------------------------------'
        if len(self.requestHeaders.getRawHeaders('Orig_args', [''])) and self.requestHeaders.getRawHeaders('Orig_args')[0]:
            print 'Get Request ! : ', self.requestHeaders.getRawHeaders('Orig_args'), ' on url ', self.path
        elif len(self.args):
            print 'Post request : ', self.args, ' on url ', self.path
        else:
            print 'no args !', ' on url ', self.path
            
        self.db = MySQLConnector.MySQLConnector().connect()
        if self.db is None:
            raise ValueError("Cannot connect to db.")
        self.cursor = self.db.cursor()
        if self.cursor is None:
            raise ValueError("Cannot connect to db.")
        sig = self.getHeader("naxsi_sig")
        if sig is None:
            print "no naxsi_sig header."
            return
        parser = signature_parser(self.cursor)
        parser.sig_to_db("", sig)
        self.db.close()
        self.finish()

class InterceptProtocol(http.HTTPChannel):
    requestFactory = InterceptHandler

class InterceptFactory(http.HTTPFactory):
    protocol = InterceptProtocol

def usage():
    print 'Usage: python nx_intercept [-h,--help] [-p,--port portnumber]'

if __name__ == '__main__':
    port = 8000
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'hp:', ['help','port'])
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
    reactor.listenTCP(port, InterceptFactory())
    reactor.run()
