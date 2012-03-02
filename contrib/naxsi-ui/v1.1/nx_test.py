#!/usr/bin/env python
from twisted.web import http
from twisted.internet import protocol
from twisted.internet import reactor
import pprint
from nx_parser import signature_parser
import MySQLdb
host="localhost"
user="root"
password="trivialpassword"
dbname="naxsi_sig"

class InterceptHandler(http.Request):
    def process(self):
        self.db = MySQLdb.connect(host, user, password, dbname)
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


if __name__ == '__main__':   

    reactor.listenTCP(8000, InterceptFactory())
    reactor.run()
