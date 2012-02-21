#!/usr/bin/env python

# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.

from twisted.internet.protocol import Protocol, Factory
from twisted.internet import reactor, threads
from nx_parser import signature_parser
import syslog
#import threading
### Protocol Implementation



# This is just about the simplest possible protocol
class NaxsiHTTPInterceptor(Protocol):
    def dataReceived(self, data):
        """
        HTTP request from learning mode might be received here :)
        """
#        print str(threading.currentThread().name)+"\n"
        sig = signature_parser("localhost", "root", "trivialpassword", "naxsi_sig")
        sig_idx = data.find("\r\nnaxsi_sig: ")
        if (sig_idx == -1):
            print "ERROR: request doesn't contain naxis_sig header"
            print data+"\n---\n"
            self.finish()
            return
        sig_idx = sig_idx + 2
        sig_end = data[sig_idx:].find("\r\n")
        if (sig_end == -1):
            print "ERROR: request doesn't contain naxsi_sig header"
            print data+"\n---\n"
            self.finish()
            return
        self.finish()
        threads.deferToThread(sig.raw_parser, *(data, data[sig_idx:sig_idx+sig_end]))
        #sig.raw_parser(data[sig_idx:sig_idx+sig_end], is_from_http=True)
        return
    def finish(self):
        self.transport.write("HTTP/1.0 200 OK\r\n"
                             "Server: nx-learn\r\n"
                             "Content-Type: text/html\r\n"
                             "Content-Length: 2\r\n"
                             "Connection: close\r\n\r\n"
                             "ok")
#        print ">"
        self.transport.loseConnection()
#        self.transport.close()


def main():
    f = Factory()
    f.protocol = NaxsiHTTPInterceptor
    reactor.listenTCP(8000, f)
#    reactor.suggestThreadPoolSize(30)
#    d = threads.deferToThread(doLongCalculation, 4)
#    d.addCallback(printResult)    
    reactor.run()

if __name__ == '__main__':
    main()

