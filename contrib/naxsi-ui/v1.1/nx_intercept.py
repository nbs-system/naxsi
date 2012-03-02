#!/usr/bin/env python


from twisted.internet.protocol import Protocol, Factory
from twisted.internet import reactor, threads
from nx_parser import signature_parser
import syslog



class NaxsiHTTPInterceptor(Protocol):
    def dataReceived(self, data):
        sig = signature_parser("localhost", "root", "trivialpassword", "naxsi_sig")
        sig_idx = data.find("\r\nnaxsi_sig: ")
        if (sig_idx == -1):
#            syslog.syslog("unable to find naxsi_sig in HTTP request.")
            print "ERROR: request doesn't contain naxsi_sig header"
#            self.finish()
            return
        sig_idx = sig_idx + 2
        sig_end = data[sig_idx:].find("\r\n")
        if (sig_end == -1):
#            syslog.syslog("unable to find naxsi_sig in HTTP request.")
            print "ERROR: request doesn't contain naxsi_sig header"
#            self.finish()
            return
        self.finish()
        threads.deferToThread(sig.raw_parser, 
                              *(data, data[sig_idx:sig_idx+sig_end], False, 
                                True))
        return

    def finish(self):
        self.transport.write("HTTP/1.0 200 OK\r\n"
                             "Server: nx-learn\r\n"
                             "Content-Type: text/html\r\n"
                             "Content-Length: 2\r\n"
                             "Connection: close\r\n\r\n"
                             "ok")
        self.transport.loseConnection()

def main():
    f = Factory()
    f.protocol = NaxsiHTTPInterceptor
    reactor.listenTCP(8000, f)
    reactor.run()

if __name__ == '__main__':
    main()

