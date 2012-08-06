#!/usr/bin/env python
from twisted.web import http
from twisted.internet import protocol
from twisted.internet import reactor, threads
from ConfigParser import ConfigParser
from nx_parser import signature_parser

import urllib
import pprint
import socket
import SQLWrapper
import getopt
import sys
import re

conf_path = ''

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
        print self
        if sig is None:
            print "no naxsi_sig header ?"
            print self
            self.finish()
            return
        url = sig.split('&uri=')[1].split('&')[0]
        print "+ "+url
        fullstr = method + ' ' + url + ' ' + ','.join([x + ' : ' + str(args.get(x, 'No Value !')) for x in args.keys()])
        threads.deferToThread(self.background, fullstr, sig)
        self.finish()
        return

    def background(self, fullstr, sig):
        wrapper = SQLWrapper.SQLWrapper(conf_path)
        wrapper.connect()
        parser = signature_parser(wrapper)
        parser.wrapper.StartInsert()
        parser.sig_to_db(fullstr, sig)
        parser.wrapper.StopInsert()
#        parser.wrapper.close()

class InterceptProtocol(http.HTTPChannel):
    requestFactory = InterceptHandler

class InterceptFactory(http.HTTPFactory):
    protocol = InterceptProtocol


def usage():
    print 'Usage: python nx_intercept [-h,--help]  [-q,--quiet] [-l,--log-file /path/to/logfile] [-c, --conf-file naxsi-ui-learning.conf] '



def fill_db(files, conf_path):

    wrapper = SQLWrapper.SQLWrapper(conf_path)
    wrapper.connect()
    sig = ''


    if re.match("[a-z0-9]+$", wrapper.dbname) == False:
        print 'bad db name :)'
        exit(-2)
    
    wrapper.drop_database()
    wrapper.create_db()
    
    wrapper.select_db(wrapper.dbname)
    #wrapper.exec()
    
    print "Filling db with %s (TABLES WILL BE DROPPED !)" %  ' '.join(files)
#    parser = signature_parser(wrapper)
    parser = signature_parser(wrapper)
    parser.wrapper.StartInsert()
    for filename in files:
        with open(filename, 'r') as fd:
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
                    fullstr = request_args.get('request', 'None')[2:-1] + ' Referer : ' + request_args.get('referrer', ' "None"')[2:-1].strip('"\n') + ',Cookie : ' + request_args.get('cookie', ' "None"')[2:-1]
                if sig != ''  and fullstr != '':
                    parser.sig_to_db(fullstr, sig, date=date)
    parser.wrapper.StopInsert()

if __name__ == '__main__':
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'c:hl:', ['conf-file', 'help', 'log-file'])
    except getopt.GetoptError, err:
        print str(err)
        usage()
        sys.exit(42)

    has_conf = False
    logs_path = []

    for o, a in opts:
        if o in ('-h', '--help'):
            usage()
            sys.exit(0)
        if o in ('-a', '--add-monitoring'):
            if has_conf is False:
                print "Conf File must be specified first !"
                exit(42)
            add_monitoring(a, conf_path)
            exit(42)
        if o in ('-l', '--log-file'):
            if has_conf is False:
                print "Conf File must be specified first !"
                exit(42)
            logs_path.append(a)
        if o in ('-c', '--conf-file'):
            has_conf = True
            conf_path = a

    if has_conf is False:
        print 'Conf file is mandatory !'
        exit(-42)

    if len(logs_path) > 0:
        fill_db(logs_path, conf_path)
        exit(0)

    fd = open(conf_path, 'r')     
    conf = ConfigParser()
    conf.readfp(fd)
    try:
       port = int(conf.get('nx_intercept', 'port'))
    except:
       print "No port in conf file ! Using default port (8080)"
       port = 8080
    fd.close()            

    reactor.listenTCP(port, InterceptFactory())
    reactor.run()
