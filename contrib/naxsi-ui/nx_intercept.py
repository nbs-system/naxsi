#!/usr/bin/env python
from twisted.web import http
from twisted.internet import protocol
from twisted.internet import reactor, threads
from ConfigParser import ConfigParser
from nx_parser import signature_parser

import urllib
import pprint
import socket
import MySQLConnector
import MySQLdb
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
        if sig is None:
            print "no naxsi_sig header."
            return
        url = sig.split('&uri=')[1].split('&')[0]
        fullstr = method + ' ' + url + ' ' + ','.join([x + ' : ' + str(args.get(x, 'No Value !')) for x in args.keys()])
        threads.deferToThread(self.background, fullstr, sig)
        self.finish()
        return

    def background(self, fullstr, sig):
        self.db = MySQLConnector.MySQLConnector(filename = conf_path).connect()
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
    print 'Usage: python nx_intercept [-h,--help]  [-a,--add-monitoring ip:1.2.3.4|md5:af794f5e532d7a4fa59c49845af7947e] [-q,--quiet] [-l,--log-file /path/to/logfile] [-c, --conf-file naxsi-ui-learning.conf] '

def add_monitoring(arg, conf_path):
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
    db = MySQLConnector.MySQLConnector(conf_path).connect()
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

def fill_db(files, conf_path):

    mysqlh = MySQLConnector.MySQLConnector(conf_path)
    db = mysqlh.connect()
    sig = ''

    if db is None:
        raise ValueError('Cannot connect to db')
    cursor = db.cursor()
    if cursor is None:
        raise ValueError('Cannot connect to db')

    if re.match("[a-z0-9]+$", mysqlh.dbname) == False:        
        print 'bad db name :)'
        exit(-2)
    
    cursor.execute("DROP DATABASE IF EXISTS %s;" % mysqlh.dbname)
    cursor.execute("CREATE DATABASE %s;" %  mysqlh.dbname)
    db.select_db(mysqlh.dbname)
    
    print "Filling db with %s (TABLES WILL BE DROPPED !)" %  ' '.join(files)

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
        #            print 'args are ', request_args
                    if request_args:
                        fullstr = request_args['request'][2:-1] + ' Referer : ' + request_args.get('referrer', ' "None"')[2:-1].strip('"\n') + ',Cookie : ' + request_args.get('cookie', ' "None"')[2:-1]
                if sig != ''  and fullstr != '':
        #            print "adding %s (%s) " % (sig, fullstr)
                    parser = signature_parser(cursor)
                    parser.sig_to_db(fullstr, sig, date=date)
    db.close()


if __name__ == '__main__':
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'c:ha:l:', ['conf-file', 'help', 'add-monitoring', 'log-file'])
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
