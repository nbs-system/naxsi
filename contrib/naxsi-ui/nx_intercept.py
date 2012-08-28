#!/usr/bin/env python
from twisted.web import http
from twisted.internet import protocol
from twisted.internet import reactor, threads
from ConfigParser import ConfigParser

#nx* imports
from NaxsiLib.nx_parser import signature_parser
from NaxsiLib.ordereddict import OrderedDict
from NaxsiLib.nx_commons import nxlogger
from NaxsiLib.nx_commons import nxdaemonizer
from NaxsiLib.SQLWrapper import SQLWrapper

import urllib
import pprint
import socket
import getopt
import sys
import re

conf_path = ''

class InterceptHandler(http.Request):
    def process(self):
        self.setResponseCode(418)
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
            log.critical("Received a request without naxsi_sig header, IGNORED.")
            self.finish()
            return
        url = sig.split('&uri=')[1].split('&')[0]
        log.warning("+ "+url)
        fullstr = method + ' ' + url + ' ' + ','.join([x + ' : ' + str(args.get(x, 'No Value !')) for x in args.keys()])
        threads.deferToThread(self.background, fullstr, sig)
        self.finish()
        return

    def background(self, fullstr, sig):
        wrapper = SQLWrapper(conf_path, log)
        wrapper.connect()
        parser = signature_parser(wrapper, log, monitor_tab)
        #parser.wrapper.StartInsert()
        parser.sig_to_db(fullstr, sig, learning=learning_mode)
        parser.wrapper.StopInsert()
#        parser.wrapper.close()

class InterceptProtocol(http.HTTPChannel):
    requestFactory = InterceptHandler

class InterceptFactory(http.HTTPFactory):
    protocol = InterceptProtocol


def usage():
    print 'Usage: python nx_intercept -c /path/to/conf/file [-h] [-l] '
    print '[-c, --conf-file /path/to/conf/file]'
    print '\tMandatory, nx_intercept configuration file.'
    print '[-l, --log-file /path/to/nginx_error.log]'
    print '\tPerform learning from nginx error log rather than live capture.'
    print "\tIn this mode, nx_intercept will exit after finished log file processing."
    print "[-n : Don't demonize]"


def fill_db(files, conf_path):

    wrapper = SQLWrapper(conf_path, log)
    wrapper.connect()
    sig = ''
    count = 0

    if re.match("[a-z0-9]+$", wrapper.dbname) == False:
        log.critial("Invalid dbname : "+wrapper.dbname)
        sys.exit(-1)
    
    wrapper.drop_database()
    wrapper.create_db()
    
    wrapper.select_db(wrapper.dbname)
    #wrapper.exec()
    
    log.critical("Filling db with %s (TABLES WILL BE DROPPED !)" %  ' '.join(files))
    parser = signature_parser(wrapper, log, None)
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
                    parser.sig_to_db(fullstr, sig, date=date, learning=learning_mode)
                    count += 1
    print(str(count)+" exceptions stored into database.")
    log.warning(str(count)+" exceptions stored into database.")
    parser.wrapper.StopInsert()


if __name__ == '__main__':
#    global log
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'c:hl:n', ['conf-file', 'help', 'log-file', ''])
    except getopt.GetoptError, err:
        print str(err)
        usage()
        sys.exit(-1)

    has_conf = False
    logs_path = []
    daemonize = True

    for o, a in opts:
        if o in ('-h', '--help'):
            usage()
            sys.exit(0)
        if o in ('-l', '--log-file'):
            if has_conf is False:
                print "Conf File must be specified first !"
                sys.exit(-1)
            logs_path.append(a)
        if o in ('-c', '--conf-file'):
            has_conf = True
            conf_path = a
        if o in ('-n'):
            daemonize = False

    if has_conf is False:
        usage()
        sys.exit(-1)

    try:
        fd = open(conf_path, 'r')     
    except:
        print "Unable to open conf file :"+conf_path
        sys.exit(-1)
        
    conf = ConfigParser()
    conf.readfp(fd)
    
    try:
        port = int(conf.get('nx_intercept', 'port'))
    except:
        print "No port in conf file ! Using default port (8080)"
        port = 8080

    try:
        learning_mode = int(conf.get('nx_intercept', 'learning_mode'))
    except:
        learning_mode = 1

    try:
        iface = conf.get('nx_intercept', 'interface')
    except:
        iface = ''
       
    try:
        pid_path = conf.get('nx_intercept', 'pid_path')
    except:
        print "No pid_path in conf file ! Using /tmp/nx_intercept.pid"
        pid_path = "/tmp/nx_intercept.pid"

    try:
        monitor_path = conf.get('nx_intercept', 'monitor_path')
        monitor_tab = []
        try:
            fd = open(monitor_path)
        except:
            print "Unable to open monitor_path"
            log.critical("Unable to open monitor_path")
            sys.exit(0)
            
        for line in fd.readlines():
            monitor_tab.append(line.strip())
        fd.close()
        log.warning("Monitor enabled.")
    except:
        monitor_tab = None

    try:
        log_path = conf.get('nx_intercept', 'log_path')
    except:
        print "No log_path in conf file ! Using /tmp/nx_intercept.log"
        log_path = "/tmp/nx_intercept.log"
       
    fd.close()
    # log
    log = nxlogger(log_path, "nx_intercept")
    log.warning("Starting nx_intercept.")
    

    if len(logs_path) > 0:
        fill_db(logs_path, conf_path)
        sys.exit(0)

    try:
        reactor.listenTCP(port, InterceptFactory(), interface=iface)
        log.warning("Listening on port "+str(port)+" iface:"+iface)
    except:
        print "Unable to listen on "+str(port)
        log.critical("Unable to listen on "+str(port)+" iface:"+iface)
        sys.exit (-1)
    
    # & daemonize
    if daemonize is True:
        daemon = nxdaemonizer(pid_path)
        daemon.daemonize()
        daemon.write_pid()
    
    reactor.run()
