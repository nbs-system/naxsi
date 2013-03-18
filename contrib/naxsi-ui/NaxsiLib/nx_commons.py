import logging
from os import getpid
from os import fork, setsid, umask, dup2
from sys import stdin, stdout, stderr

class nxlogger(object):
    def __init__(self, lfile, name, lformat=' %(asctime)-15s %(message)s'):
        logging.basicConfig(format=name+lformat, filename=lfile, name=name)
    def warning(self, message):
        logging.warning(message)
    def error(self, message):
        logging.error(message)
    def info(self, message):
        logging.info(message)
    def critical(self, message):
        logging.critical(message)




class nxdaemonizer(object):
    def __init__(self, pid_file):
        self.pid_file = pid_file
    def write_pid(self):
        outfile = open(self.pid_file, 'w')
        outfile.write('%i' % getpid())
        outfile.close()
    def daemonize(self):
        if fork(): exit(0)
        umask(0) 
        setsid() 
        if fork(): exit(0)
        stdout.flush()
        stderr.flush()
        si = file('/dev/null', 'r')
        so = file('/dev/null', 'a+')
        se = file('/dev/null', 'a+', 0)
        dup2(si.fileno(), stdin.fileno())
        dup2(so.fileno(), stdout.fileno())
        dup2(se.fileno(), stderr.fileno())
        
