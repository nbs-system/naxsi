#!/usr/bin/env python

from ConfigParser import ConfigParser
import os

class SQLWrapperException(Exception):
    pass

class SQLWrapper(object):    
    def __init__(self, config_file, log):
        self.log = log
        try:
            fd = open(config_file)
        except IOError:
            self.log.critical("Cannot open config file %s" % config_file)
            os._exit(-1)

        self.conf = ConfigParser()
        self.conf.readfp(fd)
        self.dbtype = self.get_config('dbtype')
        if self.dbtype == 'sqlite':
            self.DBManager = __import__('sqlite3')
            try:
                self.dbpath = self.get_config('data_path')
            except:
                self.dbpath = ''
            
        elif self.dbtype == 'mysql':
            self.DBManager = __import__('MySQLdb')
        else:
            self.log.critical('Unhandled db type : %s' % self.get_config('dbtype'))
            os._exit(-1)
            #raise SQLWrapperException('Unhandled db type : %s' % self.get_config('dbtype'))
    
        if self.dbtype == 'mysql':
            self.user = self.get_config('username')
            self.host = self.get_config('hostname')
            self.password = self.get_config('password')
        self.dbname = self.get_config('dbname')

    def setRowToDict(self):
        if self.dbtype == 'sqlite3':
            self.__conn.row_factory = self.DBManager.Row
        elif self.dbtype == 'mysql':
            self.__cursor = self.__conn.cursor(self.DBManager.cursors.DictCursor)

    def get_config(self, key):
        return self.conf.get('sql', key)

    def connect(self):
#        self.log.warning("Connecting to database.")
        if self.dbtype == 'mysql':
            self.log.warning( "Connecting to "+self.host+" with db "+self.dbname)
            try:
                self.__conn = self.DBManager.connect(self.host, self.user, self.password, self.dbname)
                self.__cursor = self.__conn.cursor(self.DBManager.cursors.DictCursor)
            except:
                self.log.critical("Unable to connect to database.")
                os._exit(-1)
        elif self.dbtype == 'sqlite':
#            self.log.warning( "connecting to "+self.dbname)
            try:
                self.__conn = self.DBManager.connect(self.dbpath+self.dbname)
                self.__conn.row_factory = self.DBManager.Row
                self.__conn.text_factory = str  # to avoid problems with encoding
                self.__cursor = self.__conn.cursor()
            except:
                self.log.critical("Unable to connect to database.")
                os._exit(-1)
        else:
            self.log.critical("Unknown db type.")
            os._exit(-1)

    def execute(self, query, args = None):
        if args is None:
            self.__cursor.execute(query)
        else:
            if self.dbtype == 'sqlite':
                query = query.replace('%s', '?') #hmmmm....
            self.__cursor.execute(query, args)

    def StartInsert(self):
        if self.dbtype == 'sqlite':
            self.__conn.execute("BEGIN")
    def StopInsert(self):
        if self.dbtype == 'sqlite':
            self.__conn.commit()

    def getResults(self):
        return self.__cursor.fetchall()


    def getLastId(self):
        return self.__cursor.lastrowid


    def drop_database(self):
        if self.dbtype == 'mysql':
            self.__cursor.execute("DROP DATABASE IF EXISTS %s;" % self.dbname)
        elif self.dbtype == 'sqlite':
            os.unlink(os.getcwd() + '/' + self.dbname)

    def create_db(self):
        if self.dbtype == 'mysql':
            self.__cursor.execute("CREATE DATABASE %s;" %  self.dbname)
        elif self.dbtype == 'sqlite':
            self.connect()
        

    def select_db(self, dbname):
        if self.dbtype == 'mysql':
            self.__conn.select_db(dbname)


    def create_all_tables(self):
        if self.dbtype == 'mysql':
            self.execute("CREATE TABLE connections (url_id INTEGER auto_increment, id_exception INTEGER , date TIMESTAMP default CURRENT_TIMESTAMP, peer_ip TEXT, host TEXT, primary key(url_id, id_exception))")
            self.execute("CREATE TABLE urls (url_id INTEGER auto_increment primary key, url TEXT)")
            self.execute("CREATE TABLE exceptions (exception_id INTEGER auto_increment, zone TEXT, var_name TEXT, rule_id INTEGER , primary key (exception_id, rule_id))")            
        elif self.dbtype == 'sqlite':
            self.execute("CREATE TABLE connections (url_id INTEGER, id_exception INTEGER, date TIMESTAMP default CURRENT_TIMESTAMP, peer_ip TEXT, host TEXT, primary key(url_id, id_exception))")
            self.execute("CREATE TABLE urls (url_id INTEGER primary key, url TEXT)")
            self.execute("CREATE TABLE exceptions (exception_id INTEGER PRIMARY KEY AUTOINCREMENT, zone TEXT, var_name TEXT, rule_id INTEGER)")


    def getWhitelist(self):
        self.execute('select e.exception_id as id, e.zone as zone, e.var_name as var_name, e.rule_id as rule_id, u.url as url from exceptions as e join connections as c on (c.id_exception = e.exception_id) join urls as u on (c.url_id = u.url_id)')
        return self.getResults()

    def checkDB(self):
        try:
            self.execute("SELECT 1 from exceptions")
        except:
            return False
        return True
