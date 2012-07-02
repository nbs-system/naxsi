#!/usr/bin/env python

from ConfigParser import ConfigParser
import os

class SQLWrapperException(Exception):
    pass

class SQLWrapper(object):    
    def __init__(self, config_file):
        try:
            fd = open(config_file)
        except IOError:
            raise SQLWrapperException('Cannot open config file %s' % config_file)
        self.conf = ConfigParser()
        self.conf.readfp(fd)
        self.dbtype = self.get_config('dbtype')
        if self.dbtype == 'sqlite':
            self.DBManager = __import__('sqlite3')
        elif self.dbtype == 'mysql':
            self.DBManager = __import__('MySQLdb')
        else:
            raise SQLWrapperException('Unhandled db type : %s' % self.get_config('dbtype'))
        if self.dbtype == 'mysql':
            self.user = self.get_config('username')
            self.host = self.get_config('hostname')
            self.password = self.get_config('password')
        self.dbname = self.get_config('dbname')

    def get_config(self, key):
        return self.conf.get('sql', key)

    def connect(self):
        if self.dbtype == 'mysql':
            self.__conn = self.DBManager.connect(self.host, self.user, self.password, self.dbname)
        else:
            self.__conn = self.DBManager.connect(self.dbname)
            self.__conn.row_factory = self.DBManager.Row
            self.__conn.text_factory = str  # to avoid problems with encoding
        self.__cursor = self.__conn.cursor()

    def setRowToDict(self):
        if self.dbtype == 'sqlite3':
            self.__conn.row_factory = self.DBManager.Row
        elif self.dbtype == 'mysql':
            self.__cursor = self.__conn.cursor(self.DBManager.cursors.DictCursor)

    def execute(self, query, args = None):
        if args is None:
            self.__cursor.execute(query)
        else:
            print query % args
            if self.dbtype == 'sqlite':
                query = query.replace('%s', '?') #hmmmm....
            self.__cursor.execute(query, args)
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
            self.__cursor.select_db(dbname)


    def create_all_tables(self):
        if self.dbtype == 'mysql':
            self.execute("CREATE TABLE rules (rule_id integer "
                                 "auto_increment primary key "
                                 ", action TEXT, msg TEXT, rx TEXT, "
                                 "rx_type INT, url TEXT, "
                                 "zone TEXT, arg_name TEXT, INDEX id (rule_id));")
            self.execute("CREATE TABLE connections (connection_id INTEGER "
                                 "auto_increment primary key, "
                                 "src_peer_id INT, dst_peer_id INT, exception_id "
                                 "INT, capture_id INT, date TIMESTAMP default "
                                 "CURRENT_TIMESTAMP, match_id INT, INDEX id (connection_id, exception_id, src_peer_id, dst_peer_id));")        
            self.execute("CREATE TABLE peer (peer_id INTEGER "
                                 "auto_increment primary key, "
                                 "peer_ip TEXT, peer_host TEXT, peer_tags TEXT, INDEX id (peer_id));")                
            self.execute("CREATE TABLE exception (exception_id integer "
                                 "auto_increment primary key "
                                 ",url TEXT, md5 TEXT, count INT default 1, INDEX id (exception_id));")
            self.execute("CREATE TABLE match_zone (match_id INTEGER "
                                 "auto_increment primary key, exception_id INTEGER, "
                                 "zone TEXT, arg_name TEXT, rule_id INTEGER, INDEX id (match_id, exception_id, rule_id));")
            self.execute("CREATE TABLE capture (capture_id INTEGER "
                                 "auto_increment primary key, http_request TEXT, "
                                 "exception_id INTEGER);")
            self.execute("CREATE TABLE http_monitor (id INTEGER auto_increment primary key, peer_ip TEXT, md5 TEXT)")
        elif self.dbtype == 'sqlite':
            self.execute("CREATE TABLE rules (rule_id integer"
                         " primary key "
                         ", action TEXT, msg TEXT, rx TEXT, "
                         "rx_type INT, url TEXT, "
                         "zone TEXT, arg_name TEXT);")
            self.execute("CREATE INDEX r_id ON rules (rule_id);")
            self.execute("CREATE TABLE connections (connection_id INTEGER "
                         " primary key, "
                         "src_peer_id INT, dst_peer_id INT, exception_id "
                         "INT, capture_id INT, date TIMESTAMP default "
                         "CURRENT_TIMESTAMP, match_id INT);")
            self.execute("CREATE INDEX conn_id ON connections (connection_id, exception_id, src_peer_id, dst_peer_id)")
            self.execute("CREATE TABLE peer (peer_id INTEGER "
                                 " primary key, "
                                 "peer_ip TEXT, peer_host TEXT, peer_tags TEXT);")
            self.execute("CREATE INDEX p_id on peer(peer_id)")
            self.execute("CREATE TABLE exception (exception_id integer "
                                 "primary key "
                                 ",url TEXT, md5 TEXT, count INT default 1);")
            self.execute("CREATE INDEX ex_id on exception (exception_id)")
            self.execute("CREATE TABLE match_zone (match_id INTEGER "
                                 "primary key, exception_id INTEGER, "
                                 "zone TEXT, arg_name TEXT, rule_id INTEGER);")
            self.execute("CREATE INDEX m_id ON match_zone(match_id, exception_id, rule_id)")
            self.execute("CREATE TABLE capture (capture_id INTEGER "
                                 "primary key, http_request TEXT, "
                                 "exception_id INTEGER);")
            self.execute("CREATE TABLE http_monitor (id INTEGER  primary key, peer_ip TEXT, md5 TEXT)")


    def getWhitelist(self):
        if self.dbtype == 'sqlite':
            self.execute("""select exception.exception_id as id, exception.md5 as md5, exception.url as url, exception.count as count, GROUP_CONCAT(distinct "mz:" || match_zone.rule_id || ":" || "$" || match_zone.zone ||  "_VAR:" ||  match_zone.arg_name) as match_zones from exception LEFT JOIN match_zone on (match_zone.exception_id = exception.exception_id) GROUP BY id;""")
            return self.getResults()
        elif self.dbtype == 'mysql':
            self.execute("""select exception.exception_id as id, exception.md5 as md5, exception.url as url, exception.count as count, GROUP_CONCAT(distinct "mz:" , match_zone.rule_id , ":" , "$" , match_zone.zone ,  "_VAR:" ,  match_zone.arg_name) as match_zones from exception LEFT JOIN match_zone on (match_zone.exception_id = exception.exception_id) GROUP BY id;""")            
        return self.getResults()
