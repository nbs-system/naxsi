import MySQLdb

from ConfigParser import ConfigParser

class MySQLConnectorException(Exception)
    pass

class MySQLConnector(object):
    section_name = 'mysql'
    def __init__(self, filename = 'naxsi-ui.conf'):
        try:
            fd = open(filename, 'r')
        except:
            raise MySQLConnectorException('Cannot open file %s' % filename)
        self.conf = ConfigParser()
        self.conf.readfp(fd)
        self.user = self.get_config('username')
        self.host = self.get_config('hostname')
        self.password = self.get_config('password')
        self.dbname = self.get_config('dbname')

    def get_config(self, key):
        return self.conf.get(self.__class__.section_name, key)

    def connect(self):
        return MySQLdb.connect(self.host, self.user, self.password, self.dbname)
