import MySQLdb

class MySQLConnector(object):
    def __init__(self, filename = './sql_id'):
        try:
            fd = open(filename, 'r')
        except:
            print 'Cannot open file %s' % filename
        for i in fd:
            if i.startswith('user='):
                self.user = i[5:].strip()
            if i.startswith('pass='):
                self.password = i[5:].strip()
            if i.startswith('host='):
                self.host = i[5:].strip()
            if i.startswith('name='):
                self.dbname = i[5:].strip()

    def connect(self):
        return MySQLdb.connect(self.host, self.user, self.password, self.dbname)
