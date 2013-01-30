# Waiting for seb to rewrite Wrapper.
# Shamelessly imported old one :)
import logging
import os
import sqlite3


class SQLWrapperException(Exception):
    pass


class SQLSet(object):

    def __init__(self, query, connection):
        self.__query = query
        self.__connection = connection
        self.__connection.row_factory = sqlite3.Row
        self.__connection.text_factory = str

        self.__querydone = False
        self.__args = []

    def __call__(self):
        if self.__query.startswith('INSERT') or self.__query.startswith('UPDATE'):
            self.__do_query()
        return self.__cursor.lastrowid

    def __do_query(self):
        self.__querydone = True
        self.__cursor = self.__connection.cursor()
        if len(self.__args):
            self.__cursor.execute(self.__query, self.__args)
        else:
            self.__cursor.execute(self.__query)
        self.__args = []
        self.__content = self.__cursor.fetchall()
        self.__query = ''
        
    def __len__(self):
        if not self.__querydone:
            self.__do_query()
        return len(self.__content)

    def __getitem__(self, key):
        if isinstance(key, slice):
            if key.step is not None:
                raise SQLWrapperException, 'Sorry, step is not supported'
            if key.start is not None:
                start = int(key.start)
            if key.stop is not None:
                stop = int(key.stop)            
            if not self.__querydone:
                if key.start is None:
                    self.__query += ' LIMIT ' + str(stop)
                elif key.start is not None and key.stop is not None:
                    self.__query += ' LIMIT ' + str(start) + ',' + str(stop - start)
                elif start is not None:
                    self.__query += ' LIMIT ' + str(start) + ',' + '18446744073709551615'
                return self
            else:
                self.__content = self.__content[key.start:key.stop]
                return self
        if not self.__querydone:
            self.__do_query()

        ret_dict = []
        for row in self.__content:
            ret_dict.append({key: row[key]})
        return ret_dict

    def __iter__(self):
        if not self.__querydone:
            self.__do_query()
        for field in self.__content:
            yield field

    def all(self):
        return self

    def filter(self, **kwargs):
        conditions = []
        for cond in kwargs:
            if '__' not in cond:
                raise SQLWrapperException, "Invalid Syntax in where"
            field_name, cond_type = cond.split('__')
            conditions.append((field_name, cond_type, kwargs[cond],))
        if ' WHERE (' not in self.__query:
            self.__query += ' WHERE ('
        else:
            self.__query += ' AND ('
        for cond in conditions:
            self.__query += cond[0]
            if cond[1] == 'eq':
                self.__query += ' = ? AND '
            elif cond[1] == 'not':
                self.__query += ' != ? AND '
            self.__args.append(cond[2])
        self.__query = self.__query[:-4] + ')'
        return self


    def insert(self, values):
        for i in values:
            self.__args.append(i)
        return self

    def update(self, values):
        for i in values:
            self.__args.append(i)
        return self

    def execute(self, args):
        self.__args = args
        self.__do_query()
        return self


class SQLWrapper(object):
    def __init__(self, dbname = 'naxsi_sig'):
        self.__dbname = dbname
        self.__dbopen = False
        
    def __opendb(self):
        self.__connection = sqlite3.connect(self.__dbname)
        self.__dbopen = True
        self.__connection.row_factory = sqlite3.Row
        cursor = self.__connection.cursor()
        try:            
            self.execute('SELECT exception_id FROM exceptions LIMIT 1')[:1]['exception_id']
        except Exception as e:
            cursor.execute("CREATE TABLE connections (url_id INTEGER, id_exception INTEGER, date TIMESTAMP default CURRENT_TIMESTAMP, peer_ip TEXT, host TEXT, primary key(url_id, id_exception))")
            cursor.execute("CREATE TABLE urls (url_id INTEGER primary key, url TEXT)")
            cursor.execute("CREATE TABLE exceptions (exception_id INTEGER PRIMARY KEY AUTOINCREMENT, zone TEXT, var_name TEXT, rule_id INTEGER, content TEXT)")

    def __do_request(self, args):
        self.__sql = 'SELECT ' 
        for arg in args:
            self.__sql += arg + ','
        self.__sql = self.__sql[:-1]
        if self.__tablename != '':
            self.__sql += ' FROM ' + self.__tablename
               
    def get(self, *args, **kwargs):
        if kwargs.get('table'):
            self.__tablename = kwargs['table']
        else:
            self.__tablename = ''
        if self.__dbopen is False:
            self.__opendb()
        self.__do_request(args)
        return SQLSet(self.__sql, self.__connection).all()

    def insert(self, **kwargs):
        values = []
        if kwargs.get('table') is None:
            raise SQLWrapperException, 'insert need a table !'
        if self.__dbopen is False:
            self.__opendb()
        self.__sql = 'INSERT INTO ' + kwargs['table'] + ' ('
        for field in kwargs:
            if field == 'table':
                continue
            self.__sql += field + ', '
        self.__sql = self.__sql[:-2] + ') VALUES ('
        for field in kwargs:
            if field == 'table':
                continue
            values.append(kwargs[field])
            self.__sql += '?' + ', '
        self.__sql = self.__sql[:-2] + ')'
        return SQLSet(self.__sql, self.__connection).insert(values)

    def execute(self, query, args = ()):
        if self.__dbopen is False:
            self.__opendb()
        return SQLSet(query, self.__connection).execute(args)

    def update(self, **kwargs):
        values = []
        if kwargs.get('table') is None:
            raise SQLWrapperException, 'insert need a table !'
        if self.__dbopen is False:
            self.__opendb()
        self.__sql = 'UPDATE ' + kwargs['table'] + ' SET '
        for field in kwargs:
            if field == 'table':
                continue
            self.__sql += field + ' = ?,'
            values.append(kwargs[field])
        self.__sql = self.__sql[:-1]
        return SQLSet(self.__sql, self.__connection).update(values)

    def StopInsert(self):
        self.__connection.commit()
