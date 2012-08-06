from datetime import datetime

import urlparse
import pprint
import hashlib
import SQLWrapper
import itertools
import sys

# the signature parser needs its own mysql connection/cursor, 
# as it makes heavy use of mysql's last_inserted_id()
class signature_parser:
    def __init__(self, wrapper):
        self.wrapper = wrapper
        try:
            self.wrapper.execute("SELECT 1 FROM exceptions")
        except :
            print "Unable to select, DB must be empty. Create ..."
            self.dbcreate()

    def dbcreate(self):
        print ("[+] drop and creating new tables")
        self.wrapper.create_all_tables()

    def last_id(self):
        return self.wrapper.getLastId()

    def insert(self, fmt, *args):
        self.wrapper.execute(fmt, [args])

    def add_matchzones(self, exception_id, d):
        for i in range(0, 100):
            zn = ""
            vn = ""
            if "zone"+str(i) in d:
                zn = d.get("zone"+str(i), "")
            else:
                break
            if "var_name"+str(i) in d:
                vn = d.get("var_name"+str(i), "")

            self.wrapper.execute("INSERT INTO match_zone (exception_id, "
                                "zone, arg_name, rule_id) "
                                "VALUES (%s, %s, %s, %s)", 
                                (str(exception_id), zn, vn, 
                                 d.get("id"+str(i), "")))
        return


    def sig_to_db(self, raw_request, sig, add_capture=False, date = None):
        """
        Insert signature into database. returns 
        associated connection_id.
        """
        d = dict(urlparse.parse_qsl(sig))
        if not d.has_key('server'):
            d['server'] = ''
        if not d.has_key('uri'):
            d['uri'] = ''
        
        # self.wrapper.execute("SELECT url_id from urls where url = %s", (d['uri'],))
        # url_id = self.wrapper.getResults()
        # self.wrapper.StartInsert()
        # if (len(url_id) == 0):
        #     print "New url "+d['uri']
        #     self.wrapper.execute("INSERT INTO urls (url) VALUES (%s)", (d['uri'],))
        #     url_id = self.wrapper.getLastId()
        # else:
        #     url_id = url_id[0]['url_id']
        #     print "Existing url "+d['uri']+" id "+str(url_id)
        self.wrapper.execute("INSERT INTO urls (url) VALUES (%s)", (d['uri'],))
        url_id = self.wrapper.getLastId()
        print "url id "+str(url_id)
        for i in itertools.count():
            zn = ''
            vn = ''
            rn = ''
            if 'zone' + str(i) in d.keys():
                zn  = d['zone' + str(i)]
            else:
                break
            if 'var_name' + str(i) in d.keys():
                vn = d['var_name' + str(i)]
            if 'id' + str(i) in d.keys():
                rn = d['id' + str(i)]
            self.wrapper.execute('INSERT INTO exceptions (zone, var_name, rule_id) VALUES (%s,%s,%s)', (zn, vn, rn))
            exception_id  = self.wrapper.getLastId()
            self.wrapper.execute('INSERT INTO connections (peer_ip, host, url_id, id_exception,date) VALUES (%s,%s,%s,%s,%s)', (d['ip'], d['server'], str(url_id), str(exception_id), date))
                            
if __name__ == '__main__':
    print 'This module is not intended for direct use. Please launch nx_intercept.py or nx_extract.py'
