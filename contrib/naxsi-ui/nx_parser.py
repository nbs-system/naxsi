from datetime import datetime
import urlparse
import pprint
import MySQLdb
import hashlib
import MySQLConnector

# the signature parser needs its own mysql connection/cursor, 
# as it makes heavy use of mysql's last_inserted_id()
class signature_parser:
    def __init__(self, cursor):
        self.cursor = cursor
        try:
            self.cursor.execute("SELECT COUNT(*) FROM exception")
        except:
            self.dbcreate()

    def dbcreate(self):
        print ("[+] drop and creating new tables")
        self.cursor.execute("DROP TABLES IF EXISTS rules")
        self.cursor.execute("CREATE TABLE rules (rule_id integer "
                            "auto_increment primary key "
                            ", action TEXT, msg TEXT, rx TEXT, "
                            "rx_type INT, url TEXT, "
                            "zone TEXT, arg_name TEXT);")
        
        self.cursor.execute("DROP TABLES IF EXISTS connections")
        self.cursor.execute("CREATE TABLE connections (connection_id INTEGER "
                            "auto_increment primary key, "
                            "src_peer_id INT, dst_peer_id INT, exception_id "
                            "INT, capture_id INT, date TIMESTAMP default "
                            "CURRENT_TIMESTAMP);")
        
        self.cursor.execute("DROP TABLES IF EXISTS peer")
        self.cursor.execute("CREATE TABLE peer (peer_id INTEGER "
                            "auto_increment primary key, "
                            "peer_ip TEXT, peer_host TEXT, peer_tags TEXT);")
                
        self.cursor.execute("DROP TABLES IF EXISTS exception")
        self.cursor.execute("CREATE TABLE exception (exception_id integer "
                            "auto_increment primary key "
                            ",url TEXT, md5 TEXT, count INT default 1);")
        
        self.cursor.execute("DROP TABLES IF EXISTS match_zone")
        self.cursor.execute("CREATE TABLE match_zone (match_id INTEGER "
                            "auto_increment primary key, exception_id INTEGER, "
                            "zone TEXT, arg_name TEXT, rule_id INTEGER);")

        self.cursor.execute("DROP TABLES IF EXISTS capture")
        self.cursor.execute("CREATE TABLE capture (capture_id INTEGER "
                            "auto_increment primary key, http_request TEXT, "
                            "exception_id INTEGER);")

        self.cursor.execute("DROP TABLES IF EXISTS http_monitor")
        self.cursor.execute("CREATE TABLE http_monitor (id INTEGER auto_increment primary key, peer_ip TEXT, md5 TEXT)")

    def last_id(self):
        return self.cursor.lastrowid

    def insert(self, fmt, *args):
        self.cursor.execute(fmt, [args])

    def create_exception_hash(self, d):
        """
        Creates a unique md5 hash of an exception.
        """
        sig_hash = d.get("server", "") +"#"+ d.get("uri", "")+"#"
        for i in range(0, 50):
            if "zone"+str(i) in d:
                sig_hash = sig_hash + d.get("zone"+str(i), "")
            else:
                break
            if "var_name"+str(i) in d:
                sig_hash = sig_hash + d.get("var_name", "") + "#"
            sig_hash = sig_hash + d.get("id"+str(i), "") + "#"
        sig_md5 = hashlib.md5(sig_hash).hexdigest()
        return sig_md5

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
            self.cursor.execute("INSERT INTO match_zone (exception_id, "
                                "zone, arg_name, rule_id) "
                                "VALUES (%s, %s, %s, %s)", 
                                (str(exception_id), zn, vn, 
                                 d.get("id"+str(i), "")))
        return

    def add_capture(self, exception_id, raw_request, add_capture):
        if add_capture is False:
            return 0
        self.cursor.execute("INSERT INTO capture (http_request, exception_id)"
                            "VALUES (%s, %s)", (str(raw_request), 
                                                str(exception_id)))
        capture_id = self.last_id()
        return capture_id

    def sig_to_db(self, raw_request, sig, add_capture=False, date = None):
        """
        Insert signature into database. returns 
        associated connection_id.
        """
        d = dict(urlparse.parse_qsl(sig))
#        pprint.pprint(d)
        sig_hash = self.create_exception_hash(d)
        self.cursor.execute("INSERT INTO peer (peer_ip) "
                            "VALUES (%s)", (d.get("ip", "")))
        ip_id = self.last_id()
        self.cursor.execute("INSERT INTO peer (peer_host) "
                            "VALUES (%s)", (d.get("server", "")))
        host_id = self.last_id()
        self.cursor.execute('SELECT 1 FROM exception where md5=%s', (sig_hash))
        if self.cursor.fetchall():            
            self.cursor.execute("UPDATE exception SET url=%s,md5=%s,count = count + 1 "
                                "where md5=%s", (d.get("uri", ""), sig_hash, sig_hash))
            self.cursor.execute("select exception_id from exception where url=%s and md5=%s", (d.get('uri', ''), sig_hash))
            exception_id = self.cursor.fetchall()[0][0]
        else:
            self.cursor.execute('INSERT INTO exception (url, md5) VALUES (%s, %s)', (d.get('uri', ''), sig_hash))
            exception_id = self.last_id()
        self.cursor.execute("SELECT 1 FROM http_monitor WHERE peer_ip = %s or md5 = %s", (d.get("ip", ""), sig_hash))
        if self.cursor.fetchall():    
            add_capture = True
        capture_id = self.add_capture(exception_id, raw_request, add_capture)
        print date
        self.cursor.execute("INSERT INTO connections (src_peer_id, "
                            "dst_peer_id, exception_id, capture_id, date)"
                            "VALUES (%s, %s, %s, %s, %s)", (str(ip_id), 
                                                        str(host_id), 
                                                        str(exception_id), 
                                                        str(capture_id), datetime.now() if date is None else date))
        connection_id = self.last_id()
        self.add_matchzones(exception_id, d)
#        self.cursor.execute("UPDATE exception SET md5=%s where "
#                            "exception_id=%s", (sig_hash, str(exception_id)))
        return (connection_id)
    
class signature_extractor:
    def __init__(self, cursor):
        self.cursor = cursor
        try:
            self.cursor.execute("select 1 from exception")
        except:
            self.create_table()

    def create_table(self):
        print ("[+] drop and creating new tables")
        self.cursor.execute("DROP TABLES IF EXISTS rules")
        self.cursor.execute("CREATE TABLE rules (rule_id integer "
                            "auto_increment primary key "
                            ", action TEXT, msg TEXT, rx TEXT, "
                            "rx_type INT, url TEXT, "
                            "zone TEXT, arg_name TEXT);")
        
        self.cursor.execute("DROP TABLES IF EXISTS connections")
        self.cursor.execute("CREATE TABLE connections (connection_id INTEGER "
                            "auto_increment primary key, "
                            "src_peer_id INT, dst_peer_id INT, exception_id "
                            "INT, capture_id INT, date TIMESTAMP default "
                            "CURRENT_TIMESTAMP);")
        
        self.cursor.execute("DROP TABLES IF EXISTS peer")
        self.cursor.execute("CREATE TABLE peer (peer_id INTEGER "
                            "auto_increment primary key, "
                            "peer_ip TEXT, peer_host TEXT, peer_tags TEXT);")
        
        
        self.cursor.execute("DROP TABLES IF EXISTS exception")
        self.cursor.execute("CREATE TABLE exception (exception_id integer "
                            "auto_increment primary key "
                            ",url TEXT, md5 TEXT, count INT default 1);")
        
        self.cursor.execute("DROP TABLES IF EXISTS match_zone")
        self.cursor.execute("CREATE TABLE match_zone (match_id INTEGER "
                            "auto_increment primary key, exception_id INTEGER, "
                            "zone TEXT, arg_name TEXT, rule_id INTEGER);")

        self.cursor.execute("DROP TABLES IF EXISTS capture")
        self.cursor.execute("CREATE TABLE capture (capture_id INTEGER "
                            "auto_increment primary key, http_request TEXT, "
                            "exception_id INTEGER);")

        self.cursor.execute("DROP TABLES IF EXISTS http_monitor")
        self.cursor.execute("CREATE TABLE http_monitor (id INTEGER auto_increment primary key, peer_ip TEXT, md5 TEXT)")

    def count_per_exception(self, exception_id):
        self.cursor.execute("select count(DISTINCT srcpeer.peer_ip) as count from "
                       "peer "
                       "as srcpeer,  peer as dstpeer, connections where "
                       "connections.src_peer_id = srcpeer.peer_id and "
                       "connections.dst_peer_id = dstpeer.peer_id and "
                       "connections.exception_id = %s", (str(exception_id)))
        data = self.cursor.fetchone()
        if data is None:
            return None
        return (data["count"])

    def gen_whitelists(self, d):
        if not d.get("match_zones"):
            return
        self.start = 0
        self.end = 0
        while True:
            self.mz = d.get("match_zones")
            if not self.mz[self.start:].startswith("MZ:"):
                break
            self.end = self.mz[self.start:].find("&")
            if self.end is -1:
                break
            self.rid = self.mz[self.start+3:self.end]
            print "id:"+self.rid
            self.start = self.end+1
            print "search in ["+self.mz[self.start:]+"]"
            self.end = self.mz[self.start:].find("&")
            if self.end is -1:
                break
            print "end : "+self.mz[self.end:]
            self.zone = self.mz[self.start:self.end]
            print "zone:"+self.zone
            self.start = self.end+1
            self.end = self.mz[self.start:].find("&")
            if self.end is -1:
                break
            if self.mz[self.start:].startswith(",MZ:"):
                print "NEXT !"
                self.mz = self.mz[self.start:]
                continue
            self.arg_name = self.mz[self.start:self.end]
            print ("This round : rid:%d,zone:%s,arg_name:%s",
                   (self.rid, self.zone, self.arg_name))
            self.mz = self.mz[self.end+1:]

    def extract_whitelists(self):
        self.ret = self.extract_exceptions()
        print type(self.ret)
        for d in self.ret:
            count =  self.count_per_exception(d["id"])
            d["src_count"] = count
            self.wls = self.gen_whitelists(d)

    def extract_exceptions(self):
        self.cursor.execute("""select exception.exception_id as id, 
exception.md5 as md5, exception.url as url, exception.count as count, 
srcpeer.peer_ip as src, dstpeer.peer_host as dst, GROUP_CONCAT("MZ:", 
match_zone.rule_id, "&", match_zone.zone, "&", match_zone.arg_name, "&" )  
as match_zones from exception LEFT JOIN  (peer as srcpeer, peer as dstpeer, 
connections, match_zone)  on (connections.src_peer_id = srcpeer.peer_id and  
connections.dst_peer_id = dstpeer.peer_id and  connections.exception_id = 
exception.exception_id and  match_zone.exception_id = exception.exception_id) 
GROUP BY id;""")
        data = self.cursor.fetchall()
        pprint.pprint(data)
        return data

if __name__ == '__main__':
    db = MySQLConnector.MySQLConnector().connect()
    cursor = db.cursor(MySQLdb.cursors.DictCursor)
    bla = signature_extractor(cursor)
#    bla.extract_exceptions()
#    bla.extract_whitelists()
