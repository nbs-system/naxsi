import urlparse
import pprint
import MySQLdb
import hashlib

#exception + zone : select * from exception LEFT JOIN (peer as srcpeer, peer as dstpeer, connections, match_zone) on (connections.src_peer_id = srcpeer.peer_id and connections.dst_peer_id = dstpeer.peer_id and connections.exception_id = exception.exception_id and match_zone.exception_id = exception.exception_id);



#select de gros bourrin : select exc.url, exc.count, exc.md5, cap.http_request, srcpeer.peer_ip, dstpeer.peer_host, mz.zone, mz.arg_name, mz.rule_id from exception as exc, capture as cap, peer as srcpeer, peer as dstpeer, match_zone as mz, connections as conn WHERE (mz.exception_id = exc.exception_id and cap.exception_id = exc.exception_id and srcpeer.peer_id = conn.src_peer_id and conn.dst_peer_id = dstpeer.peer_id);


# select all exception with associated peers.
##select * from exception LEFT JOIN (peer as srcpeer, peer as dstpeer, connections) on (connections.src_peer_id = srcpeer.peer_id and connections.dst_peer_id = dstpeer.peer_id and exception.connection_id = connections.connection_id) LIMIT 10;

# select all exceptions with associated zone_match and peers.
# select * from exception LEFT JOIN (peer as srcpeer, peer as dstpeer, connections, match_zone) on (connections.src_peer_id = srcpeer.peer_id and connections.dst_peer_id = dstpeer.peer_id and exception.connection_id = connections.connection_id and match_zone.exception_id = exception.exception_id) where srcpeer.peer_ip != '88.191.133.106' and srcpeer.peer_ip != '82.234.123.117' and srcpeer.peer_ip != '82.247.12.197';
            
class signature_parser:
    def __init__(self, host, user, password, dbname):
#        print "[+] Connecting to database"
        self.db = MySQLdb.connect(host, user, password, dbname)
        if self.db is None:
            print "ERROR!"
            return
        self.cursor = self.db.cursor()
        if self.cursor is None:
            print "ERROR!"
            return
        # Checking wether the base already exists
        try:
            self.cursor.execute("SELECT COUNT(*) FROM exception")
        except:
            self.dbcreate()
    def dbcreate(self):
        print ("[+] drop'ing and creating new tables")
        self.cursor.execute("DROP TABLES IF EXISTS rules")
        self.cursor.execute("CREATE TABLE rules (rule_id integer "
                            "auto_increment primary key "
                            ", action TEXT, msg TEXT, rx TEXT, "
                            "rx_type INT, url TEXT, "
                            "zone TEXT, arg_name TEXT);")
        
        self.cursor.execute("DROP TABLES IF EXISTS connections")
        self.cursor.execute("CREATE TABLE connections (connection_id INTEGER "
                            "auto_increment primary key, "
                            "src_peer_id INT, dst_peer_id INT, exception_id INT, capture_id INT);")
        
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
                            "auto_increment primary key, http_request TEXT, exception_id INTEGER);")

        
        # self.cursor.execute("DROP TABLES IF EXISTS router")
        # self.cursor.execute("CREATE TABLE router(route_id INTEGER "
        #                     "auto_increment primary key,"
        #                     "exception_id INTEGER, rule_id INTEGER, "
        #                     "conn_id INTEGER, capture_id INTEGER);")
        
    def extract_sig(self, raw_rule, is_from_http=False, is_from_log=False):
        start = raw_rule.find(": ")
        if (start != -1):
            if (is_from_log == True):
                end = raw_rule[start:].find(", client: ")
                if (end):
                    return (raw_rule[raw_rule.find(": ") + 2:
                                         raw_rule.find(", client: ")])
            elif (is_from_http == True):
                return (raw_rule[raw_rule.find(": ") + 2:])
            
        return ("")
    def last_id(self):
        self.cursor.execute("SELECT last_insert_id()")
        data = self.cursor.fetchone()
        return data[0]
    def insert(self, fmt, *args):
        self.cursor.execute(fmt, [args])
    def add_capture(self, exception_id, raw_request):
        #capture information
        self.cursor.execute("SELECT COUNT(*) FROM capture where exception_id = %s", (str(exception_id)))
        x = self.cursor.fetchone()
        if (x is None or x[0] < 10):
#            print "less than 10 "+str(x[0])
            self.cursor.execute("INSERT INTO capture (http_request, exception_id)"
                                "VALUES (%s, %s)", (str(raw_request), str(exception_id)))
            capture_id = self.last_id()
        else:
            capture_id = 0
        return capture_id
    def sig_to_db(self, raw_request, d, force_insert=False):
        if (force_insert == False):
            sig_hash = d["server"][0]+"#"+d["uri"][0]+"#"
            for i in range(0, 50):
                if "zone"+str(i) in d:
                    sig_hash = sig_hash + d["zone"+str(i)][0] + "#"
                else:
                    break
                if "var_name"+str(i) in d:
                    sig_hash = sig_hash + d["var_name"+str(i)][0] + "#"
                sig_hash = sig_hash + d["id"+str(i)][0] + "#"
            sig_md5 = hashlib.md5(sig_hash).hexdigest()
            self.cursor.execute("SELECT exception_id FROM exception where md5 = %s LIMIT 1", (sig_md5))
            exception_id = self.cursor.fetchone()
            if (exception_id is not None):
                self.add_capture(exception_id[0], raw_request)
                self.cursor.execute("UPDATE exception SET count=count+1 where md5 = %s", (sig_md5))
                return
        #peer information
        sig_hash = d["server"][0]+"#"+d["uri"][0]+"#"
        self.cursor.execute("INSERT INTO peer (peer_ip) "
                            "VALUES (%s)", (d["ip"][0]))
        ip_id = self.last_id()
        
        self.cursor.execute("INSERT INTO peer (peer_host) "
                            "VALUES (%s)", (d["server"][0]))
        host_id = self.last_id()
        #exception
        self.cursor.execute("INSERT INTO exception (url) VALUES "
                            "(%s)", (d["uri"][0]))
        exception_id = self.last_id()
        #capture information
        capture_id = self.add_capture(exception_id, raw_request)
#        print "cap id : "+str(capture_id)
        #connection information
        self.cursor.execute("INSERT INTO connections (src_peer_id, dst_peer_id, exception_id, capture_id)"
                            "VALUES (%s, %s, %s, %s)", (str(ip_id), str(host_id), str(exception_id), str(capture_id)))
        connection_id = self.last_id()
        #match_zones
        for i in range(0, 50):
            zn = ""
            vn = ""
            if "zone"+str(i) in d:
                zn = d["zone"+str(i)][0]
                sig_hash = sig_hash + d["zone"+str(i)][0] + "#"
            else:
                break
            if "var_name"+str(i) in d:
                vn = d["var_name"+str(i)][0]
                sig_hash = sig_hash + d["var_name"+str(i)][0] + "#"
            sig_hash = sig_hash + d["id"+str(i)][0] + "#"
            self.cursor.execute("INSERT INTO match_zone (exception_id, zone, arg_name, rule_id) "
                                "VALUES (%s, %s, %s, %s)", (str(exception_id), zn, vn, d["id"+str(i)][0]))
        self.cursor.execute("UPDATE exception SET md5=%s WHERE exception_id=%s", (hashlib.md5(sig_hash).hexdigest(), str(exception_id)))
        return (connection_id)
    def raw_parser(self, raw_request, raw_rule, is_from_http=True, is_from_log=False):
        sig = self.extract_sig(raw_rule, is_from_http, is_from_log)
        tmpdict = urlparse.parse_qs(sig)
        connection_id = self.sig_to_db(raw_request, tmpdict, force_insert=False)
        self.db.close()
        
