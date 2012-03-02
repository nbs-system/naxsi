import MySQLdb
import pprint
import re

def main():
   db = MySQLdb.connect("localhost", "root", "trivialpassword", "naxsi_sig") #host, user, password, dbname)
   cursor = db.cursor(MySQLdb.cursors.DictCursor)
   data = get_full_by(cursor, srcip="127.0.0.1")
   pprint.pprint(data)
   pass

#   cursor.execute("""select exception.exception_id as id, exception.md5 as md5, exception.url as url, exception.count as count, srcpeer.peer_ip as src, dstpeer.peer_host as dst, match_zone.rule_id, match_zone.zone, match_zone.arg_name from exception LEFT JOIN  (peer as srcpeer, peer as dstpeer, connections, match_zone)  on (connections.src_peer_id = srcpeer.peer_id and  connections.dst_peer_id = dstpeer.peer_id and  connections.exception_id = exception.exception_id and  match_zone.exception_id = exception.exception_id);""")

def get_whitelist():
   

def get_full_by(cursor, url=None, srcip=None, dsthost=None,
                rule_id=None, exception_md5=None,
                exception_id=None):
   ret = []
#   cursor.execute("""select exception.exception_id as id, exception.md5 as md5, exception.url as url, exception.count as count, srcpeer.peer_ip as src, dstpeer.peer_host as dst, GROUP_CONCAT("MZ:", match_zone.rule_id, "&", match_zone.zone, "&", match_zone.arg_name, "&" )  as match_zones from exception LEFT JOIN  (peer as srcpeer, peer as dstpeer, connections, match_zone)  on (connections.src_peer_id = srcpeer.peer_id and  connections.dst_peer_id = dstpeer.peer_id and  connections.exception_id = exception.exception_id and  match_zone.exception_id = exception.exception_id) GROUP BY id;""")
   data = cursor.fetchall()
   for row in data:
      if (url is not None and not re.search(url, row.get("url", ""))):
         continue
      if (srcip is not None and not re.search(srcip, row.get("src", ""))):
         continue
      if (dsthost is not None and not re.search(dsthost, row.get("dst", ""))):
         continue
      if (exception_md5 is not None and not re.search(exception_md5, row.get("md5", ""))):
         continue
      ret.append(row)
   return ret

if __name__  == '__main__':
    print "start."
    main()
