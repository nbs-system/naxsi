from __future__ import print_function
import MySQLdb
import MySQLConnector
import pprint
import re
import getopt
import sys
from twisted.web import http
from twisted.internet import protocol
from twisted.internet import reactor

class rules_extractor(object):
   def __init__(self, max_hit):
      self.db = MySQLConnector.MySQLConnector().connect()
      self.cursor = self.db.cursor(MySQLdb.cursors.DictCursor)
      self.rules_list = []
      self.final_rules = []
      self.base_rules = []
      self.max_hit = max_hit
   
   def gen_basic_rules(self,url=None, srcip=None, dsthost=None,
                rule_id=None, exception_md5=None,
                exception_id=None):
      tmp_rules = []
      self.cursor.execute("""select exception.exception_id as id, exception.md5 as md5, exception.url as url, exception.count as count, srcpeer.peer_ip as src, count(distinct srcpeer.peer_ip) as cnt_peer, dstpeer.peer_host as dst, GROUP_CONCAT("mz:", match_zone.rule_id, ":", "$", match_zone.zone, "_VAR:", match_zone.arg_name)  as match_zones from exception LEFT JOIN  (peer as srcpeer, peer as dstpeer, connections, match_zone)  on (connections.src_peer_id = srcpeer.peer_id and  connections.dst_peer_id = dstpeer.peer_id and  connections.exception_id = exception.exception_id and  match_zone.exception_id = exception.exception_id) GROUP BY id;""")
      data = self.cursor.fetchall()
      for row in data:
         if (url is not None and not re.search(url, row.get("url", ""))):
            continue
         if (srcip is not None and not re.search(srcip, row.get("src", ""))):
            continue
         if (dsthost is not None and not re.search(dsthost, row.get("dst", ""))):
            continue
         if (exception_md5 is not None and not re.search(exception_md5, row.get("md5", ""))):
            continue
         tmp_rules.append(row)
      for i in tmp_rules:
         for j in i['match_zones'].split(','):
            da_dict = {}
            da_dict['url'] = i['url']
            da_dict['arg'] = ':'.join(j.split(':')[2:])
            da_dict['id'] = j.split(':')[1]
            da_dict['count'] = i['count']
            da_dict['cnt_peer'] = i['cnt_peer']
            if da_dict not in self.rules_list:
               self.rules_list.append(da_dict)
      self.base_rules = self.rules_list[:]

   def opti_rules(self):
      lr = len(self.rules_list)
      i = 0
      while i < lr:
         matching = []
         arg_type, arg_name = tuple(self.rules_list[i]['arg'].split(':'))
         id = self.rules_list[i]['id']
         url = self.rules_list[i]['url']
         matching = filter(lambda l: id == l['id'] and l['arg'] == arg_type + ':' + arg_name, self.rules_list)
         if len(matching) >= self.max_hit:
            #whitelist the ids on every url with arg_name and arg_type -> BasicRule wl:id "mz:argtype:argname"
            self.final_rules.append({'url': None, 'id': id, 'arg': arg_type + ':' + arg_name})
            for bla in matching:
               self.rules_list.remove(bla)
            lr -= len(matching)
            i = -1
         else:
            matching = filter(lambda l: url == l['url'] and l['arg'] == arg_type + ':' + arg_name, self.rules_list)
            if len(matching) >= self.max_hit:
            #whitelist all id on url with arg_name and arg_type -> BasicRule wl:0 "mz:argtype:argname"
               self.final_rules.append({'url': url, 'id': str(0), 'arg': arg_type + ':' + arg_name})
               for bla in matching:
                  self.rules_list.remove(bla)
               lr -= len(matching)
               i = -1
         i += 1
      if self.rules_list == self.final_rules:
         return self.base_rules, self.final_rules
      #append rules that cant be optimized
      self.final_rules += self.rules_list
      #remove duplicate
      tmp_list = []
      for i in self.final_rules:
         if i not in tmp_list:
            tmp_list.append(i)
      self.final_rules = tmp_list
     #try to reoptimize
      self.rules_list = self.final_rules
      self.opti_rules()
      return self.base_rules, self.final_rules
      
   def write_rules(self, filename = '/tmp/naxsi_wl.rules'):
      try:
         fd = open(filename, 'w')
      except:
         print('Cant open rules file !')
         return
      r = '########### Rules Before Optimisation ##################\n'
      pprint.pprint(self.base_rules)
      for i in self.base_rules:
         r += '#BasicRule wl' + i['id'] + ' "mz:$URL:' + i['url'] + '|' + i['arg'] + '";\n'
      r += '########### End Of Rules Before Optimisation ###########\n'
      fd.write(r)
      print(r)
      r = ''
      if not len(self.final_rules):
         for i in self.rules_list:
            r += 'BasicRule wl:' + i['id'] + ' "mz:$URL:' + i['url'] + '|' + i['arg'] + '";\n'
         print(r.rstrip())
         fd.write(r)
      else:
         for i in self.final_rules:
            r += 'BasicRule wl:' + i['id'] + ' "mz:'
            if i['url'] is not None:
               r += '$URL:' + i['url'] + '|'
            r += i['arg'] + '";\n'
         fd.write(r)
         print(r.rstrip())
      fd.close()
               

class InterceptHandler(http.Request):
    def process(self):
       if self.path == '/get_rules':
          ex = rules_extractor(int(self.args.get('max_hit', ['10'])[0]))
          ex.gen_basic_rules()
          base_rules, opti_rules = ex.opti_rules()
          r = '########### Rules Before Optimisation ##################\n'
          for i in base_rules:
             r += '#%s hits on rule %s on url %s from %s different peers\n' % (i['count'], i['id'], i['url'], i['cnt_peer'])
             r += '#BasicRule wl:' + i['id'] + ' "mz:$URL:' + i['url'] + '|' + i['arg'] + '";\n'
          r += '########### End Of Rules Before Optimisation ###########\n'
          for i in opti_rules:
             r += 'BasicRule wl:' + i['id'] + ' "mz:'
             if i['url'] is not None:
                r += '$URL:' + i['url'] + '|'
             r += i['arg'] + '";\n'
          self.write(r)
       self.finish()

class InterceptProtocol(http.HTTPChannel):
   requestFactory = InterceptHandler
   
class InterceptFactory(http.HTTPFactory):
   protocol = InterceptProtocol
      
def usage():
   print('Usage : python nx_extract [-h,--help] [-p|--port portnumber]')

if __name__  == '__main__':
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'hp:', ['help','port'])
    except getopt.GetoptError, err:
        print(str(err))
        usage()
        sys.exit(42)    

    port = 80
    for o, a in opts:
       if o in ('-h', '--help'):
          usage()
          sys.exit(0)
       if o in ('-p', '--port'):
           port = int(a)

    reactor.listenTCP(port, InterceptFactory())
    reactor.run()
